/*
Technitium Library
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Http
{
    public class HttpClientDaneHandler : HttpMessageHandler
    {
        #region variables

        readonly static FieldInfo _innerStream = typeof(SslStream).GetField("_innerStream", BindingFlags.Instance | BindingFlags.NonPublic);

        readonly DnsClient _dnsClient;
        readonly HttpMessageInvoker _messageInvoker;

        #endregion

        #region constructor

        public HttpClientDaneHandler()
        {
            _dnsClient = new DnsClient();
            _dnsClient.DnssecValidation = true;

            SocketsHttpHandler httpHandler = new SocketsHttpHandler();
            httpHandler.SslOptions.RemoteCertificateValidationCallback += RemoteCertificateValidationCallback;

            _messageInvoker = new HttpMessageInvoker(httpHandler);
        }

        #endregion

        #region private

        private bool RemoteCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.RemoteCertificateNotAvailable)
                return false;

            SslStream sslStream = sender as SslStream;
            NetworkStream networkStream = _innerStream.GetValue(sslStream) as NetworkStream;

            string domain = "_" + networkStream.Socket.RemoteEndPoint.GetPort() + "._tcp." + sslStream.TargetHostName;
            DnsDatagram response;

            try
            {
                response = _dnsClient.ResolveAsync(domain, DnsResourceRecordType.TLSA).Sync();
            }
            catch (Exception ex)
            {
                throw new HttpRequestException("The TLS certificate failed DANE validation: failed to resolve TLSA record for '" + domain + "'.", ex);
            }

            List<DnsTLSARecordData> tlsaRecords;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                    {
                        tlsaRecords = null;
                    }
                    else
                    {
                        tlsaRecords = new List<DnsTLSARecordData>();

                        foreach (DnsResourceRecord answer in response.Answer)
                        {
                            if ((answer.Type == DnsResourceRecordType.TLSA) && (answer.DnssecStatus == DnssecStatus.Secure))
                            {
                                DnsTLSARecordData tlsa = answer.RDATA as DnsTLSARecordData;

                                switch (tlsa.CertificateUsage)
                                {
                                    case DnsTLSACertificateUsage.PKIX_TA:
                                    case DnsTLSACertificateUsage.PKIX_EE:
                                    case DnsTLSACertificateUsage.DANE_TA:
                                    case DnsTLSACertificateUsage.DANE_EE:
                                        break;

                                    default:
                                        continue; //unusable
                                }

                                switch (tlsa.Selector)
                                {
                                    case DnsTLSASelector.Cert:
                                    case DnsTLSASelector.SPKI:
                                        break;

                                    default:
                                        continue; //unusable
                                }

                                switch (tlsa.MatchingType)
                                {
                                    case DnsTLSAMatchingType.Full:
                                    case DnsTLSAMatchingType.SHA2_256:
                                    case DnsTLSAMatchingType.SHA2_512:
                                        break;

                                    default:
                                        continue; //unusable
                                }

                                if (tlsa.CertificateAssociationDataValue.Length == 0)
                                    continue; //unusable

                                tlsaRecords.Add(tlsa);
                            }
                        }
                    }
                    break;

                case DnsResponseCode.NxDomain:
                    tlsaRecords = null;
                    break;

                default:
                    throw new HttpRequestException("The TLS certificate failed DANE validation: failed to resolve TLSA record for '" + domain + "' (RCODE: " + response.RCODE.ToString() + ")");
            }

            if ((tlsaRecords is null) || (tlsaRecords.Count == 0)) //no TLSA records available
                return sslPolicyErrors == SslPolicyErrors.None; //process as usual

            foreach (DnsTLSARecordData tlsa in tlsaRecords)
            {
                switch (tlsa.CertificateUsage)
                {
                    case DnsTLSACertificateUsage.PKIX_TA:
                        {
                            if (sslPolicyErrors == SslPolicyErrors.None)
                            {
                                //PKIX is validating; validate TLSA
                                for (int i = 1; i < chain.ChainElements.Count; i++)
                                {
                                    X509ChainElement chainElement = chain.ChainElements[i];
                                    byte[] certificateAssociatedData = DnsTLSARecordData.GetCertificateAssociatedData(tlsa.Selector, tlsa.MatchingType, chainElement.Certificate);

                                    if (BinaryNumber.Equals(certificateAssociatedData, tlsa.CertificateAssociationDataValue))
                                        return true; //TLSA is validating
                                }
                            }
                        }
                        break;

                    case DnsTLSACertificateUsage.PKIX_EE:
                        {
                            if (sslPolicyErrors == SslPolicyErrors.None)
                            {
                                //PKIX is validating; validate TLSA
                                byte[] certificateAssociatedData = DnsTLSARecordData.GetCertificateAssociatedData(tlsa.Selector, tlsa.MatchingType, certificate);

                                if (BinaryNumber.Equals(certificateAssociatedData, tlsa.CertificateAssociationDataValue))
                                    return true; //TLSA is validating
                            }
                        }
                        break;

                    case DnsTLSACertificateUsage.DANE_TA:
                        {
                            bool pkixFailed = false;

                            for (int i = 0; i < chain.ChainElements.Count; i++)
                            {
                                X509ChainElement chainElement = chain.ChainElements[i];

                                if (i == 0)
                                {
                                    //validate PKIX
                                    if (chainElement.ChainElementStatus.Length > 0)
                                        break; //cert has validation issues

                                    //first i.e. end entity certificate only requires cert validation
                                    continue;
                                }

                                //validate TLSA
                                byte[] certificateAssociatedData = DnsTLSARecordData.GetCertificateAssociatedData(tlsa.Selector, tlsa.MatchingType, chainElement.Certificate);
                                bool tlsaVerified = BinaryNumber.Equals(certificateAssociatedData, tlsa.CertificateAssociationDataValue);

                                //validate PKIX
                                foreach (X509ChainStatus chainStatus in chainElement.ChainElementStatus)
                                {
                                    switch (chainStatus.Status)
                                    {
                                        case X509ChainStatusFlags.PartialChain:
                                        case X509ChainStatusFlags.UntrustedRoot:
                                            if (tlsaVerified)
                                                continue; //ignored issues since cert is TA

                                            //cert has validation issues
                                            break;
                                    }

                                    //cert has validation issues
                                    pkixFailed = true;
                                    break;
                                }

                                if (pkixFailed)
                                    break; //cert has validation issues; DANE-TA failed to validate

                                if (tlsaVerified)
                                    return true; //TLSA is validating; DANE-TA was validated successfully
                            }

                            if (!pkixFailed && (tlsa.MatchingType == DnsTLSAMatchingType.Full))
                            {
                                switch (tlsa.Selector)
                                {
                                    case DnsTLSASelector.Cert:
                                        {
                                            //validate TA cert from TLSA record
                                            X509Certificate2 taCert = new X509Certificate2(tlsa.CertificateAssociationDataValue);
                                            X509Certificate2 lastCert = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;

                                            using (X509Chain taChain = new X509Chain())
                                            {
                                                taChain.ChainPolicy.CustomTrustStore.Add(taCert);

                                                if (taChain.Build(lastCert))
                                                    return true; //TA cert chain is validating
                                            }
                                        }
                                        break;

                                    case DnsTLSASelector.SPKI:
                                        //validation using only public key is not supported
                                        break;
                                }
                            }
                        }
                        break;

                    case DnsTLSACertificateUsage.DANE_EE:
                        {
                            //validate PKIX
                            bool pkixFailed = false;

                            foreach (X509ChainStatus chainStatus in chain.ChainElements[0].ChainElementStatus)
                            {
                                switch (chainStatus.Status)
                                {
                                    case X509ChainStatusFlags.PartialChain:
                                    case X509ChainStatusFlags.UntrustedRoot:
                                    case X509ChainStatusFlags.HasExcludedNameConstraint:
                                    case X509ChainStatusFlags.HasNotDefinedNameConstraint:
                                    case X509ChainStatusFlags.HasNotPermittedNameConstraint:
                                    case X509ChainStatusFlags.HasNotSupportedNameConstraint:
                                    case X509ChainStatusFlags.InvalidNameConstraints:
                                    case X509ChainStatusFlags.NotTimeValid:
                                        //ignored issues
                                        continue;
                                }

                                //cert has validation issues
                                pkixFailed = true;
                                break;
                            }

                            if (pkixFailed)
                                break; //cert has validation issues

                            //PKIX is validating; validate TLSA
                            byte[] certificateAssociatedData = DnsTLSARecordData.GetCertificateAssociatedData(tlsa.Selector, tlsa.MatchingType, certificate);

                            if (BinaryNumber.Equals(certificateAssociatedData, tlsa.CertificateAssociationDataValue))
                                return true; //TLSA is validating
                        }
                        break;
                }
            }

            throw new HttpRequestException("The TLS certificate failed DANE validation: no matching TLSA record was found, or a certificate has one or more issues.");
        }

        #endregion

        #region protected

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return await _messageInvoker.SendAsync(request, cancellationToken);
        }

        #endregion
    }
}
