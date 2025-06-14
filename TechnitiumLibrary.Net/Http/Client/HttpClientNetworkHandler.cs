/*
Technitium Library
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Http.Client
{
    public enum HttpClientNetworkType
    {
        Default = 0,
        IPv4Only = 1,
        IPv6Only = 2,
        PreferIPv6 = 3
    }

    //The DNS-Based Authentication of Named Entities (DANE) Protocol: Updates and Operational Guidance (RFC 7671)
    //https://datatracker.ietf.org/doc/rfc7671/

    public sealed class HttpClientNetworkHandler : DelegatingHandler
    {
        #region variables

        static bool _publicIpv6Available;
        static DateTime _publicIpv6AvailableLastCheckedOn;
        const int PUBLIC_IPv6_CHECK_FREQUENCY = 300000;

        readonly SocketsHttpHandler _innerHandler;

        HttpClientNetworkType _networkType = HttpClientNetworkType.Default;
        IDnsClient _dnsClient;
        NetProxy _proxy;
        bool _enableDANE;

        #endregion

        #region constructor

        public HttpClientNetworkHandler()
            : base(new SocketsHttpHandler())
        {
            _innerHandler = base.InnerHandler as SocketsHttpHandler;

            _innerHandler.EnableMultipleHttp2Connections = true;
            _innerHandler.AutomaticDecompression = DecompressionMethods.All;

            _innerHandler.ConnectCallback = ConnectCallback;
        }

        #endregion

        #region private

        private async ValueTask<Stream> ConnectCallback(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
        {
            if (_innerHandler.UseProxy && (_innerHandler.Proxy is not null))
                throw new NotSupportedException("Proxy is not supported at SocketsHttpHandler level.");

            DnsResolutionResult dnsResult = await ResolveAddressesAsync(context.DnsEndPoint.Host, context.DnsEndPoint.Port, cancellationToken);
            Socket socket;

            if (_proxy is null)
            {
                socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                socket.NoDelay = true;

                await socket.ConnectAsync(dnsResult.Addresses, context.DnsEndPoint.Port, cancellationToken);
            }
            else
            {
                socket = await _proxy.ConnectAsync(dnsResult.Addresses, context.DnsEndPoint.Port, cancellationToken);
            }

            Stream stream = new NetworkStream(socket, true);

            if (!context.InitialRequestMessage.RequestUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                return stream;

            SslClientAuthenticationOptions sslOptions = new SslClientAuthenticationOptions();

            sslOptions.AllowRenegotiation = _innerHandler.SslOptions.AllowRenegotiation;
            sslOptions.AllowTlsResume = _innerHandler.SslOptions.AllowTlsResume;
            sslOptions.LocalCertificateSelectionCallback = _innerHandler.SslOptions.LocalCertificateSelectionCallback;

            if (_enableDANE && (dnsResult.TlsaRecords is not null) && (dnsResult.TlsaRecords.Count > 0))
            {
                sslOptions.TargetHost = dnsResult.TlsaBaseDomain;
                sslOptions.RemoteCertificateValidationCallback += delegate (object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
                {
                    if (_innerHandler.SslOptions.RemoteCertificateValidationCallback is not null)
                    {
                        if (_innerHandler.SslOptions.RemoteCertificateValidationCallback(sender, certificate, chain, sslPolicyErrors))
                            return true; //validation passed by user callback
                    }

                    if (certificate is not X509Certificate2 certificate2)
                        certificate2 = new X509Certificate2(certificate);

                    ValidateDane(certificate2, chain, sslPolicyErrors, dnsResult.TlsaRecords);
                    return true;
                };
            }
            else
            {
                if (!string.IsNullOrEmpty(_innerHandler.SslOptions.TargetHost))
                    sslOptions.TargetHost = _innerHandler.SslOptions.TargetHost;
                else
                    sslOptions.TargetHost = context.DnsEndPoint.Host;

                sslOptions.RemoteCertificateValidationCallback = _innerHandler.SslOptions.RemoteCertificateValidationCallback;
            }

            if (_innerHandler.SslOptions.ApplicationProtocols is not null)
                sslOptions.ApplicationProtocols = _innerHandler.SslOptions.ApplicationProtocols;
            else if (context.InitialRequestMessage.Version == HttpVersion.Version20)
                sslOptions.ApplicationProtocols = [SslApplicationProtocol.Http2];

            sslOptions.ClientCertificates = _innerHandler.SslOptions.ClientCertificates;
            sslOptions.ClientCertificateContext = _innerHandler.SslOptions.ClientCertificateContext;
            sslOptions.CertificateRevocationCheckMode = _innerHandler.SslOptions.CertificateRevocationCheckMode;
            sslOptions.EncryptionPolicy = _innerHandler.SslOptions.EncryptionPolicy;
            sslOptions.EnabledSslProtocols = _innerHandler.SslOptions.EnabledSslProtocols;
            sslOptions.CipherSuitesPolicy = _innerHandler.SslOptions.CipherSuitesPolicy;
            sslOptions.CertificateChainPolicy = _innerHandler.SslOptions.CertificateChainPolicy;

            SslStream sslStream = new SslStream(stream);

            await sslStream.AuthenticateAsClientAsync(sslOptions, cancellationToken);

            return sslStream;
        }

        private async ValueTask<DnsResolutionResult> ResolveAddressesAsync(string host, int port, CancellationToken cancellationToken)
        {
            if (IPAddress.TryParse(host, out IPAddress ip))
            {
                switch (_networkType)
                {
                    case HttpClientNetworkType.IPv4Only:
                        if (ip.AddressFamily != AddressFamily.InterNetwork)
                            throw new HttpRequestException("HttpClientNetworkHandler current network type allows only IPv4 access.");

                        break;

                    case HttpClientNetworkType.IPv6Only:
                        if (ip.AddressFamily != AddressFamily.InterNetworkV6)
                            throw new HttpRequestException("HttpClientNetworkHandler current network type allows only IPv6 access.");

                        break;
                }

                return new DnsResolutionResult([ip], null, null);
            }

            if (_dnsClient is null)
            {
                DnsClient dnsClient = new DnsClient((_networkType == HttpClientNetworkType.IPv6Only) || (_networkType == HttpClientNetworkType.PreferIPv6));
                dnsClient.Cache = new DnsCache();
                dnsClient.Proxy = _proxy;
                dnsClient.DnssecValidation = true;

                _dnsClient = dnsClient;
            }

            DnsDatagram response;
            IReadOnlyList<IPAddress> addresses;

            try
            {
                switch (_networkType)
                {
                    case HttpClientNetworkType.IPv4Only:
                        {
                            response = await _dnsClient.ResolveAsync(new DnsQuestionRecord(host, DnsResourceRecordType.A, DnsClass.IN), cancellationToken);

                            addresses = Dns.DnsClient.ParseResponseA(response);
                            if (addresses.Count < 1)
                                throw new HttpRequestException("HttpClientNetworkHandler could not resolve IPv4 address for host: " + host);
                        }
                        break;

                    case HttpClientNetworkType.IPv6Only:
                        {
                            response = await _dnsClient.ResolveAsync(new DnsQuestionRecord(host, DnsResourceRecordType.AAAA, DnsClass.IN), cancellationToken);

                            addresses = Dns.DnsClient.ParseResponseAAAA(response);
                            if (addresses.Count < 1)
                                throw new HttpRequestException("HttpClientNetworkHandler could not resolve IPv6 address for host: " + host);
                        }
                        break;

                    default:
                        {
                            Task<DnsDatagram> ipv6Task = (_networkType == HttpClientNetworkType.PreferIPv6) || IsPublicIPv6Available() ? _dnsClient.ResolveAsync(new DnsQuestionRecord(host, DnsResourceRecordType.AAAA, DnsClass.IN), cancellationToken) : null;
                            Task<DnsDatagram> ipv4Task = _dnsClient.ResolveAsync(new DnsQuestionRecord(host, DnsResourceRecordType.A, DnsClass.IN), cancellationToken);

                            List<IPAddress> allAddresses = new List<IPAddress>();

                            if (ipv6Task is not null)
                                allAddresses.AddRange(Dns.DnsClient.ParseResponseAAAA(await ipv6Task));

                            response = await ipv4Task;

                            allAddresses.AddRange(Dns.DnsClient.ParseResponseA(response));

                            if (allAddresses.Count < 1)
                                throw new HttpRequestException("HttpClientNetworkHandler could not resolve IP address for host: " + host);

                            addresses = allAddresses;
                        }
                        break;
                }
            }
            catch (DnsClientException ex)
            {
                throw new HttpRequestException("HttpClientNetworkHandler could not resolve IP address for host: " + host, ex);
            }

            string tlsaBaseDomain = null;
            IReadOnlyList<DnsTLSARecordData> tlsaRecords = null;

            if (_enableDANE)
            {
                try
                {
                    string baseDomain = host;

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if ((record.Type == DnsResourceRecordType.CNAME) && record.Name.Equals(baseDomain, StringComparison.OrdinalIgnoreCase))
                        {
                            if (record.DnssecStatus != DnssecStatus.Secure)
                            {
                                baseDomain = host; //rfc7671#section-7
                                break;
                            }

                            baseDomain = (record.RDATA as DnsCNAMERecordData).Domain;
                        }
                    }

                    Task<DnsDatagram> tlsaTask1 = _dnsClient.ResolveAsync(new DnsQuestionRecord("_" + port + "._tcp." + baseDomain, DnsResourceRecordType.TLSA, DnsClass.IN), cancellationToken);
                    Task<DnsDatagram> tlsaTask2 = host.Equals(baseDomain, StringComparison.OrdinalIgnoreCase) ? null : _dnsClient.ResolveAsync(new DnsQuestionRecord("_" + port + "._tcp." + host, DnsResourceRecordType.TLSA, DnsClass.IN), cancellationToken);

                    IReadOnlyList<DnsTLSARecordData> tlsaRecords1 = Dns.DnsClient.ParseResponseTLSA(await tlsaTask1);
                    IReadOnlyList<DnsTLSARecordData> tlsaRecords2 = tlsaTask2 is null ? null : Dns.DnsClient.ParseResponseTLSA(await tlsaTask2);

                    bool tlsaAvailable1 = (tlsaRecords1 is not null) && (tlsaRecords1.Count > 0);
                    bool tlsaAvailable2 = (tlsaRecords2 is not null) && (tlsaRecords2.Count > 0);

                    if (tlsaAvailable1 && tlsaAvailable2)
                    {
                        tlsaBaseDomain = baseDomain;
                        tlsaRecords = [.. tlsaRecords1, .. tlsaRecords2];
                    }
                    else if (tlsaAvailable1)
                    {
                        tlsaBaseDomain = baseDomain;
                        tlsaRecords = tlsaRecords1;
                    }
                    else if (tlsaAvailable2)
                    {
                        tlsaBaseDomain = host;
                        tlsaRecords = tlsaRecords2;
                    }
                }
                catch (Exception ex)
                {
                    throw new HttpRequestException("HttpClientNetworkHandler could not resolve DANE TLSA record for host: " + host, ex);
                }
            }

            return new DnsResolutionResult([.. addresses], tlsaBaseDomain, tlsaRecords);
        }

        private static void ValidateDane(X509Certificate2 certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors, IReadOnlyList<DnsTLSARecordData> tlsaRecords)
        {
            if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
                throw new AuthenticationException("The remote certificate is invalid according to the validation procedure: " + sslPolicyErrors.ToString());

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

                                    if (BinaryNumber.Equals(certificateAssociatedData, tlsa.CertificateAssociationData))
                                        return; //TLSA is validating
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

                                if (BinaryNumber.Equals(certificateAssociatedData, tlsa.CertificateAssociationData))
                                    return; //TLSA is validating
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
                                    if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch) || (chainElement.ChainElementStatus.Length > 0))
                                    {
                                        //cert has validation issues
                                        pkixFailed = true;
                                        break;
                                    }

                                    //first i.e. end entity certificate only requires cert validation
                                    continue;
                                }

                                //validate TLSA
                                byte[] certificateAssociatedData = DnsTLSARecordData.GetCertificateAssociatedData(tlsa.Selector, tlsa.MatchingType, chainElement.Certificate);
                                bool tlsaVerified = BinaryNumber.Equals(certificateAssociatedData, tlsa.CertificateAssociationData);

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
                                    return; //TLSA is validating; DANE-TA was validated successfully
                            }

                            if (!pkixFailed)
                            {
                                //server probably did not include TA cert in its chain
                                //validation using only digest-based matching type is not possible - rfc7671#section-5.2.2
                                //validation using only public key is not supported - rfc7671#section-5.2.3
                                //DANE-TA(2) Cert(0) Full(0) is only possible case where the server need not provide the TA cert in it chain
                                if ((tlsa.Selector == DnsTLSASelector.Cert) && (tlsa.MatchingType == DnsTLSAMatchingType.Full))
                                {
                                    //validate using TA cert from TLSA record
                                    X509Certificate2 taCert = new X509Certificate2(tlsa.CertificateAssociationData);
                                    X509Certificate2 lastCert = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;

                                    using (X509Chain taChain = new X509Chain())
                                    {
                                        taChain.ChainPolicy.CustomTrustStore.Add(taCert);

                                        if (taChain.Build(lastCert))
                                            return; //TA cert chain is validating
                                    }
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

                            if (BinaryNumber.Equals(certificateAssociatedData, tlsa.CertificateAssociationData))
                                return; //TLSA is validating
                        }
                        break;
                }
            }

            throw new AuthenticationException($"The SSL connection could not be established since the TLS certificate failed DANE validation: no matching TLSA record was found, or the certificate had one or more issues [{sslPolicyErrors}].");
        }

        private static bool IsPublicIPv6Available()
        {
            if (!Socket.OSSupportsIPv6)
                return false;

            if (DateTime.UtcNow > _publicIpv6AvailableLastCheckedOn.AddMilliseconds(PUBLIC_IPv6_CHECK_FREQUENCY))
            {
                _publicIpv6Available = NetUtilities.GetDefaultIPv6NetworkInfo() is not null;
                _publicIpv6AvailableLastCheckedOn = DateTime.UtcNow;
            }

            return _publicIpv6Available;
        }

        #endregion

        #region protected

        protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (_innerHandler.ConnectCallback != ConnectCallback)
                throw new NotSupportedException("ConnectCallback is not supported for SocketsHttpHandler.");

            if (request.Version == HttpVersion.Version30)
                request.Version = HttpVersion.Version20; //downgrade since http/3 is currently not supported

            return base.Send(request, cancellationToken);
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (_innerHandler.ConnectCallback != ConnectCallback)
                throw new NotSupportedException("ConnectCallback is not supported for SocketsHttpHandler.");

            if (request.Version == HttpVersion.Version30)
                request.Version = HttpVersion.Version20; //downgrade since http/3 is currently not supported

            return await base.SendAsync(request, cancellationToken);
        }

        #endregion

        #region properties

        public new SocketsHttpHandler InnerHandler
        { get { return _innerHandler; } }

        public HttpClientNetworkType NetworkType
        {
            get { return _networkType; }
            set { _networkType = value; }
        }

        public IDnsClient DnsClient
        {
            get { return _dnsClient; }
            set { _dnsClient = value; }
        }

        public NetProxy Proxy
        {
            get { return _proxy; }
            set { _proxy = value; }
        }

        public bool EnableDANE
        {
            get { return _enableDANE; }
            set { _enableDANE = value; }
        }

        #endregion

        class DnsResolutionResult
        {
            #region variables

            readonly IPAddress[] _addresses;
            readonly string _tlsaBaseDomain;
            readonly IReadOnlyList<DnsTLSARecordData> _tlsaRecords;

            #endregion

            #region constructor

            public DnsResolutionResult(IPAddress[] addresses, string tlsaBaseDomain, IReadOnlyList<DnsTLSARecordData> tlsaRecords)
            {
                _addresses = addresses;
                _tlsaBaseDomain = tlsaBaseDomain;
                _tlsaRecords = tlsaRecords;
            }

            #endregion

            #region properties

            public IPAddress[] Addresses
            { get { return _addresses; } }

            public string TlsaBaseDomain
            { get { return _tlsaBaseDomain; } }

            public IReadOnlyList<DnsTLSARecordData> TlsaRecords
            { get { return _tlsaRecords; } }

            #endregion
        }
    }
}
