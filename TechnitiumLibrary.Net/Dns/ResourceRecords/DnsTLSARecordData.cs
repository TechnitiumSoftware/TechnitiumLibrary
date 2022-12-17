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
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public enum DnsTLSACertificateUsage : byte
    {
        PKIX_TA = 0, //CA constraint
        PKIX_EE = 1, //Service certificate constraint
        DANE_TA = 2, //Trust anchor assertion
        DANE_EE = 3, //Domain-issued certificate
        PrivCert = 255 //Reserved for Private Use
    }

    public enum DnsTLSASelector : byte
    {
        Cert = 0, //Full certificate
        SPKI = 1, //SubjectPublicKeyInfo
        PrivSel = 255 //Reserved for Private Use
    }

    public enum DnsTLSAMatchingType : byte
    {
        Full = 0, //No hash used
        SHA2_256 = 1, //256 bit hash by SHA2
        SHA2_512 = 2, //512 bit hash by SHA2
        PrivMatch = 255 //Reserved for Private Use
    }

    public class DnsTLSARecordData : DnsResourceRecordData
    {
        #region variables

        DnsTLSACertificateUsage _certificateUsage;
        DnsTLSASelector _selector;
        DnsTLSAMatchingType _matchingType;
        byte[] _certificateAssociationData;

        #endregion

        #region constructor

        public DnsTLSARecordData(DnsTLSACertificateUsage certificateUsage, DnsTLSASelector selector, DnsTLSAMatchingType matchingType, byte[] certificateAssociationData)
        {
            switch (matchingType)
            {
                case DnsTLSAMatchingType.Full:
                    if (certificateAssociationData.Length == 0)
                        throw new ArgumentException("Invalid Certificate Association Data value for the Matching Type.");

                    break;

                case DnsTLSAMatchingType.SHA2_256:
                    if (certificateAssociationData.Length != 32)
                        throw new ArgumentException("Invalid Certificate Association Data value for the Matching Type.");

                    break;

                case DnsTLSAMatchingType.SHA2_512:
                    if (certificateAssociationData.Length != 64)
                        throw new ArgumentException("Invalid Certificate Association Data value for the Matching Type.");

                    break;

                default:
                    throw new NotSupportedException("Matching Type is not supported: " + matchingType);
            }

            _certificateUsage = certificateUsage;
            _selector = selector;
            _matchingType = matchingType;
            _certificateAssociationData = certificateAssociationData;
        }

        public DnsTLSARecordData(DnsTLSACertificateUsage certificateUsage, DnsTLSASelector selector, DnsTLSAMatchingType matchingType, string certificateAssociationData)
        {
            _certificateUsage = certificateUsage;
            _selector = selector;
            _matchingType = matchingType;

            if (certificateAssociationData.StartsWith('-'))
            {
                _certificateAssociationData = GetCertificateAssociatedData(_selector, _matchingType, X509Certificate2.CreateFromPem(certificateAssociationData));
            }
            else
            {
                switch (_matchingType)
                {
                    case DnsTLSAMatchingType.Full:
                        if (certificateAssociationData.Length == 0)
                            throw new ArgumentException("Invalid Certificate Association Data value for the Matching Type.");

                        break;

                    case DnsTLSAMatchingType.SHA2_256:
                        if (certificateAssociationData.Length != 64)
                            throw new ArgumentException("Invalid Certificate Association Data value for the Matching Type.");

                        break;

                    case DnsTLSAMatchingType.SHA2_512:
                        if (certificateAssociationData.Length != 128)
                            throw new ArgumentException("Invalid Certificate Association Data value for the Matching Type.");

                        break;

                    default:
                        throw new NotSupportedException("Matching Type is not supported: " + matchingType);
                }

                _certificateAssociationData = Convert.FromHexString(certificateAssociationData);
            }
        }

        public DnsTLSARecordData(DnsTLSACertificateUsage certificateUsage, DnsTLSASelector selector, DnsTLSAMatchingType matchingType, X509Certificate2 certificate)
        {
            _certificateUsage = certificateUsage;
            _selector = selector;
            _matchingType = matchingType;
            _certificateAssociationData = GetCertificateAssociatedData(_selector, _matchingType, certificate);
        }

        public DnsTLSARecordData(Stream s)
            : base(s)
        { }

        public DnsTLSARecordData(JsonElement jsonResourceRecord)
        {
            string rdata = jsonResourceRecord.GetProperty("data").GetString();

            _rdLength = Convert.ToUInt16(rdata.Length);

            string[] parts = rdata.Split(' ');

            _certificateUsage = (DnsTLSACertificateUsage)byte.Parse(parts[0]);
            _selector = (DnsTLSASelector)byte.Parse(parts[1]);
            _matchingType = (DnsTLSAMatchingType)byte.Parse(parts[2]);
            _certificateAssociationData = Convert.FromHexString(parts[3]);
        }

        #endregion

        #region static

        public static byte[] GetCertificateAssociatedData(DnsTLSASelector selector, DnsTLSAMatchingType matchingType, X509Certificate certificate)
        {
            byte[] certificateData;

            switch (selector)
            {
                case DnsTLSASelector.Cert:
                    certificateData = certificate.GetRawCertData();
                    break;

                case DnsTLSASelector.SPKI:
                    certificateData = (certificate as X509Certificate2).PublicKey.ExportSubjectPublicKeyInfo();
                    break;

                default:
                    throw new NotSupportedException("The TLSA selector is not supported: " + selector.ToString());
            }

            switch (matchingType)
            {
                case DnsTLSAMatchingType.Full:
                    return certificateData;

                case DnsTLSAMatchingType.SHA2_256:
                    using (HashAlgorithm hash = SHA256.Create())
                    {
                        return hash.ComputeHash(certificateData);
                    }

                case DnsTLSAMatchingType.SHA2_512:
                    using (HashAlgorithm hash = SHA512.Create())
                    {
                        return hash.ComputeHash(certificateData);
                    }

                default:
                    throw new NotSupportedException("The TLSA matching type is not supported: " + matchingType.ToString());
            }
        }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _certificateUsage = (DnsTLSACertificateUsage)s.ReadByteValue();
            _selector = (DnsTLSASelector)s.ReadByteValue();
            _matchingType = (DnsTLSAMatchingType)s.ReadByteValue();
            _certificateAssociationData = s.ReadBytes(_rdLength - 3);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            s.WriteByte((byte)_certificateUsage);
            s.WriteByte((byte)_selector);
            s.WriteByte((byte)_matchingType);
            s.Write(_certificateAssociationData);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsTLSARecordData other)
            {
                if (_certificateUsage != other._certificateUsage)
                    return false;

                if (_selector != other._selector)
                    return false;

                if (_matchingType != other._matchingType)
                    return false;

                if (!BinaryNumber.Equals(_certificateAssociationData, other._certificateAssociationData))
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_certificateUsage, _selector, _matchingType, _certificateAssociationData);
        }

        public override string ToString()
        {
            return (byte)_certificateUsage + " " + (byte)_selector + " " + (byte)_matchingType + " " + Convert.ToHexString(_certificateAssociationData);
        }

        #endregion

        #region properties

        public DnsTLSACertificateUsage CertificateUsage
        { get { return _certificateUsage; } }

        public DnsTLSASelector Selector
        { get { return _selector; } }

        public DnsTLSAMatchingType MatchingType
        { get { return _matchingType; } }

        [JsonIgnore]
        public byte[] CertificateAssociationDataValue
        { get { return _certificateAssociationData; } }

        public string CertificateAssociationData
        { get { return Convert.ToHexString(_certificateAssociationData); } }

        [JsonIgnore]
        public override ushort UncompressedLength
        { get { return Convert.ToUInt16(1 + 1 + 1 + _certificateAssociationData.Length); } }

        #endregion
    }
}
