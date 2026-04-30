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
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    // RFC 4398 certificate types
    public enum DnsCertType : ushort
    {
        Reserved = 0,
        PKIX = 1,   // X.509 as per PKIX
        SPKI = 2,   // SPKI certificate
        PGP = 3,    // OpenPGP packet
        IPKIX = 4,  // URL of an X.509 data object
        ISPKI = 5,  // URL of an SPKI certificate
        IPGP = 6,   // Fingerprint and URL of an OpenPGP packet
        ACPKIX = 7, // Attribute Certificate
        IACPKIX = 8,// URL of an Attribute Certificate
        URI = 253,  // URI private
        OID = 254   // OID private
    }

    public class DnsCERTRecordData : DnsResourceRecordData
    {
        #region variables

        DnsCertType _certType;
        ushort _keyTag;
        byte _algorithm;
        byte[] _certificate;

        #endregion

        #region constructor

        public DnsCERTRecordData(DnsCertType certType, ushort keyTag, byte algorithm, byte[] certificate)
        {
            _certType = certType;
            _keyTag = keyTag;
            _algorithm = algorithm;
            _certificate = certificate;
        }

        public DnsCERTRecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _certType = (DnsCertType)DnsDatagram.ReadUInt16NetworkOrder(s);
            _keyTag = DnsDatagram.ReadUInt16NetworkOrder(s);
            _algorithm = s.ReadByteValue();
            _certificate = s.ReadExactly(_rdLength - 5);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            DnsDatagram.WriteUInt16NetworkOrder((ushort)_certType, s);
            DnsDatagram.WriteUInt16NetworkOrder(_keyTag, s);
            s.WriteByte(_algorithm);
            s.Write(_certificate);
        }

        #endregion

        #region internal

        internal static async Task<DnsCERTRecordData> FromZoneFileEntryAsync(ZoneFile zoneFile)
        {
            Stream rdata = await zoneFile.GetRData();
            if (rdata is not null)
                return new DnsCERTRecordData(rdata);

            // cert-type is numeric or mnemonic (e.g. "PGP" or "3")
            string certTypeStr = await zoneFile.PopItemAsync();
            DnsCertType certType = Enum.TryParse(certTypeStr, true, out DnsCertType parsed)
                ? parsed
                : (DnsCertType)ushort.Parse(certTypeStr);

            ushort keyTag = ushort.Parse(await zoneFile.PopItemAsync());
            byte algorithm = byte.Parse(await zoneFile.PopItemAsync());
            byte[] certificate = Convert.FromBase64String(await zoneFile.PopItemAsync());

            return new DnsCERTRecordData(certType, keyTag, algorithm, certificate);
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            return (ushort)_certType + " " + _keyTag + " " + _algorithm + " " + Convert.ToBase64String(_certificate);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsCERTRecordData other)
            {
                if (_certType != other._certType)
                    return false;

                if (_keyTag != other._keyTag)
                    return false;

                if (_algorithm != other._algorithm)
                    return false;

                if (!BinaryNumber.Equals(_certificate, other._certificate))
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_certType, _keyTag, _algorithm, _certificate.GetArrayHashCode());
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("CertType", _certType.ToString());
            jsonWriter.WriteNumber("KeyTag", _keyTag);
            jsonWriter.WriteNumber("Algorithm", _algorithm);
            jsonWriter.WriteString("Certificate", Convert.ToBase64String(_certificate));

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public DnsCertType CertType
        { get { return _certType; } }

        public ushort KeyTag
        { get { return _keyTag; } }

        public byte Algorithm
        { get { return _algorithm; } }

        public byte[] Certificate
        { get { return _certificate; } }

        public override int UncompressedLength
        { get { return 2 + 2 + 1 + _certificate.Length; } }

        #endregion
    }
}
