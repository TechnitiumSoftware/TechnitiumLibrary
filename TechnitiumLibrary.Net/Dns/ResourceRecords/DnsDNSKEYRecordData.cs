/*
Technitium Library
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

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
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns.Dnssec;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [Flags]
    public enum DnsDnsKeyFlag : ushort
    {
        ZoneKey = 0x100,
        SecureEntryPoint = 0x1,
        Revoke = 0x80
    }

    public enum DnssecAlgorithm : byte
    {
        Unknown = 0,
        RSAMD5 = 1,
        DSA = 3,
        RSASHA1 = 5,
        DSA_NSEC3_SHA1 = 6,
        RSASHA1_NSEC3_SHA1 = 7,
        RSASHA256 = 8,
        RSASHA512 = 10,
        ECC_GOST = 12,
        ECDSAP256SHA256 = 13,
        ECDSAP384SHA384 = 14,
        ED25519 = 15,
        ED448 = 16,
        PRIVATEDNS = 253,
        PRIVATEOID = 254
    }

    public class DnsDNSKEYRecordData : DnsResourceRecordData
    {
        #region variables

        DnsDnsKeyFlag _flags;
        byte _protocol;
        DnssecAlgorithm _algorithm;
        DnssecPublicKey _publicKey;

        ushort _computedKeyTag;

        byte[] _rData;

        #endregion

        #region constructors

        public DnsDNSKEYRecordData(DnsDnsKeyFlag flags, byte protocol, DnssecAlgorithm algorithm, DnssecPublicKey publicKey)
        {
            _flags = flags;
            _protocol = protocol;
            _algorithm = algorithm;
            _publicKey = publicKey;

            Serialize();
            ComputeKeyTag();
        }

        public DnsDNSKEYRecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region static

        public static bool IsAnyDnssecAlgorithmSupported(IReadOnlyList<DnsResourceRecord> dnsKeyRecords)
        {
            foreach (DnsResourceRecord record in dnsKeyRecords)
            {
                if (record.Type != DnsResourceRecordType.DNSKEY)
                    continue;

                if (DnsDSRecordData.IsDnssecAlgorithmSupported((record.RDATA as DnsDNSKEYRecordData)._algorithm))
                    return true;
            }

            return false;
        }

        #endregion

        #region private

        private void Serialize()
        {
            using (MemoryStream mS = new MemoryStream())
            {
                DnsDatagram.WriteUInt16NetworkOrder((ushort)_flags, mS);
                mS.WriteByte(_protocol);
                mS.WriteByte((byte)_algorithm);
                _publicKey.WriteTo(mS);

                _rData = mS.ToArray();
            }
        }

        private void ComputeKeyTag()
        {
            switch (_algorithm)
            {
                case DnssecAlgorithm.RSAMD5:
                    byte[] buffer = new byte[2];
                    Buffer.BlockCopy(_publicKey.RawPublicKey, _publicKey.RawPublicKey.Length - 3, buffer, 0, 2);
                    Array.Reverse(buffer);
                    _computedKeyTag = BitConverter.ToUInt16(buffer);
                    break;

                default:
                    uint ac = 0;

                    for (int i = 0; i < _rData.Length; i++)
                    {
                        if ((i & 1) > 0)
                            ac += _rData[i];
                        else
                            ac += (uint)(_rData[i] << 8);
                    }

                    ac += (ac >> 16) & 0xFFFF;

                    _computedKeyTag = (ushort)(ac & 0xFFFFu);
                    break;
            }
        }

        private byte[] ComputeDigest(string ownerName, DnssecDigestType digestType)
        {
            using (MemoryStream mS = new MemoryStream(DnsDatagram.GetSerializeDomainNameLength(ownerName) + _rData.Length))
            {
                DnsDatagram.SerializeDomainName(ownerName.ToLowerInvariant(), mS);
                mS.Write(_rData);

                mS.Position = 0;

                switch (digestType)
                {
                    case DnssecDigestType.SHA1:
                        return SHA1.HashData(mS);

                    case DnssecDigestType.SHA256:
                        return SHA256.HashData(mS);

                    case DnssecDigestType.SHA384:
                        return SHA384.HashData(mS);

                    default:
                        throw new NotSupportedException("DNSSEC DS digest type hash algorithm is not supported: " + digestType.ToString());
                }
            }
        }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _rData = s.ReadExactly(_rdLength);

            using (MemoryStream mS = new MemoryStream(_rData))
            {
                _flags = (DnsDnsKeyFlag)DnsDatagram.ReadUInt16NetworkOrder(mS);
                _protocol = mS.ReadByteValue();
                _algorithm = (DnssecAlgorithm)mS.ReadByteValue();
                _publicKey = DnssecPublicKey.Parse(_algorithm, mS.ReadExactly(_rdLength - 2 - 1 - 1));
            }

            ComputeKeyTag();
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            s.Write(_rData);
        }

        #endregion

        #region internal

        internal static async Task<DnsDNSKEYRecordData> FromZoneFileEntryAsync(ZoneFile zoneFile)
        {
            Stream rdata = await zoneFile.GetRData();
            if (rdata is not null)
                return new DnsDNSKEYRecordData(rdata);

            DnsDnsKeyFlag flags = (DnsDnsKeyFlag)ushort.Parse(await zoneFile.PopItemAsync());
            byte protocol = byte.Parse(await zoneFile.PopItemAsync());
            DnssecAlgorithm algorithm = (DnssecAlgorithm)byte.Parse(await zoneFile.PopItemAsync());
            DnssecPublicKey publicKey = DnssecPublicKey.Parse(algorithm, Convert.FromBase64String(await zoneFile.PopToEndAsync()));

            return new DnsDNSKEYRecordData(flags, protocol, algorithm, publicKey);
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            return (ushort)_flags + " " + _protocol + " " + (byte)_algorithm + " " + Convert.ToBase64String(_publicKey.RawPublicKey);
        }

        #endregion

        #region public

        public bool IsDnsKeyValid(string ownerName, DnsDSRecordData ds)
        {
            byte[] computedDigest = ComputeDigest(ownerName, ds.DigestType);

            return BinaryNumber.Equals(computedDigest, ds.Digest);
        }

        public DnsDSRecordData CreateDS(string ownerName, DnssecDigestType digestType)
        {
            byte[] computedDigest = ComputeDigest(ownerName, digestType);

            return new DnsDSRecordData(_computedKeyTag, _algorithm, digestType, computedDigest);
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsDNSKEYRecordData other)
            {
                if (_flags != other._flags)
                    return false;

                if (_protocol != other._protocol)
                    return false;

                if (_algorithm != other._algorithm)
                    return false;

                if (!BinaryNumber.Equals(_publicKey.RawPublicKey, other._publicKey.RawPublicKey))
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_flags, _protocol, _algorithm, _publicKey.RawPublicKey);
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("Flags", _flags.ToString());
            jsonWriter.WriteNumber("Protocol", _protocol);
            jsonWriter.WriteString("Algorithm", _algorithm.ToString());
            jsonWriter.WriteString("PublicKey", Convert.ToBase64String(_publicKey.RawPublicKey));
            jsonWriter.WriteNumber("ComputedKeyTag", _computedKeyTag);

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public DnsDnsKeyFlag Flags
        { get { return _flags; } }

        public byte Protocol
        { get { return _protocol; } }

        public DnssecAlgorithm Algorithm
        { get { return _algorithm; } }

        public DnssecPublicKey PublicKey
        { get { return _publicKey; } }

        public ushort ComputedKeyTag
        { get { return _computedKeyTag; } }

        public override int UncompressedLength
        { get { return _rData.Length; } }

        #endregion
    }
}
