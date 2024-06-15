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
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public enum DnssecDigestType : byte
    {
        Unknown = 0,
        SHA1 = 1,
        SHA256 = 2,
        GOST_R_34_11_94 = 3,
        SHA384 = 4
    }

    public class DnsDSRecordData : DnsResourceRecordData
    {
        #region variables

        ushort _keyTag;
        DnssecAlgorithm _algorithm;
        DnssecDigestType _digestType;
        byte[] _digest;

        byte[] _rData;

        #endregion

        #region constructors

        public DnsDSRecordData(ushort keyTag, DnssecAlgorithm algorithm, DnssecDigestType digestType, byte[] digest)
        {
            switch (digestType)
            {
                case DnssecDigestType.SHA1:
                    if (digest.Length != 20)
                        throw new ArgumentException("Invalid Digest value for the Digest Type.");

                    break;

                case DnssecDigestType.SHA256:
                case DnssecDigestType.GOST_R_34_11_94:
                    if (digest.Length != 32)
                        throw new ArgumentException("Invalid Digest value for the Digest Type.");

                    break;

                case DnssecDigestType.SHA384:
                    if (digest.Length != 48)
                        throw new ArgumentException("Invalid Digest value for the Digest Type.");

                    break;

                default:
                    throw new NotSupportedException("Digest Type is not supported: " + digestType);
            }

            _keyTag = keyTag;
            _algorithm = algorithm;
            _digestType = digestType;
            _digest = digest;

            Serialize();
        }

        public DnsDSRecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region static

        public static bool IsAnyDnssecAlgorithmSupported(IReadOnlyList<DnsResourceRecord> dsRecords)
        {
            foreach (DnsResourceRecord record in dsRecords)
            {
                if (record.Type != DnsResourceRecordType.DS)
                    throw new InvalidOperationException();

                if (IsDnssecAlgorithmSupported((record.RDATA as DnsDSRecordData)._algorithm))
                    return true;
            }

            return false;
        }

        public static bool IsAnyDigestTypeSupported(IReadOnlyList<DnsResourceRecord> dsRecords)
        {
            foreach (DnsResourceRecord record in dsRecords)
            {
                if (record.Type != DnsResourceRecordType.DS)
                    throw new InvalidOperationException();

                if (IsDigestTypeSupported((record.RDATA as DnsDSRecordData)._digestType))
                    return true;
            }

            return false;
        }

        public static bool IsDnssecAlgorithmSupported(DnssecAlgorithm algorithm)
        {
            switch (algorithm)
            {
                //case DnssecAlgorithm.RSAMD5: depricated
                case DnssecAlgorithm.RSASHA1:
                case DnssecAlgorithm.RSASHA256:
                case DnssecAlgorithm.RSASHA512:
                case DnssecAlgorithm.RSASHA1_NSEC3_SHA1:
                case DnssecAlgorithm.ECDSAP256SHA256:
                case DnssecAlgorithm.ECDSAP384SHA384:
                    return true;

                default:
                    return false;
            }
        }

        public static bool IsDigestTypeSupported(DnssecDigestType digestType)
        {
            switch (digestType)
            {
                case DnssecDigestType.SHA1:
                case DnssecDigestType.SHA256:
                case DnssecDigestType.SHA384:
                    return true;

                default:
                    return false;
            }
        }

        #endregion

        #region private

        private void Serialize()
        {
            using (MemoryStream mS = new MemoryStream(2 + 1 + 1 + _digest.Length))
            {
                DnsDatagram.WriteUInt16NetworkOrder(_keyTag, mS);
                mS.WriteByte((byte)_algorithm);
                mS.WriteByte((byte)_digestType);
                mS.Write(_digest);

                _rData = mS.ToArray();
            }
        }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _rData = s.ReadExactly(_rdLength);

            using (MemoryStream mS = new MemoryStream(_rData))
            {
                _keyTag = DnsDatagram.ReadUInt16NetworkOrder(mS);
                _algorithm = (DnssecAlgorithm)mS.ReadByteValue();
                _digestType = (DnssecDigestType)mS.ReadByteValue();
                _digest = mS.ReadExactly(_rdLength - 2 - 1 - 1);
            }
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            s.Write(_rData);
        }

        #endregion

        #region internal

        internal static async Task<DnsDSRecordData> FromZoneFileEntryAsync(ZoneFile zoneFile)
        {
            Stream rdata = await zoneFile.GetRData();
            if (rdata is not null)
                return new DnsDSRecordData(rdata);

            ushort keyTag = ushort.Parse(await zoneFile.PopItemAsync());
            DnssecAlgorithm algorithm = (DnssecAlgorithm)byte.Parse(await zoneFile.PopItemAsync());
            DnssecDigestType digestType = (DnssecDigestType)byte.Parse(await zoneFile.PopItemAsync());
            byte[] digest = Convert.FromHexString(await zoneFile.PopItemAsync());

            return new DnsDSRecordData(keyTag, algorithm, digestType, digest);
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            return _keyTag + " " + (byte)_algorithm + " " + (byte)_digestType + " " + Convert.ToHexString(_digest);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsDSRecordData other)
            {
                if (_keyTag != other._keyTag)
                    return false;

                if (_algorithm != other._algorithm)
                    return false;

                if (_digestType != other._digestType)
                    return false;

                if (!BinaryNumber.Equals(_digest, other._digest))
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_keyTag, _algorithm, _digestType, _digest.GetArrayHashCode());
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteNumber("KeyTag", _keyTag);
            jsonWriter.WriteString("Algorithm", _algorithm.ToString());
            jsonWriter.WriteString("DigestType", _digestType.ToString());
            jsonWriter.WriteString("Digest", Convert.ToHexString(_digest));

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public ushort KeyTag
        { get { return _keyTag; } }

        public DnssecAlgorithm Algorithm
        { get { return _algorithm; } }

        public DnssecDigestType DigestType
        { get { return _digestType; } }

        public byte[] Digest
        { get { return _digest; } }

        public override int UncompressedLength
        { get { return 2 + 1 + 1 + _digest.Length; } }

        #endregion
    }
}
