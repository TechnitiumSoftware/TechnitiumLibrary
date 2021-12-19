/*
Technitium Library
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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
using System.Runtime.Serialization;
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

    public class DnsDSRecord : DnsResourceRecordData
    {
        #region variables

        ushort _keyTag;
        DnssecAlgorithm _algorithm;
        DnssecDigestType _digestType;
        byte[] _digest;

        byte[] _rData;

        #endregion

        #region constructors

        public DnsDSRecord(ushort keyTag, DnssecAlgorithm algorithm, DnssecDigestType digestType, byte[] digest)
        {
            _keyTag = keyTag;
            _algorithm = algorithm;
            _digestType = digestType;
            _digest = digest;

            Serialize();
        }

        public DnsDSRecord(Stream s)
            : base(s)
        { }

        public DnsDSRecord(dynamic jsonResourceRecord)
        {
            _rdLength = Convert.ToUInt16(jsonResourceRecord.data.Value.Length);

            string[] parts = (jsonResourceRecord.data.Value as string).Split(' ');

            _keyTag = ushort.Parse(parts[0]);
            _algorithm = Enum.Parse<DnssecAlgorithm>(parts[1].Replace("-", "_"), true);
            _digestType = Enum.Parse<DnssecDigestType>(parts[2], true);
            _digest = Convert.FromHexString(parts[3]);

            Serialize();
        }

        #endregion

        #region static

        public static bool IsAlgorithmSupported(IReadOnlyList<DnsResourceRecord> dsRecords)
        {
            foreach (DnsResourceRecord record in dsRecords)
            {
                if (record.Type != DnsResourceRecordType.DS)
                    throw new InvalidOperationException();

                if ((record.RDATA as DnsDSRecord).IsAlgorithmSupported())
                    return true;
            }

            return false;
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
            _rData = s.ReadBytes(_rdLength);

            using (MemoryStream mS = new MemoryStream(_rData))
            {
                _keyTag = DnsDatagram.ReadUInt16NetworkOrder(mS);
                _algorithm = (DnssecAlgorithm)mS.ReadByteValue();
                _digestType = (DnssecDigestType)mS.ReadByteValue();
                _digest = mS.ReadBytes(_rdLength - 2 - 1 - 1);
            }
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            s.Write(_rData);
        }

        #endregion

        #region public

        public bool IsAlgorithmSupported()
        {
            switch (_algorithm)
            {
                case DnssecAlgorithm.RSAMD5:
                case DnssecAlgorithm.RSASHA1:
                case DnssecAlgorithm.RSASHA256:
                case DnssecAlgorithm.RSASHA512:
                case DnssecAlgorithm.RSASHA1_NSEC3_SHA1:
                case DnssecAlgorithm.ECDSAP256SHA256:
                case DnssecAlgorithm.ECDSAP384SHA384:
                    //supported algorithm
                    break;

                default:
                    return false;
            }

            switch (_digestType)
            {
                case DnssecDigestType.SHA1:
                case DnssecDigestType.SHA256:
                case DnssecDigestType.SHA384:
                    //supported digest algorithm
                    break;

                default:
                    return false;
            }

            return true;
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsDSRecord other)
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
            return HashCode.Combine(_keyTag, _algorithm, _digestType, _digest);
        }

        public override string ToString()
        {
            return _keyTag + " " + (byte)_algorithm + " " + (byte)_digestType + " " + Convert.ToHexString(_digest);
        }

        #endregion

        #region properties

        public ushort KeyTag
        { get { return _keyTag; } }

        public DnssecAlgorithm Algorithm
        { get { return _algorithm; } }

        public DnssecDigestType DigestType
        { get { return _digestType; } }

        [IgnoreDataMember]
        public byte[] DigestValue
        { get { return _digest; } }

        public string Digest
        { get { return Convert.ToHexString(_digest); } }

        [IgnoreDataMember]
        public override ushort UncompressedLength
        { get { return Convert.ToUInt16(2 + 1 + 1 + _digest.Length); } }

        #endregion
    }
}
