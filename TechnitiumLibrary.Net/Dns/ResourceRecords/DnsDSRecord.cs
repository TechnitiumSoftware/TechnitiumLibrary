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

        byte[] _serializedData;

        #endregion

        #region constructors

        public DnsDSRecord(ushort keyTag, DnssecAlgorithm algorithm, DnssecDigestType digestType, byte[] digest)
        {
            _keyTag = keyTag;
            _algorithm = algorithm;
            _digestType = digestType;
            _digest = digest;
        }

        public DnsDSRecord(Stream s)
            : base(s)
        { }

        public DnsDSRecord(dynamic jsonResourceRecord)
        {
            throw new NotSupportedException();
        }

        #endregion

        #region protected

        protected override void Parse(Stream s)
        {
            _serializedData = s.ReadBytes(_rdLength);

            using (MemoryStream mS = new MemoryStream(_serializedData))
            {
                _keyTag = DnsDatagram.ReadUInt16NetworkOrder(mS);
                _algorithm = (DnssecAlgorithm)mS.ReadByteValue();
                _digestType = (DnssecDigestType)mS.ReadByteValue();
                _digest = mS.ReadBytes(_rdLength - 2 - 1 - 1);
            }
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
        {
            if (_serializedData is null)
            {
                using (MemoryStream mS = new MemoryStream())
                {
                    DnsDatagram.WriteUInt16NetworkOrder(_keyTag, mS);
                    mS.WriteByte((byte)_algorithm);
                    mS.WriteByte((byte)_digestType);
                    mS.Write(_digest);

                    _serializedData = mS.ToArray();
                }
            }

            s.Write(_serializedData);
        }

        #endregion

        #region public

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
            return _keyTag + " " + (byte)_algorithm + " " + (byte)_digestType + " ( " + BitConverter.ToString(_digest).Replace("-", "") + " )";
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

        [IgnoreDataMember]
        public override ushort UncompressedLength
        { get { return Convert.ToUInt16(2 + 1 + 1 + _digest.Length); } }

        #endregion
    }
}
