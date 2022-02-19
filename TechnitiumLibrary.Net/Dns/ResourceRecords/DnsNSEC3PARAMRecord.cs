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
using System.Runtime.Serialization;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsNSEC3PARAMRecord : DnsResourceRecordData
    {
        #region variables

        DnssecNSEC3HashAlgorithm _hashAlgorithm;
        DnssecNSEC3Flags _flags;
        ushort _iterations;
        byte[] _salt;

        byte[] _rData;

        #endregion

        #region constructors

        public DnsNSEC3PARAMRecord(DnssecNSEC3HashAlgorithm hashAlgorithm, DnssecNSEC3Flags flags, ushort iterations, byte[] salt)
        {
            _hashAlgorithm = hashAlgorithm;
            _flags = flags;
            _iterations = iterations;
            _salt = salt;

            Serialize();
        }

        public DnsNSEC3PARAMRecord(Stream s)
            : base(s)
        { }

        public DnsNSEC3PARAMRecord(dynamic jsonResourceRecord)
        {
            _rdLength = Convert.ToUInt16(jsonResourceRecord.data.Value.Length);

            string[] parts = (jsonResourceRecord.data.Value as string).Split(' ');

            _hashAlgorithm = Enum.Parse<DnssecNSEC3HashAlgorithm>(parts[0], true);
            _flags = Enum.Parse<DnssecNSEC3Flags>(parts[1], true);
            _iterations = ushort.Parse(parts[2]);
            _salt = parts[3] == "-" ? Array.Empty<byte>() : Convert.FromHexString(parts[3]);

            Serialize();
        }

        #endregion

        #region private

        private void Serialize()
        {
            using (MemoryStream mS = new MemoryStream(1 + 1 + 2 + 1 + _salt.Length))
            {
                mS.WriteByte((byte)_hashAlgorithm);
                mS.WriteByte((byte)_flags);
                DnsDatagram.WriteUInt16NetworkOrder(_iterations, mS);
                mS.WriteByte((byte)_salt.Length);
                mS.Write(_salt);

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
                _hashAlgorithm = (DnssecNSEC3HashAlgorithm)mS.ReadByteValue();
                _flags = (DnssecNSEC3Flags)mS.ReadByteValue();
                _iterations = DnsDatagram.ReadUInt16NetworkOrder(mS);
                _salt = mS.ReadBytes(mS.ReadByteValue());
            }
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            s.Write(_rData);
        }

        #endregion

        #region public

        public string ComputeHashedOwnerNameBase32HexString(string ownerName)
        {
            return Base32.ToBase32HexString(DnsNSEC3Record.ComputeHashedOwnerName(ownerName, _hashAlgorithm, _iterations, _salt));
        }

        public byte[] ComputeHashedOwnerName(string ownerName)
        {
            return DnsNSEC3Record.ComputeHashedOwnerName(ownerName, _hashAlgorithm, _iterations, _salt);
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsNSEC3PARAMRecord other)
            {
                if (_hashAlgorithm != other._hashAlgorithm)
                    return false;

                if (_flags != other._flags)
                    return false;

                if (_iterations != other._iterations)
                    return false;

                if (!BinaryNumber.Equals(_salt, other._salt))
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_hashAlgorithm, _flags, _iterations, _salt);
        }

        public override string ToString()
        {
            return (byte)_hashAlgorithm + " " + (byte)_flags + " " + _iterations + " " + (_salt.Length == 0 ? "-" : Convert.ToHexString(_salt));
        }

        #endregion

        #region properties

        public DnssecNSEC3HashAlgorithm HashAlgorithm
        { get { return _hashAlgorithm; } }

        public DnssecNSEC3Flags Flags
        { get { return _flags; } }

        public ushort Iterations
        { get { return _iterations; } }

        public string Salt
        { get { return Convert.ToHexString(_salt); } }

        [IgnoreDataMember]
        public byte[] SaltValue
        { get { return _salt; } }

        [IgnoreDataMember]
        public override ushort UncompressedLength
        { get { return Convert.ToUInt16(_rData.Length); } }

        #endregion
    }
}
