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
    public enum DnsSSHFPAlgorithm : byte
    {
        Reserved = 0,
        RSA = 1,
        DSA = 2,
        ECDSA = 3,
        Ed25519 = 4,
        Ed448 = 6
    }

    public enum DnsSSHFPFingerprintType : byte
    {
        Reserved = 0,
        SHA1 = 1,
        SHA256 = 2
    }

    public class DnsSSHFPRecordData : DnsResourceRecordData
    {
        #region variables

        DnsSSHFPAlgorithm _algorithm;
        DnsSSHFPFingerprintType _fingerprintType;
        byte[] _fingerprint;

        #endregion

        #region constructor

        public DnsSSHFPRecordData(DnsSSHFPAlgorithm algorithm, DnsSSHFPFingerprintType fingerprintType, byte[] fingerprint)
        {
            switch (fingerprintType)
            {
                case DnsSSHFPFingerprintType.SHA1:
                    if (fingerprint.Length != 20)
                        throw new ArgumentException("Invalid Fingerprint value for the Fingerprint Type.");

                    break;

                case DnsSSHFPFingerprintType.SHA256:
                    if (fingerprint.Length != 32)
                        throw new ArgumentException("Invalid Fingerprint value for the Fingerprint Type.");

                    break;

                default:
                    throw new NotSupportedException("Fingerprint Type is not supported: " + fingerprintType);
            }

            _algorithm = algorithm;
            _fingerprintType = fingerprintType;
            _fingerprint = fingerprint;
        }

        public DnsSSHFPRecordData(Stream s)
            : base(s)
        { }

        public DnsSSHFPRecordData(dynamic jsonResourceRecord)
        {
            _rdLength = Convert.ToUInt16(jsonResourceRecord.data.Value.Length);

            string[] parts = (jsonResourceRecord.data.Value as string).Split(' ');

            _algorithm = (DnsSSHFPAlgorithm)byte.Parse(parts[0]);
            _fingerprintType = (DnsSSHFPFingerprintType)byte.Parse(parts[1]);
            _fingerprint = Convert.FromHexString(parts[2]);
        }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _algorithm = (DnsSSHFPAlgorithm)s.ReadByteValue();
            _fingerprintType = (DnsSSHFPFingerprintType)s.ReadByteValue();
            _fingerprint = s.ReadBytes(_rdLength - 2);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            s.WriteByte((byte)_algorithm);
            s.WriteByte((byte)_fingerprintType);
            s.Write(_fingerprint);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsSSHFPRecordData other)
            {
                if (_algorithm != other._algorithm)
                    return false;

                if (_fingerprintType != other._fingerprintType)
                    return false;

                if (!BinaryNumber.Equals(_fingerprint, other._fingerprint))
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_algorithm, _fingerprintType, _fingerprint);
        }

        public override string ToString()
        {
            return (byte)_algorithm + " " + (byte)_fingerprintType + " " + Convert.ToHexString(_fingerprint);
        }

        #endregion

        #region properties

        public DnsSSHFPAlgorithm Algorithm
        { get { return _algorithm; } }

        public DnsSSHFPFingerprintType FingerprintType
        { get { return _fingerprintType; } }

        [IgnoreDataMember]
        public byte[] FingerprintValue
        { get { return _fingerprint; } }

        public string Fingerprint
        { get { return Convert.ToHexString(_fingerprint); } }

        [IgnoreDataMember]
        public override ushort UncompressedLength
        { get { return Convert.ToUInt16(1 + 1 + _fingerprint.Length); } }

        #endregion
    }
}
