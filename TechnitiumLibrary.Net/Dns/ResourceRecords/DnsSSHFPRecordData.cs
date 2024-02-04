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

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _algorithm = (DnsSSHFPAlgorithm)s.ReadByteValue();
            _fingerprintType = (DnsSSHFPFingerprintType)s.ReadByteValue();
            _fingerprint = s.ReadExactly(_rdLength - 2);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            s.WriteByte((byte)_algorithm);
            s.WriteByte((byte)_fingerprintType);
            s.Write(_fingerprint);
        }

        #endregion

        #region internal

        internal static async Task<DnsSSHFPRecordData> FromZoneFileEntryAsync(ZoneFile zoneFile)
        {
            Stream rdata = await zoneFile.GetRData();
            if (rdata is not null)
                return new DnsSSHFPRecordData(rdata);

            DnsSSHFPAlgorithm algorithm = (DnsSSHFPAlgorithm)byte.Parse(await zoneFile.PopItemAsync());
            DnsSSHFPFingerprintType fingerprintType = (DnsSSHFPFingerprintType)byte.Parse(await zoneFile.PopItemAsync());
            byte[] fingerprint = Convert.FromHexString(await zoneFile.PopItemAsync());

            return new DnsSSHFPRecordData(algorithm, fingerprintType, fingerprint);
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            return (byte)_algorithm + " " + (byte)_fingerprintType + " " + Convert.ToHexString(_fingerprint);
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

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("Algorithm", _algorithm.ToString());
            jsonWriter.WriteString("FingerprintType", _fingerprint.ToString());
            jsonWriter.WriteString("Fingerprint", Convert.ToHexString(_fingerprint));

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public DnsSSHFPAlgorithm Algorithm
        { get { return _algorithm; } }

        public DnsSSHFPFingerprintType FingerprintType
        { get { return _fingerprintType; } }

        public byte[] Fingerprint
        { get { return _fingerprint; } }

        public override int UncompressedLength
        { get { return 1 + 1 + _fingerprint.Length; } }

        #endregion
    }
}
