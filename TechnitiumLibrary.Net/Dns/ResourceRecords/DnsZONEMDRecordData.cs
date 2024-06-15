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
    public enum ZoneMdScheme : byte
    {
        Unknown = 0,
        Simple = 1 //Simple ZONEMD collation
    }

    public enum ZoneMdHashAlgorithm : byte
    {
        Unknown = 0,
        SHA384 = 1,
        SHA512 = 2
    }

    public class DnsZONEMDRecordData : DnsResourceRecordData
    {
        #region variables

        uint _serial;
        ZoneMdScheme _scheme;
        ZoneMdHashAlgorithm _hashAlgorithm;
        byte[] _digest;

        byte[] _rData;

        #endregion

        #region constructor

        public DnsZONEMDRecordData(uint serial, ZoneMdScheme scheme, ZoneMdHashAlgorithm hashAlgorithm, byte[] digest)
        {
            switch (hashAlgorithm)
            {
                case ZoneMdHashAlgorithm.SHA384:
                    if (digest.Length != 48)
                        throw new ArgumentException("Invalid Digest value for the Hash Algorithm.");

                    break;

                case ZoneMdHashAlgorithm.SHA512:
                    if (digest.Length != 64)
                        throw new ArgumentException("Invalid Digest value for the Hash Algorithm.");

                    break;

                default:
                    throw new NotSupportedException("Hash Algorithm is not supported: " + hashAlgorithm);
            }

            _serial = serial;
            _scheme = scheme;
            _hashAlgorithm = hashAlgorithm;
            _digest = digest;

            Serialize();
        }

        public DnsZONEMDRecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region private

        private void Serialize()
        {
            using (MemoryStream mS = new MemoryStream(4 + 1 + 1 + _digest.Length))
            {
                DnsDatagram.WriteUInt32NetworkOrder(_serial, mS);
                mS.WriteByte((byte)_scheme);
                mS.WriteByte((byte)_hashAlgorithm);
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
                _serial = DnsDatagram.ReadUInt32NetworkOrder(mS);
                _scheme = (ZoneMdScheme)mS.ReadByteValue();
                _hashAlgorithm = (ZoneMdHashAlgorithm)mS.ReadByteValue();
                _digest = mS.ReadExactly(_rdLength - 4 - 1 - 1);
            }
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            s.Write(_rData);
        }

        #endregion

        #region internal

        internal static async Task<DnsZONEMDRecordData> FromZoneFileEntryAsync(ZoneFile zoneFile)
        {
            Stream rdata = await zoneFile.GetRData();
            if (rdata is not null)
                return new DnsZONEMDRecordData(rdata);

            uint serial = uint.Parse(await zoneFile.PopItemAsync());
            ZoneMdScheme scheme = (ZoneMdScheme)byte.Parse(await zoneFile.PopItemAsync());
            ZoneMdHashAlgorithm hashAlgorithm = (ZoneMdHashAlgorithm)byte.Parse(await zoneFile.PopItemAsync());
            byte[] digest = Convert.FromHexString(await zoneFile.PopItemAsync());

            return new DnsZONEMDRecordData(serial, scheme, hashAlgorithm, digest);
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            return _serial + " " + (byte)_scheme + " " + (byte)_hashAlgorithm + " " + Convert.ToHexString(_digest);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsZONEMDRecordData other)
            {
                if (_serial != other._serial)
                    return false;

                if (_scheme != other._scheme)
                    return false;

                if (_hashAlgorithm != other._hashAlgorithm)
                    return false;

                if (!BinaryNumber.Equals(_digest, other._digest))
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_serial, _scheme, _hashAlgorithm, _digest.GetArrayHashCode());
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteNumber("Serial", _serial);
            jsonWriter.WriteString("Scheme", _scheme.ToString());
            jsonWriter.WriteString("HashAlgorithm", _hashAlgorithm.ToString());
            jsonWriter.WriteString("Digest", Convert.ToHexString(_digest));

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public uint Serial
        { get { return _serial; } }

        public ZoneMdScheme Scheme
        { get { return _scheme; } }

        public ZoneMdHashAlgorithm HashAlgorithm
        { get { return _hashAlgorithm; } }

        public byte[] Digest
        { get { return _digest; } }

        public override int UncompressedLength
        { get { return 4 + 1 + 1 + _digest.Length; } }

        #endregion
    }
}
