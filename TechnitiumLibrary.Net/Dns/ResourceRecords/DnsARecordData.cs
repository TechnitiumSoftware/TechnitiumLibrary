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

using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsARecordData : DnsResourceRecordData
    {
        #region variables

        IPAddress _address;

        byte[] _rData;

        #endregion

        #region constructor

        public DnsARecordData(IPAddress address)
        {
            _address = address;

            if (_address.AddressFamily != AddressFamily.InterNetwork)
                throw new DnsClientException("Invalid IP address family.");
        }

        public DnsARecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _rData = s.ReadExactly(4);
            _address = new IPAddress(_rData);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            if (_rData is null)
                _rData = _address.GetAddressBytes();

            s.Write(_rData);
        }

        #endregion

        #region internal

        internal static async Task<DnsARecordData> FromZoneFileEntryAsync(ZoneFile zoneFile)
        {
            Stream rdata = await zoneFile.GetRData();
            if (rdata is not null)
                return new DnsARecordData(rdata);

            return new DnsARecordData(IPAddress.Parse(await zoneFile.PopItemAsync()));
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            return _address.ToString();
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsARecordData other)
                return _address.Equals(other._address);

            return false;
        }

        public override int GetHashCode()
        {
            return _address.GetHashCode();
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("IPAddress", _address.ToString());

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public IPAddress Address
        { get { return _address; } }

        public override int UncompressedLength
        { get { return 4; } }

        #endregion
    }
}
