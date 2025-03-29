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
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsNSRecordData : DnsResourceRecordData
    {
        #region variables

        string _nameServer;

        NameServerMetadata _metadata;

        #endregion

        #region constructor

        public DnsNSRecordData(string nameServer, bool validateName = true)
        {
            if (validateName)
            {
                if (DnsClient.IsDomainNameUnicode(nameServer))
                    nameServer = DnsClient.ConvertDomainNameToAscii(nameServer);

                DnsClient.IsDomainNameValid(nameServer, true);

                if (IPAddress.TryParse(nameServer, out _))
                    throw new DnsClientException("Invalid domain name [" + nameServer + "]: IP address cannot be used for name server domain name.");
            }

            _nameServer = nameServer;
        }

        public DnsNSRecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _nameServer = DnsDatagram.DeserializeDomainName(s);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            DnsDatagram.SerializeDomainName(canonicalForm ? _nameServer.ToLowerInvariant() : _nameServer, s, domainEntries);
        }

        #endregion

        #region internal

        internal override void NormalizeName()
        {
            _nameServer = _nameServer.ToLowerInvariant();
        }

        internal static async Task<DnsNSRecordData> FromZoneFileEntryAsync(ZoneFile zoneFile)
        {
            Stream rdata = await zoneFile.GetRData();
            if (rdata is not null)
                return new DnsNSRecordData(rdata);

            return new DnsNSRecordData(await zoneFile.PopDomainAsync());
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            return DnsResourceRecord.GetRelativeDomainName(_nameServer, originDomain);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsNSRecordData other)
                return _nameServer.Equals(other._nameServer, StringComparison.OrdinalIgnoreCase);

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_nameServer);
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("NameServer", _nameServer);

            if (DnsClient.TryConvertDomainNameToUnicode(_nameServer, out string nameServerIDN))
                jsonWriter.WriteString("NameServerIDN", nameServerIDN);

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public string NameServer
        { get { return _nameServer; } }

        public NameServerMetadata Metadata
        {
            get
            {
                if (_metadata is null)
                    _metadata = new NameServerMetadata();

                return _metadata;
            }
        }

        public override int UncompressedLength
        { get { return DnsDatagram.GetSerializeDomainNameLength(_nameServer); } }

        #endregion
    }
}
