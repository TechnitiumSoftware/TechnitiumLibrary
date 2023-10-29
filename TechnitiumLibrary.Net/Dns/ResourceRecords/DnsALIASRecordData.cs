/*
Technitium Library
Copyright (C) 2023  Shreyas Zare (shreyas@technitium.com)

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

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsALIASRecordData : DnsANAMERecordData
    {
        #region variables

        DnsResourceRecordType _type; //alias for record type

        #endregion

        #region constructor

        public DnsALIASRecordData(DnsResourceRecordType type, string domain)
            : base(domain)
        {
            _type = type;
        }

        public DnsALIASRecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _type = (DnsResourceRecordType)DnsDatagram.ReadUInt16NetworkOrder(s);
            base.ReadRecordData(s); //read domain from base
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            DnsDatagram.WriteUInt16NetworkOrder((ushort)_type, s);
            base.WriteRecordData(s, domainEntries, canonicalForm); //write domain from base
        }

        #endregion

        #region internal

        internal new static async Task<DnsANAMERecordData> FromZoneFileEntryAsync(ZoneFile zoneFile)
        {
            Stream rdata = await zoneFile.GetRData();
            if (rdata is not null)
                return new DnsALIASRecordData(rdata);

            DnsResourceRecordType type = (DnsResourceRecordType)ushort.Parse(await zoneFile.PopItemAsync());
            string domain = await zoneFile.PopDomainAsync();

            return new DnsALIASRecordData(type, domain);
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            return (ushort)_type + " " + base.ToZoneFileEntry(originDomain);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsALIASRecordData other)
            {
                if (_type != other._type)
                    return false;

                return Domain.Equals(other.Domain, StringComparison.OrdinalIgnoreCase);
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_type, Domain);
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("Type", _type.ToString());
            jsonWriter.WriteString("Domain", Domain);

            if (DnsClient.TryConvertDomainNameToUnicode(Domain, out string domainIDN))
                jsonWriter.WriteString("DomainIDN", domainIDN);

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public DnsResourceRecordType Type
        { get { return _type; } }

        public override int UncompressedLength
        { get { return 2 + base.UncompressedLength; } }

        #endregion
    }
}
