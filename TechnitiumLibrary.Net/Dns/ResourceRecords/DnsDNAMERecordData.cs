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

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsDNAMERecordData : DnsResourceRecordData
    {
        #region variables

        string _domain;

        #endregion

        #region constructor

        public DnsDNAMERecordData(string domain)
        {
            if (DnsClient.IsDomainNameUnicode(domain))
                domain = DnsClient.ConvertDomainNameToAscii(domain);

            DnsClient.IsDomainNameValid(domain, true);

            _domain = domain;
        }

        public DnsDNAMERecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _domain = DnsDatagram.DeserializeDomainName(s);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            DnsDatagram.SerializeDomainName(canonicalForm ? _domain.ToLowerInvariant() : _domain, s);
        }

        #endregion

        #region internal

        internal override void NormalizeName()
        {
            _domain = _domain.ToLowerInvariant();
        }

        internal static async Task<DnsDNAMERecordData> FromZoneFileEntryAsync(ZoneFile zoneFile)
        {
            Stream rdata = await zoneFile.GetRData();
            if (rdata is not null)
                return new DnsDNAMERecordData(rdata);

            return new DnsDNAMERecordData(await zoneFile.PopDomainAsync());
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            return DnsResourceRecord.GetRelativeDomainName(_domain, originDomain).ToLowerInvariant();
        }

        #endregion

        #region public

        public string Substitute(string qname, string owner)
        {
            if (_domain.Length == 0)
                return qname.Substring(0, qname.Length - owner.Length - 1);
            else
                return qname.Substring(0, qname.Length - owner.Length) + _domain;
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsDNAMERecordData other)
                return _domain.Equals(other._domain, StringComparison.OrdinalIgnoreCase);

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_domain);
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("Domain", _domain);

            if (DnsClient.TryConvertDomainNameToUnicode(_domain, out string domainIDN))
                jsonWriter.WriteString("DomainIDN", domainIDN);

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public string Domain
        { get { return _domain; } }

        public override int UncompressedLength
        { get { return DnsDatagram.GetSerializeDomainNameLength(_domain); } }

        #endregion
    }
}
