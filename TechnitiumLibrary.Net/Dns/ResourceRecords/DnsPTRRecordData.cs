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
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsPTRRecordData : DnsResourceRecordData
    {
        #region variables

        string _domain;

        #endregion

        #region constructor

        public DnsPTRRecordData(string domain)
        {
            DnsClient.IsDomainNameValid(domain, true);

            _domain = domain;
        }

        public DnsPTRRecordData(Stream s)
            : base(s)
        { }

        public DnsPTRRecordData(JsonElement jsonResourceRecord)
        {
            string rdata = jsonResourceRecord.GetProperty("data").GetString();

            _rdLength = Convert.ToUInt16(rdata.Length);
            _domain = rdata.TrimEnd('.');
        }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _domain = DnsDatagram.DeserializeDomainName(s);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            DnsDatagram.SerializeDomainName(canonicalForm ? _domain.ToLowerInvariant() : _domain, s, domainEntries);
        }

        #endregion

        #region internal

        internal override void NormalizeName()
        {
            _domain = _domain.ToLowerInvariant();
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsPTRRecordData other)
                return _domain.Equals(other._domain, StringComparison.OrdinalIgnoreCase);

            return false;
        }

        public override int GetHashCode()
        {
            return _domain.GetHashCode();
        }

        public override string ToString()
        {
            return _domain.ToLowerInvariant() + ".";
        }

        #endregion

        #region properties

        public string Domain
        { get { return _domain; } }

        [JsonIgnore]
        public override ushort UncompressedLength
        { get { return Convert.ToUInt16(DnsDatagram.GetSerializeDomainNameLength(_domain)); } }

        #endregion
    }
}
