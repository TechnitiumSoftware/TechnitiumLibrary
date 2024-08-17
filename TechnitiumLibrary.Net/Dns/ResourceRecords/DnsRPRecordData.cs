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
    //https://www.rfc-editor.org/rfc/rfc1183.html

    public class DnsRPRecordData : DnsResourceRecordData
    {
        #region variables

        string _mailbox;
        string _txtDomain;

        #endregion

        #region constructor

        public DnsRPRecordData(string mailbox = "", string txtDomain = "")
        {
            if (DnsClient.IsDomainNameUnicode(txtDomain))
                txtDomain = DnsClient.ConvertDomainNameToAscii(txtDomain);

            DnsClient.IsDomainNameValid(txtDomain, true);

            _mailbox = DnsSOARecordData.GetResponsiblePersonEmailFormat(mailbox);
            _txtDomain = txtDomain;
        }

        public DnsRPRecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _mailbox = DnsDatagram.DeserializeDomainName(s, isEmailAddress: true);
            _txtDomain = DnsDatagram.DeserializeDomainName(s);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            DnsDatagram.SerializeDomainName(canonicalForm ? _mailbox.ToLowerInvariant() : _mailbox, s, isEmailAddress: true);
            DnsDatagram.SerializeDomainName(canonicalForm ? _txtDomain.ToLowerInvariant() : _txtDomain, s);
        }

        #endregion

        #region internal

        internal static async Task<DnsRPRecordData> FromZoneFileEntryAsync(ZoneFile zoneFile)
        {
            Stream rdata = await zoneFile.GetRData();
            if (rdata is not null)
                return new DnsRPRecordData(rdata);

            string mailbox = await zoneFile.PopDomainAsync();
            string txtDomain = await zoneFile.PopDomainAsync();

            return new DnsRPRecordData(mailbox, txtDomain);
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            return DnsResourceRecord.GetRelativeDomainName(DnsSOARecordData.GetResponsiblePersonDomainFormat(_mailbox), originDomain) + " " + DnsResourceRecord.GetRelativeDomainName(_txtDomain, originDomain);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsRPRecordData other)
            {
                if (!_mailbox.Equals(other._mailbox, StringComparison.OrdinalIgnoreCase))
                    return false;

                if (!_txtDomain.Equals(other._txtDomain, StringComparison.OrdinalIgnoreCase))
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_mailbox, _txtDomain);
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("Mailbox", _mailbox);
            jsonWriter.WriteString("TxtDomain", _txtDomain);

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public string Mailbox
        { get { return _mailbox; } }

        public string TxtDomain
        { get { return _txtDomain; } }

        public override int UncompressedLength
        { get { return DnsDatagram.GetSerializeDomainNameLength(_mailbox) + DnsDatagram.GetSerializeDomainNameLength(_txtDomain); } }

        #endregion
    }
}
