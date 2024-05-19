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
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsNAPTRRecordData : DnsResourceRecordData
    {
        #region variables

        ushort _order;
        ushort _preference;
        string _flags;
        string _services;
        string _regexp;
        string _replacement;

        byte[] _rData;

        #endregion

        #region constructor

        public DnsNAPTRRecordData(ushort order, ushort preference, string flags, string services, string regexp, string replacement)
        {
            if (DnsClient.IsDomainNameUnicode(replacement))
                replacement = DnsClient.ConvertDomainNameToAscii(replacement);

            DnsClient.IsDomainNameValid(replacement, true);

            _order = order;
            _preference = preference;
            _flags = flags;
            _services = services;
            _regexp = regexp;
            _replacement = replacement;

            Serialize();
        }

        public DnsNAPTRRecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region private

        private void Serialize()
        {
            using (MemoryStream mS = new MemoryStream(UncompressedLength))
            {
                DnsDatagram.WriteUInt16NetworkOrder(_order, mS);
                DnsDatagram.WriteUInt16NetworkOrder(_preference, mS);
                mS.WriteShortString(_flags, Encoding.ASCII);
                mS.WriteShortString(_services, Encoding.ASCII);
                mS.WriteShortString(_regexp, Encoding.ASCII);
                DnsDatagram.SerializeDomainName(_replacement, mS);

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
                _order = DnsDatagram.ReadUInt16NetworkOrder(mS);
                _preference = DnsDatagram.ReadUInt16NetworkOrder(mS);
                _flags = mS.ReadShortString(Encoding.ASCII);
                _services = mS.ReadShortString(Encoding.ASCII);
                _regexp = mS.ReadShortString(Encoding.ASCII);
                _replacement = DnsDatagram.DeserializeDomainName(mS);
            }
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            s.Write(_rData);
        }

        #endregion

        #region internal

        internal static async Task<DnsNAPTRRecordData> FromZoneFileEntryAsync(ZoneFile zoneFile)
        {
            Stream rdata = await zoneFile.GetRData();
            if (rdata is not null)
                return new DnsNAPTRRecordData(rdata);

            ushort order = ushort.Parse(await zoneFile.PopItemAsync());
            ushort preference = ushort.Parse(await zoneFile.PopItemAsync());
            string flags = DnsDatagram.DecodeCharacterString(await zoneFile.PopItemAsync());
            string services = DnsDatagram.DecodeCharacterString(await zoneFile.PopItemAsync());
            string regexp = DnsDatagram.DecodeCharacterString(await zoneFile.PopItemAsync());
            string replacement = await zoneFile.PopDomainAsync();

            return new DnsNAPTRRecordData(order, preference, flags, services, regexp, replacement);
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            return _order + " " + _preference + " " + DnsDatagram.EncodeCharacterString(_flags) + " " + DnsDatagram.EncodeCharacterString(_services) + " " + DnsDatagram.EncodeCharacterString(_regexp) + " " + DnsResourceRecord.GetRelativeDomainName(_replacement, originDomain).ToLowerInvariant();
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsNAPTRRecordData other)
            {
                if (_order != other._order)
                    return false;

                if (_preference != other._preference)
                    return false;

                if (!_flags.Equals(other._flags, StringComparison.Ordinal))
                    return false;

                if (!_services.Equals(other._services, StringComparison.Ordinal))
                    return false;

                if (!_regexp.Equals(other._regexp, StringComparison.Ordinal))
                    return false;

                if (!_replacement.Equals(other._replacement, StringComparison.Ordinal))
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_order, _preference, _flags, _services, _regexp, _replacement);
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteNumber("Order", _order);
            jsonWriter.WriteNumber("Preference", _preference);
            jsonWriter.WriteString("Flags", _flags);
            jsonWriter.WriteString("Services", _services);
            jsonWriter.WriteString("Regexp", _regexp);
            jsonWriter.WriteString("Replacement", _replacement);

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public ushort Order
        { get { return _order; } }

        public ushort Preference
        { get { return _preference; } }

        public string Flags
        { get { return _flags; } }

        public string Services
        { get { return _services; } }

        public string Regexp
        { get { return _regexp; } }

        public string Replacement
        { get { return _replacement; } }

        public override int UncompressedLength
        { get { return 2 + 2 + 1 + _flags.Length + 1 + _services.Length + 1 + _regexp.Length + DnsDatagram.GetSerializeDomainNameLength(_replacement); } }

        #endregion
    }
}
