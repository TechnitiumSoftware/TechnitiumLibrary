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

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsMXRecordData : DnsResourceRecordData, IComparable<DnsMXRecordData>
    {
        #region variables

        ushort _preference;
        string _exchange;

        #endregion

        #region constructor

        public DnsMXRecordData(ushort preference, string exchange)
        {
            DnsClient.IsDomainNameValid(exchange, true);

            _preference = preference;
            _exchange = exchange;
        }

        public DnsMXRecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _preference = DnsDatagram.ReadUInt16NetworkOrder(s);
            _exchange = DnsDatagram.DeserializeDomainName(s);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            DnsDatagram.WriteUInt16NetworkOrder(_preference, s);
            DnsDatagram.SerializeDomainName(canonicalForm ? _exchange.ToLowerInvariant() : _exchange, s, domainEntries);
        }

        #endregion

        #region internal

        internal override void NormalizeName()
        {
            _exchange = _exchange.ToLowerInvariant();
        }

        #endregion

        #region public

        public int CompareTo(DnsMXRecordData other)
        {
            return _preference.CompareTo(other._preference);
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsMXRecordData other)
            {
                if (_preference != other._preference)
                    return false;

                return _exchange.Equals(other._exchange, StringComparison.OrdinalIgnoreCase);
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_preference, _exchange);
        }

        public override string ToString()
        {
            return _preference + " " + _exchange.ToLowerInvariant() + ".";
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteNumber("Preference", _preference);
            jsonWriter.WriteString("Exchange", _exchange);

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public ushort Preference
        { get { return _preference; } }

        public string Exchange
        { get { return _exchange; } }

        public override ushort UncompressedLength
        { get { return Convert.ToUInt16(2 + DnsDatagram.GetSerializeDomainNameLength(_exchange)); } }

        #endregion
    }
}
