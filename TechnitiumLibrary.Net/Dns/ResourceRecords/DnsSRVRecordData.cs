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
    public class DnsSRVRecordData : DnsResourceRecordData
    {
        #region variables

        ushort _priority;
        ushort _weight;
        ushort _port;
        string _target;

        #endregion

        #region constructor

        public DnsSRVRecordData(ushort priority, ushort weight, ushort port, string target)
        {
            DnsClient.IsDomainNameValid(target, true);

            _priority = priority;
            _weight = weight;
            _port = port;
            _target = target;
        }

        public DnsSRVRecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _priority = DnsDatagram.ReadUInt16NetworkOrder(s);
            _weight = DnsDatagram.ReadUInt16NetworkOrder(s);
            _port = DnsDatagram.ReadUInt16NetworkOrder(s);
            _target = DnsDatagram.DeserializeDomainName(s);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            DnsDatagram.WriteUInt16NetworkOrder(_priority, s);
            DnsDatagram.WriteUInt16NetworkOrder(_weight, s);
            DnsDatagram.WriteUInt16NetworkOrder(_port, s);
            DnsDatagram.SerializeDomainName(canonicalForm ? _target.ToLowerInvariant() : _target, s, null); //no compression for domain name as per RFC
        }

        #endregion

        #region internal

        internal override void NormalizeName()
        {
            _target = _target.ToLowerInvariant();
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsSRVRecordData other)
            {
                if (_priority != other._priority)
                    return false;

                if (_weight != other._weight)
                    return false;

                if (_port != other._port)
                    return false;

                if (!_target.Equals(other._target, StringComparison.OrdinalIgnoreCase))
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_priority, _weight, _port, _target);
        }

        public override string ToString()
        {
            return _priority + " " + _weight + " " + _port + " " + _target.ToLowerInvariant() + ".";
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteNumber("Priority", _priority);
            jsonWriter.WriteNumber("Weight", _weight);
            jsonWriter.WriteNumber("Port", _port);
            jsonWriter.WriteString("Target", _target);

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public ushort Priority
        { get { return _priority; } }

        public ushort Weight
        { get { return _weight; } }

        public ushort Port
        { get { return _port; } }

        public string Target
        { get { return _target; } }

        public override ushort UncompressedLength
        { get { return Convert.ToUInt16(2 + 2 + 2 + DnsDatagram.GetSerializeDomainNameLength(_target)); } }

        #endregion
    }
}
