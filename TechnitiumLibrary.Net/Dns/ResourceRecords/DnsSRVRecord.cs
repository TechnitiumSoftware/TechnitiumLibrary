/*
Technitium Library
Copyright (C) 2019  Shreyas Zare (shreyas@technitium.com)

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

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsSRVRecord : DnsResourceRecordData
    {
        #region variables

        ushort _priority;
        ushort _weight;
        ushort _port;
        string _target;

        #endregion

        #region constructor

        public DnsSRVRecord(ushort priority, ushort weight, ushort port, string target)
        {
            DnsClient.IsDomainNameValid(target, true);

            _priority = priority;
            _weight = weight;
            _port = port;
            _target = target;
        }

        public DnsSRVRecord(Stream s)
            : base(s)
        { }

        public DnsSRVRecord(dynamic jsonResourceRecord)
        {
            _length = Convert.ToUInt16(jsonResourceRecord.data.Value.Length);

            string[] parts = (jsonResourceRecord.data.Value as string).Split(' ');

            _priority = ushort.Parse(parts[0]);
            _weight = ushort.Parse(parts[1]);
            _port = ushort.Parse(parts[2]);
            _target = parts[3].TrimEnd('.');
        }

        #endregion

        #region protected

        protected override void Parse(Stream s)
        {
            _priority = DnsDatagram.ReadUInt16NetworkOrder(s);
            _weight = DnsDatagram.ReadUInt16NetworkOrder(s);
            _port = DnsDatagram.ReadUInt16NetworkOrder(s);
            _target = DnsDatagram.DeserializeDomainName(s);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
        {
            DnsDatagram.WriteUInt16NetworkOrder(_priority, s);
            DnsDatagram.WriteUInt16NetworkOrder(_weight, s);
            DnsDatagram.WriteUInt16NetworkOrder(_port, s);
            DnsDatagram.SerializeDomainName(_target, s, null); //no compression for domain name as per RFC
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            DnsSRVRecord other = obj as DnsSRVRecord;
            if (other == null)
                return false;

            if (_port != other._port)
                return false;

            if (!_target.Equals(other._target, StringComparison.OrdinalIgnoreCase))
                return false;

            return true;
        }

        public override int GetHashCode()
        {
            return _target.GetHashCode();
        }

        public override string ToString()
        {
            return _priority + " " + _weight + " " + _port + " " + _target + ".";
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

        #endregion
    }
}
