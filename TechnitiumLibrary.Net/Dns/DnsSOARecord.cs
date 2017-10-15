/*
Technitium Library
Copyright (C) 2017  Shreyas Zare (shreyas@technitium.com)

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

namespace TechnitiumLibrary.Net.Dns
{
    public class DnsSOARecord : DnsResourceRecordData
    {
        #region variables

        string _masterNameServer;
        string _responsiblePerson;
        uint _serial;
        uint _refresh;
        uint _retry;
        uint _expire;
        uint _minimum;

        #endregion

        #region constructor

        public DnsSOARecord(string masterNameServer, string responsiblePerson, uint serial, uint refresh, uint retry, uint expire, uint minimum)
        {
            _masterNameServer = masterNameServer;
            _responsiblePerson = responsiblePerson;
            _serial = serial;
            _refresh = refresh;
            _retry = retry;
            _expire = expire;
            _minimum = minimum;
        }

        public DnsSOARecord(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void Parse(Stream s)
        {
            _masterNameServer = DnsDatagram.ConvertLabelToDomain(s);
            _responsiblePerson = DnsDatagram.ConvertLabelToDomain(s);
            _serial = DnsDatagram.ReadUInt32NetworkOrder(s);
            _refresh = DnsDatagram.ReadUInt32NetworkOrder(s);
            _retry = DnsDatagram.ReadUInt32NetworkOrder(s);
            _expire = DnsDatagram.ReadUInt32NetworkOrder(s);
            _minimum = DnsDatagram.ReadUInt32NetworkOrder(s);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
        {
            DnsDatagram.ConvertDomainToLabel(_masterNameServer, s, domainEntries);
            DnsDatagram.ConvertDomainToLabel(_responsiblePerson, s, domainEntries);
            DnsDatagram.WriteUInt32NetworkOrder(_serial, s);
            DnsDatagram.WriteUInt32NetworkOrder(_refresh, s);
            DnsDatagram.WriteUInt32NetworkOrder(_retry, s);
            DnsDatagram.WriteUInt32NetworkOrder(_expire, s);
            DnsDatagram.WriteUInt32NetworkOrder(_minimum, s);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj))
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            DnsSOARecord other = obj as DnsSOARecord;
            if (other == null)
                return false;

            if (!this._masterNameServer.Equals(other._masterNameServer, System.StringComparison.CurrentCultureIgnoreCase))
                return false;

            if (!this._responsiblePerson.Equals(other._responsiblePerson, System.StringComparison.CurrentCultureIgnoreCase))
                return false;

            if (this._serial != other._serial)
                return false;

            if (this._refresh != other._refresh)
                return false;

            if (this._retry != other._retry)
                return false;

            if (this._expire != other._expire)
                return false;

            if (this._minimum != other._minimum)
                return false;

            return true;
        }

        public override int GetHashCode()
        {
            return _masterNameServer.GetHashCode();
        }

        #endregion

        #region properties

        public string MasterNameServer
        { get { return _masterNameServer; } }

        public string ResponsiblePerson
        { get { return _responsiblePerson; } }

        public uint Serial
        { get { return _serial; } }

        public uint Refresh
        { get { return _refresh; } }

        public uint Retry
        { get { return _retry; } }

        public uint Expire
        { get { return _expire; } }

        public uint Minimum
        { get { return _minimum; } }

        #endregion
    }
}
