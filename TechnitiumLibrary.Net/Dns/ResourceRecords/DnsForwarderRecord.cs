/*
Technitium Library
Copyright (C) 2020  Shreyas Zare (shreyas@technitium.com)

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
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsForwarderRecord : DnsResourceRecordData
    {
        #region variables

        DnsTransportProtocol _protocol;
        string _forwarder;

        NameServerAddress _nameServer;

        #endregion

        #region constructor

        public DnsForwarderRecord(DnsTransportProtocol protocol, string forwarder)
        {
            _protocol = protocol;
            _forwarder = forwarder;

            _nameServer = new NameServerAddress(_forwarder, _protocol);
        }

        public DnsForwarderRecord(Stream s)
            : base(s)
        { }

        public DnsForwarderRecord(dynamic jsonResourceRecord)
        {
            throw new NotSupportedException();
        }

        #endregion

        #region protected

        protected override void Parse(Stream s)
        {
            int b = s.ReadByte();
            if (b < 0)
                throw new EndOfStreamException();

            _protocol = (DnsTransportProtocol)b;

            b = s.ReadByte();
            if (b < 0)
                throw new EndOfStreamException();

            _forwarder = Encoding.ASCII.GetString(s.ReadBytes(b));

            _nameServer = new NameServerAddress(_forwarder, _protocol);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
        {
            s.WriteByte((byte)_protocol);

            s.WriteByte(Convert.ToByte(_forwarder.Length));
            s.Write(Encoding.ASCII.GetBytes(_forwarder));
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            DnsForwarderRecord other = obj as DnsForwarderRecord;
            if (other == null)
                return false;

            if (_protocol != other._protocol)
                return false;

            return _forwarder.Equals(other._forwarder, StringComparison.OrdinalIgnoreCase);
        }

        public override int GetHashCode()
        {
            return _protocol.GetHashCode() ^ _forwarder.GetHashCode();
        }

        public override string ToString()
        {
            return _protocol.ToString() + " " + _forwarder;
        }

        #endregion

        #region properties

        public DnsTransportProtocol Protocol
        { get { return _protocol; } }

        public string Forwarder
        { get { return _forwarder; } }

        public NameServerAddress NameServer
        { get { return _nameServer; } }

        #endregion
    }
}
