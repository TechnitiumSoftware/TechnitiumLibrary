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
using System.Net;
using System.Net.Sockets;

namespace TechnitiumLibrary.Net.Dns
{
    public class DnsQuestionRecord
    {
        #region variables

        string _name;
        DnsResourceRecordType _type;
        DnsClass _class;

        #endregion

        #region constructor

        public DnsQuestionRecord(string name, DnsResourceRecordType type, DnsClass @class)
        {
            DnsClient.IsDomainNameValid(name, true);

            _type = type;
            _class = @class;

            if (_type == DnsResourceRecordType.PTR)
                throw new DnsClientException("Invalid type selected for question record.");
            else
                _name = name;
        }

        public DnsQuestionRecord(IPAddress ip, DnsClass @class)
        {
            _type = DnsResourceRecordType.PTR;
            _class = @class;

            byte[] ipBytes = ip.GetAddressBytes();

            switch (ip.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    for (int i = ipBytes.Length - 1; i >= 0; i--)
                        _name += ipBytes[i] + ".";

                    _name += "in-addr.arpa";
                    break;

                case AddressFamily.InterNetworkV6:
                    for (int i = ipBytes.Length - 1; i >= 0; i--)
                        _name += (ipBytes[i] & 0x0F).ToString("X") + "." + (ipBytes[i] >> 4).ToString("X") + ".";

                    _name += "ip6.arpa";
                    break;

                default:
                    throw new DnsClientException("IP address family not supported for PTR query.");
            }
        }

        public DnsQuestionRecord(Stream s)
        {
            _name = DnsDatagram.DeserializeDomainName(s);
            _type = (DnsResourceRecordType)DnsDatagram.ReadUInt16NetworkOrder(s);
            _class = (DnsClass)DnsDatagram.ReadUInt16NetworkOrder(s);
        }

        public DnsQuestionRecord(dynamic jsonQuestionRecord)
        {
            _name = (jsonQuestionRecord.name.Value as string).TrimEnd('.');
            _type = (DnsResourceRecordType)jsonQuestionRecord.type;
            _class = DnsClass.IN;
        }

        #endregion

        #region public

        public void WriteTo(Stream s, List<DnsDomainOffset> domainEntries)
        {
            DnsDatagram.SerializeDomainName(_name, s, domainEntries);
            DnsDatagram.WriteUInt16NetworkOrder((ushort)_type, s);
            DnsDatagram.WriteUInt16NetworkOrder((ushort)_class, s);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj))
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            DnsQuestionRecord other = obj as DnsQuestionRecord;
            if (other == null)
                return false;

            if (!_name.Equals(other._name, StringComparison.OrdinalIgnoreCase))
                return false;

            if (_type != other._type)
                return false;

            if (_class != other._class)
                return false;

            return true;
        }

        public override int GetHashCode()
        {
            return _name.GetHashCode();
        }

        #endregion

        #region properties

        public string Name
        { get { return _name; } }

        public DnsResourceRecordType Type
        { get { return _type; } }

        public DnsClass Class
        { get { return _class; } }

        #endregion
    }
}
