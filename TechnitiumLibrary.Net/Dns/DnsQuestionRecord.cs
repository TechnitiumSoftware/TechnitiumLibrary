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
using System.Net;
using System.Net.Sockets;
using System.Runtime.Serialization;

namespace TechnitiumLibrary.Net.Dns
{
    //DNS Query Name Minimisation to Improve Privacy
    //https://tools.ietf.org/html/draft-ietf-dnsop-rfc7816bis-04

    public class DnsQuestionRecord
    {
        #region variables

        readonly string _name;
        readonly DnsResourceRecordType _type;
        readonly DnsClass _class;

        //QNAME Minimization
        const int MAX_MINIMISE_COUNT = 10;
        string _zoneCut;
        string _minimizedName;

        #endregion

        #region constructor

        public DnsQuestionRecord(string name, DnsResourceRecordType type, DnsClass @class)
        {
            DnsClient.IsDomainNameValid(name, true);

            _name = name;
            _type = type;
            _class = @class;
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

        #region private

        private static string GetMinimizedName(string name, string zoneCut)
        {
            //www.example.com
            //com

            if ((zoneCut != null) && (zoneCut.Length < name.Length))
            {
                int i = name.LastIndexOf('.', name.Length - zoneCut.Length - 2);
                if (i < 0)
                    return name;

                //return minimized QNAME
                return name.Substring(i + 1);
            }

            return null;
        }

        #endregion

        #region public

        public void WriteTo(Stream s, List<DnsDomainOffset> domainEntries)
        {
            if (_minimizedName == null)
            {
                DnsDatagram.SerializeDomainName(_name, s, domainEntries);
                DnsDatagram.WriteUInt16NetworkOrder((ushort)_type, s);
                DnsDatagram.WriteUInt16NetworkOrder((ushort)_class, s);
            }
            else
            {
                DnsResourceRecordType type;

                switch (_type)
                {
                    case DnsResourceRecordType.AAAA:
                        type = DnsResourceRecordType.AAAA;
                        break;

                    default:
                        type = DnsResourceRecordType.A;
                        break;
                }

                DnsDatagram.SerializeDomainName(_minimizedName, s, domainEntries);
                DnsDatagram.WriteUInt16NetworkOrder((ushort)type, s);
                DnsDatagram.WriteUInt16NetworkOrder((ushort)_class, s);
            }
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
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

        [IgnoreDataMember]
        public string ZoneCut
        {
            get { return _zoneCut; }
            set
            {
                _zoneCut = value;
                _minimizedName = GetMinimizedName(_name, _zoneCut);
                if ((_minimizedName == null) || (_minimizedName.Split('.').Length > MAX_MINIMISE_COUNT))
                {
                    //auto disable QNAME minimization
                    _zoneCut = null;
                    _minimizedName = null;
                }
            }
        }

        [IgnoreDataMember]
        public string MinimizedName
        { get { return _minimizedName; } }

        #endregion
    }
}
