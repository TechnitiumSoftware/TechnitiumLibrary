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
using System.Runtime.Serialization;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsSOARecordData : DnsResourceRecordData
    {
        #region variables

        string _primaryNameServer;
        string _responsiblePerson;
        uint _serial;
        uint _refresh;
        uint _retry;
        uint _expire;
        uint _minimum;

        #endregion

        #region constructor

        public DnsSOARecordData(string primaryNameServer, string responsiblePerson, uint serial, uint refresh, uint retry, uint expire, uint minimum)
        {
            DnsClient.IsDomainNameValid(primaryNameServer, true);

            if (!responsiblePerson.Contains('@'))
            {
                int i = responsiblePerson.IndexOf('.');
                if (i < 1)
                    throw new ArgumentException("Please enter a valid email address.", nameof(responsiblePerson));

                responsiblePerson = responsiblePerson.Substring(0, i) + "@" + responsiblePerson.Substring(i + 1);
            }

            _primaryNameServer = primaryNameServer;
            _responsiblePerson = responsiblePerson;
            _serial = serial;
            _refresh = refresh;
            _retry = retry;
            _expire = expire;
            _minimum = minimum;
        }

        public DnsSOARecordData(Stream s)
            : base(s)
        { }

        public DnsSOARecordData(dynamic jsonResourceRecord)
        {
            _rdLength = Convert.ToUInt16(jsonResourceRecord.data.Value.Length);

            string[] parts = (jsonResourceRecord.data.Value as string).Split(' ');

            _primaryNameServer = parts[0].TrimEnd('.');
            _responsiblePerson = parts[1].TrimEnd('.');
            _serial = uint.Parse(parts[2]);
            _refresh = uint.Parse(parts[3]);
            _retry = uint.Parse(parts[4]);
            _expire = uint.Parse(parts[5]);
            _minimum = uint.Parse(parts[6]);

            int i = _responsiblePerson.LastIndexOf("\\.");
            if (i < 0)
                i = _responsiblePerson.IndexOf('.');
            else
                i = _responsiblePerson.IndexOf('.', i + 2);

            if (i > -1)
                _responsiblePerson = _responsiblePerson.Substring(0, i).Replace("\\.", ".") + "@" + _responsiblePerson.Substring(i + 1);
        }

        #endregion

        #region static

        public static bool IsZoneUpdateAvailable(uint currentSerial, uint newSerial)
        {
            //compare using sequence space arithmetic
            //(i1 < i2 and i2 - i1 > 2^(SERIAL_BITS - 1)) or
            //(i1 > i2 and i1 -i2 < 2^(SERIAL_BITS - 1))

            return ((newSerial < currentSerial) && ((currentSerial - newSerial) > (uint.MaxValue >> 1))) || ((newSerial > currentSerial) && ((newSerial - currentSerial) < (uint.MaxValue >> 1)));
        }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _primaryNameServer = DnsDatagram.DeserializeDomainName(s);
            _responsiblePerson = DnsDatagram.DeserializeDomainName(s, 10, false, true);
            _serial = DnsDatagram.ReadUInt32NetworkOrder(s);
            _refresh = DnsDatagram.ReadUInt32NetworkOrder(s);
            _retry = DnsDatagram.ReadUInt32NetworkOrder(s);
            _expire = DnsDatagram.ReadUInt32NetworkOrder(s);
            _minimum = DnsDatagram.ReadUInt32NetworkOrder(s);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            DnsDatagram.SerializeDomainName(canonicalForm ? _primaryNameServer.ToLower() : _primaryNameServer, s, domainEntries);
            DnsDatagram.SerializeDomainName(canonicalForm ? _responsiblePerson.ToLower() : _responsiblePerson, s, domainEntries, true);
            DnsDatagram.WriteUInt32NetworkOrder(_serial, s);
            DnsDatagram.WriteUInt32NetworkOrder(_refresh, s);
            DnsDatagram.WriteUInt32NetworkOrder(_retry, s);
            DnsDatagram.WriteUInt32NetworkOrder(_expire, s);
            DnsDatagram.WriteUInt32NetworkOrder(_minimum, s);
        }

        #endregion

        #region internal

        internal override void NormalizeName()
        {
            _primaryNameServer = _primaryNameServer.ToLower();
            _responsiblePerson = _responsiblePerson.ToLower();
        }

        #endregion

        #region public

        public bool IsZoneUpdateAvailable(DnsSOARecordData newRecord)
        {
            return IsZoneUpdateAvailable(_serial, newRecord._serial);
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsSOARecordData other)
            {
                if (!_primaryNameServer.Equals(other._primaryNameServer, StringComparison.OrdinalIgnoreCase))
                    return false;

                if (!_responsiblePerson.Equals(other._responsiblePerson, StringComparison.OrdinalIgnoreCase))
                    return false;

                if (_serial != other._serial)
                    return false;

                if (_refresh != other._refresh)
                    return false;

                if (_retry != other._retry)
                    return false;

                if (_expire != other._expire)
                    return false;

                if (_minimum != other._minimum)
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return _primaryNameServer.GetHashCode();
        }

        public override string ToString()
        {
            string responsiblePerson = _responsiblePerson;

            int i = responsiblePerson.IndexOf('@');
            if (i > -1)
                responsiblePerson = responsiblePerson.Substring(0, i).Replace(".", "\\.") + "." + responsiblePerson.Substring(i + 1);

            return _primaryNameServer.ToLower() + ". " + responsiblePerson.ToLower() + ". " + _serial + " " + _refresh + " " + _retry + " " + _expire + " " + _minimum;
        }

        #endregion

        #region properties

        public string PrimaryNameServer
        { get { return _primaryNameServer; } }

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

        [IgnoreDataMember]
        public override ushort UncompressedLength
        { get { return Convert.ToUInt16(DnsDatagram.GetSerializeDomainNameLength(_primaryNameServer) + DnsDatagram.GetSerializeDomainNameLength(_responsiblePerson) + 4 + 4 + 4 + 4 + 4); } }

        #endregion
    }
}
