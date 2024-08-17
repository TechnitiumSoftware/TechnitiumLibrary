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
using System.Net.Mail;
using System.Text.Json;
using System.Threading.Tasks;

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
            if (DnsClient.IsDomainNameUnicode(primaryNameServer))
                primaryNameServer = DnsClient.ConvertDomainNameToAscii(primaryNameServer);

            DnsClient.IsDomainNameValid(primaryNameServer, true);

            _primaryNameServer = primaryNameServer;
            _responsiblePerson = GetResponsiblePersonEmailFormat(responsiblePerson);
            _serial = serial;
            _refresh = refresh;
            _retry = retry;
            _expire = expire;
            _minimum = minimum;
        }

        public DnsSOARecordData(Stream s)
            : base(s)
        { }

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
            DnsDatagram.SerializeDomainName(canonicalForm ? _primaryNameServer.ToLowerInvariant() : _primaryNameServer, s, domainEntries);
            DnsDatagram.SerializeDomainName(canonicalForm ? _responsiblePerson.ToLowerInvariant() : _responsiblePerson, s, domainEntries, true);
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
            _primaryNameServer = _primaryNameServer.ToLowerInvariant();
            _responsiblePerson = _responsiblePerson.ToLowerInvariant();
        }

        internal static async Task<DnsSOARecordData> FromZoneFileEntryAsync(ZoneFile zoneFile)
        {
            Stream rdata = await zoneFile.GetRData();
            if (rdata is not null)
                return new DnsSOARecordData(rdata);

            string primaryNameServer = await zoneFile.PopDomainAsync();
            string responsiblePerson = await zoneFile.PopDomainAsync();
            uint serial = uint.Parse(await zoneFile.PopItemAsync());
            uint refresh = uint.Parse(await zoneFile.PopItemAsync());
            uint retry = uint.Parse(await zoneFile.PopItemAsync());
            uint expire = uint.Parse(await zoneFile.PopItemAsync());
            uint minimum = uint.Parse(await zoneFile.PopItemAsync());

            return new DnsSOARecordData(primaryNameServer, responsiblePerson, serial, refresh, retry, expire, minimum);
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            return DnsResourceRecord.GetRelativeDomainName(_primaryNameServer, originDomain) + " " + DnsResourceRecord.GetRelativeDomainName(GetResponsiblePersonDomainFormat(_responsiblePerson), originDomain) + " " + _serial + " " + _refresh + " " + _retry + " " + _expire + " " + _minimum;
        }

        internal static string GetResponsiblePersonEmailFormat(string responsiblePerson)
        {
            if (responsiblePerson.Length == 0)
                return responsiblePerson;

            if (responsiblePerson.Contains('@'))
            {
                //validate email address
                MailAddress mailAddress = new MailAddress(responsiblePerson);

                string host = mailAddress.Host;
                if (DnsClient.IsDomainNameUnicode(host))
                    host = DnsClient.ConvertDomainNameToAscii(host);

                DnsClient.IsDomainNameValid(host, true);
            }
            else
            {
                //validate domain name
                if (DnsClient.IsDomainNameUnicode(responsiblePerson))
                    responsiblePerson = DnsClient.ConvertDomainNameToAscii(responsiblePerson);

                DnsClient.IsDomainNameValid(responsiblePerson.Replace("\\.", "."), true);

                //convert to email address
                int i = 0;

                while (true)
                {
                    i = responsiblePerson.IndexOf('.', i);
                    if (i < 1)
                        break;

                    if ((i > 0) && (responsiblePerson[i - 1] == '\\'))
                    {
                        i++;

                        if (i < responsiblePerson.Length)
                            continue;

                        i = -1; //not found
                    }

                    break;
                }

                if (i > 0)
                    responsiblePerson = responsiblePerson.Substring(0, i).Replace("\\.", ".") + "@" + responsiblePerson.Substring(i + 1);
            }

            return responsiblePerson;
        }

        internal static string GetResponsiblePersonDomainFormat(string responsiblePerson)
        {
            int i = responsiblePerson.IndexOf('@');
            if (i < 0)
                return responsiblePerson;

            return responsiblePerson.Substring(0, i).Replace(".", "\\.") + "." + responsiblePerson.Substring(i + 1);
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
            return HashCode.Combine(_primaryNameServer, _responsiblePerson, _serial, _refresh, _retry, _expire, _minimum);
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("PrimaryNameServer", _primaryNameServer);

            if (DnsClient.TryConvertDomainNameToUnicode(_primaryNameServer, out string primaryNameServerIDN))
                jsonWriter.WriteString("PrimaryNameServerIDN", primaryNameServerIDN);

            jsonWriter.WriteString("ResponsiblePerson", _responsiblePerson);
            jsonWriter.WriteNumber("Serial", _serial);
            jsonWriter.WriteNumber("Refresh", _refresh);
            jsonWriter.WriteNumber("Retry", _retry);
            jsonWriter.WriteNumber("Expire", _expire);
            jsonWriter.WriteNumber("Minimum", _minimum);

            jsonWriter.WriteEndObject();
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

        public override int UncompressedLength
        { get { return DnsDatagram.GetSerializeDomainNameLength(_primaryNameServer) + DnsDatagram.GetSerializeDomainNameLength(_responsiblePerson) + 4 + 4 + 4 + 4 + 4; } }

        #endregion
    }
}
