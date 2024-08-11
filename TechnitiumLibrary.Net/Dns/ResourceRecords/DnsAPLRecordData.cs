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
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public enum IanaAddressFamily : ushort
    {
        Unknown = 0,
        IPv4 = 1,
        IPv6 = 2
    }

    //A DNS RR Type for Lists of Address Prefixes (APL RR)
    //https://datatracker.ietf.org/doc/rfc3123/

    public class DnsAPLRecordData : DnsResourceRecordData
    {
        #region variables

        IReadOnlyList<APItem> _apItems;

        #endregion

        #region constructor

        public DnsAPLRecordData(IReadOnlyList<APItem> apItems)
        {
            _apItems = apItems;
        }

        public DnsAPLRecordData(NetworkAddress networkAddress, bool negation)
        {
            _apItems = [new APItem(networkAddress, negation)];
        }

        public DnsAPLRecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            long initialPosition = s.Position;
            long bytesRead = 0;

            List<APItem> apItems = new List<APItem>();

            while (bytesRead < _rdLength)
            {
                apItems.Add(new APItem(s));

                bytesRead = s.Position - initialPosition;
            }

            _apItems = apItems;
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            foreach (APItem item in _apItems)
                item.WriteTo(s);
        }

        #endregion

        #region internal

        internal static async Task<DnsAPLRecordData> FromZoneFileEntryAsync(ZoneFile zoneFile)
        {
            Stream rdata = await zoneFile.GetRData();
            if (rdata is not null)
                return new DnsAPLRecordData(rdata);

            List<APItem> apItems = new List<APItem>();

            while (true)
            {
                APItem apItem = await APItem.FromZoneFileEntryAsync(zoneFile);
                if (apItem is null)
                    break;

                apItems.Add(apItem);
            }

            return new DnsAPLRecordData(apItems);
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            string value = null;

            foreach (APItem item in _apItems)
            {
                if (value is null)
                    value = item.ToZoneFileEntry();
                else
                    value += " " + item.ToZoneFileEntry();
            }

            return value;
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsAPLRecordData other)
                return _apItems.ListEquals(other._apItems);

            return false;
        }

        public override int GetHashCode()
        {
            return _apItems.GetArrayHashCode();
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartArray();

            foreach (APItem item in _apItems)
                item.SerializeTo(jsonWriter);

            jsonWriter.WriteEndArray();
        }

        #endregion

        #region properties

        public IReadOnlyCollection<APItem> APItems
        { get { return _apItems; } }

        public override int UncompressedLength
        {
            get
            {
                int count = 0;

                foreach (APItem item in APItems)
                    count += item.UncompressedLength;

                return count;
            }
        }

        #endregion

        public class APItem
        {
            #region variables

            readonly IanaAddressFamily _addressFamily;
            readonly byte _prefix;
            readonly bool _n;
            readonly byte[] _afdPart;

            readonly NetworkAddress _networkAddress;

            #endregion

            #region constructor

            public APItem(NetworkAddress networkAddress, bool negation)
            {
                switch (networkAddress.AddressFamily)
                {
                    case System.Net.Sockets.AddressFamily.InterNetwork:
                        _addressFamily = IanaAddressFamily.IPv4;
                        break;

                    case System.Net.Sockets.AddressFamily.InterNetworkV6:
                        _addressFamily = IanaAddressFamily.IPv6;
                        break;

                    default:
                        throw new NotSupportedException("Address Family not supported.");
                }

                _prefix = networkAddress.PrefixLength;
                _n = negation;

                Span<byte> buffer = stackalloc byte[16];
                if (!networkAddress.Address.TryWriteBytes(buffer, out int bytesWritten))
                    throw new InvalidOperationException();

                for (int i = bytesWritten - 1; i > -1; i--)
                {
                    if (_afdPart is null)
                    {
                        if (buffer[i] == 0)
                            continue;

                        _afdPart = new byte[i + 1];
                    }

                    _afdPart[i] = buffer[i];
                }

                if (_afdPart is null)
                    _afdPart = [];

                _networkAddress = networkAddress;
            }

            public APItem(Stream s)
            {
                _addressFamily = (IanaAddressFamily)DnsDatagram.ReadUInt16NetworkOrder(s);
                _prefix = s.ReadByteValue();

                byte b = s.ReadByteValue();
                _n = (b & 0x80) > 0;

                int afdLength = b & 0x7F;
                _afdPart = s.ReadExactly(afdLength);

                switch (_addressFamily)
                {
                    case IanaAddressFamily.IPv4:
                        {
                            Span<byte> buffer = stackalloc byte[4];
                            _afdPart.CopyTo(buffer);
                            _networkAddress = new NetworkAddress(new IPAddress(buffer), _prefix);
                        }
                        break;

                    case IanaAddressFamily.IPv6:
                        {
                            Span<byte> buffer = stackalloc byte[16];
                            _afdPart.CopyTo(buffer);
                            _networkAddress = new NetworkAddress(new IPAddress(buffer), _prefix);
                        }
                        break;
                }
            }

            #endregion

            #region internal

            internal static async Task<APItem> FromZoneFileEntryAsync(ZoneFile zoneFile)
            {
                string apItem = await zoneFile.PopItemAsync();
                if (apItem is null)
                    return null;

                string[] parts = apItem.Split(':', 2);
                if (parts.Length != 2)
                    throw new FormatException("Failed to parse APL record data for AP Item: " + apItem);

                bool n = parts[0].StartsWith('!');
                IanaAddressFamily addressFamily = (IanaAddressFamily)ushort.Parse(parts[0].TrimStart('!'));

                if (!NetworkAddress.TryParse(parts[1], out NetworkAddress networkAddress))
                    throw new FormatException("Failed to parse APL record data for AP Item: " + apItem);

                switch (networkAddress.AddressFamily)
                {
                    case System.Net.Sockets.AddressFamily.InterNetwork:
                        if (addressFamily != IanaAddressFamily.IPv4)
                            throw new FormatException("Failed to parse APL record data for AP Item: " + apItem);

                        break;

                    case System.Net.Sockets.AddressFamily.InterNetworkV6:
                        if (addressFamily != IanaAddressFamily.IPv6)
                            throw new FormatException("Failed to parse APL record data for AP Item: " + apItem);

                        break;
                }

                return new APItem(networkAddress, n);
            }

            internal string ToZoneFileEntry()
            {
                return (_n ? "!" : "") + (ushort)_addressFamily + ":" + _networkAddress.ToString() + (_networkAddress.IsHostAddress ? "/" + _networkAddress.PrefixLength : "");
            }

            #endregion

            #region public

            public void WriteTo(Stream s)
            {
                DnsDatagram.WriteUInt16NetworkOrder((ushort)_addressFamily, s);
                s.WriteByte(_prefix);
                s.WriteByte((byte)((_n ? 0x80 : 0) | _afdPart.Length));
                s.Write(_afdPart);
            }

            public override bool Equals(object obj)
            {
                if (obj is null)
                    return false;

                if (ReferenceEquals(this, obj))
                    return true;

                if (obj is APItem other)
                {
                    if (_addressFamily != other._addressFamily)
                        return false;

                    if (_prefix != other._prefix)
                        return false;

                    if (_n != other._n)
                        return false;

                    if (!_afdPart.ListEquals(other._afdPart))
                        return false;

                    return true;
                }

                return false;
            }

            public override int GetHashCode()
            {
                return HashCode.Combine(_addressFamily, _prefix, _n, _afdPart.GetArrayHashCode());
            }

            public override string ToString()
            {
                return ToZoneFileEntry();
            }

            public void SerializeTo(Utf8JsonWriter jsonWriter)
            {
                jsonWriter.WriteStartObject();

                jsonWriter.WriteString("AddressFamily", _addressFamily.ToString());
                jsonWriter.WriteNumber("Prefix", _prefix);
                jsonWriter.WriteBoolean("Negation", _n);
                jsonWriter.WriteString("AFDPart", _networkAddress.Address.ToString());

                jsonWriter.WriteEndObject();
            }

            #endregion

            #region properties

            public IanaAddressFamily AddressFamily
            { get { return _addressFamily; } }

            public byte Prefix
            { get { return _prefix; } }

            public bool Negation
            { get { return _n; } }

            public byte[] AFDPart
            { get { return _afdPart; } }

            public NetworkAddress NetworkAddress
            { get { return _networkAddress; } }

            public int UncompressedLength
            { get { return 2 + 1 + 1 + _afdPart.Length; } }

            #endregion
        }
    }
}
