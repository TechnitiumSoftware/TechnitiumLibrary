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
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public enum DnsForwarderRecordProxyType : byte
    {
        DefaultProxy = 0,
        None = 0,
        Http = 1,
        Socks5 = 2,
        NoProxy = 254
    }

    public class DnsForwarderRecordData : DnsResourceRecordData
    {
        #region variables

        DnsTransportProtocol _protocol;
        string _forwarder;
        bool _dnssecValidation;
        DnsForwarderRecordProxyType _proxyType;
        string _proxyAddress;
        ushort _proxyPort;
        string _proxyUsername;
        string _proxyPassword;
        byte _priority;

        readonly bool _isPartialRecordData;

        NameServerAddress _nameServer;
        NetProxy _proxy;

        #endregion

        #region constructor

        private DnsForwarderRecordData(DnsTransportProtocol protocol, string forwarder)
            : this(protocol, forwarder, false, DnsForwarderRecordProxyType.DefaultProxy, null, 0, null, null, 0)
        {
            _isPartialRecordData = true;
        }

        public DnsForwarderRecordData(DnsTransportProtocol protocol, string forwarder, bool dnssecValidation, DnsForwarderRecordProxyType proxyType, string proxyAddress, ushort proxyPort, string proxyUsername, string proxyPassword, byte priority)
        {
            _protocol = protocol;
            _forwarder = forwarder;
            _dnssecValidation = dnssecValidation;
            _proxyType = proxyType;

            switch (proxyType)
            {
                case DnsForwarderRecordProxyType.Http:
                case DnsForwarderRecordProxyType.Socks5:
                    _proxyAddress = proxyAddress;
                    _proxyPort = proxyPort;
                    _proxyUsername = proxyUsername;
                    _proxyPassword = proxyPassword;

                    if (_proxyUsername is null)
                        _proxyUsername = string.Empty;

                    if (_proxyPassword is null)
                        _proxyPassword = string.Empty;

                    break;
            }

            _priority = priority;

            if (_protocol == DnsTransportProtocol.HttpsJson)
                _protocol = DnsTransportProtocol.Https;

            _nameServer = NameServerAddress.Parse(_forwarder);
            if (_nameServer.Protocol != _protocol)
                _nameServer = _nameServer.ChangeProtocol(_protocol);
        }

        public DnsForwarderRecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region static

        public static DnsForwarderRecordData CreatePartialRecordData(DnsTransportProtocol protocol, string forwarder)
        {
            return new DnsForwarderRecordData(protocol, forwarder);
        }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            long initialPosition = s.Position;

            _protocol = (DnsTransportProtocol)s.ReadByteValue();
            _forwarder = s.ReadShortString(Encoding.ASCII);

            long bytesRead = s.Position - initialPosition;
            if (bytesRead < _rdLength)
            {
                _dnssecValidation = s.ReadByteValue() == 1;
                _proxyType = (DnsForwarderRecordProxyType)s.ReadByteValue();

                switch (_proxyType)
                {
                    case DnsForwarderRecordProxyType.Http:
                    case DnsForwarderRecordProxyType.Socks5:
                        _proxyAddress = s.ReadShortString(Encoding.ASCII);
                        _proxyPort = DnsDatagram.ReadUInt16NetworkOrder(s);
                        _proxyUsername = s.ReadShortString(Encoding.ASCII);
                        _proxyPassword = s.ReadShortString(Encoding.ASCII);
                        break;
                }
            }

            bytesRead = s.Position - initialPosition;
            if (bytesRead < _rdLength)
                _priority = s.ReadByteValue();

            //read any extra bytes in RDATA for forward compatibility
            bytesRead = s.Position - initialPosition;
            if (bytesRead < _rdLength)
            {
                int count = _rdLength - (ushort)bytesRead;
                Span<byte> buffer = stackalloc byte[count];
                s.ReadExactly(buffer);
            }

            if (_protocol == DnsTransportProtocol.HttpsJson)
                _protocol = DnsTransportProtocol.Https;
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            s.WriteByte((byte)_protocol);
            s.WriteShortString(_forwarder, Encoding.ASCII);
            s.WriteByte(_dnssecValidation ? (byte)1 : byte.MinValue);
            s.WriteByte((byte)_proxyType);

            switch (_proxyType)
            {
                case DnsForwarderRecordProxyType.Http:
                case DnsForwarderRecordProxyType.Socks5:
                    s.WriteShortString(_proxyAddress, Encoding.ASCII);
                    DnsDatagram.WriteUInt16NetworkOrder(_proxyPort, s);
                    s.WriteShortString(_proxyUsername, Encoding.ASCII);
                    s.WriteShortString(_proxyPassword, Encoding.ASCII);
                    break;
            }

            s.WriteByte(_priority);
        }

        #endregion

        #region internal

        internal static async Task<DnsForwarderRecordData> FromZoneFileEntryAsync(ZoneFile zoneFile)
        {
            Stream rdata = await zoneFile.GetRData();
            if (rdata is not null)
                return new DnsForwarderRecordData(rdata);

            DnsTransportProtocol protocol = Enum.Parse<DnsTransportProtocol>(await zoneFile.PopItemAsync(), true);
            string forwarder = await zoneFile.PopItemAsync();
            bool dnssecValidation = bool.Parse(await zoneFile.PopItemAsync());
            DnsForwarderRecordProxyType proxyType = Enum.Parse<DnsForwarderRecordProxyType>(await zoneFile.PopItemAsync(), true);

            string proxyAddress = null;
            ushort proxyPort = 0;
            string proxyUsername = null;
            string proxyPassword = null;

            switch (proxyType)
            {
                case DnsForwarderRecordProxyType.Http:
                case DnsForwarderRecordProxyType.Socks5:
                    proxyAddress = await zoneFile.PopItemAsync();
                    proxyPort = ushort.Parse(await zoneFile.PopItemAsync());

                    proxyUsername = await zoneFile.PopItemAsync();
                    if ((proxyUsername is null) || (proxyUsername == "-"))
                        proxyUsername = string.Empty;

                    proxyPassword = await zoneFile.PopItemAsync();
                    if ((proxyPassword is null) || (proxyPassword == "-"))
                        proxyPassword = string.Empty;

                    break;
            }

            byte priority = byte.Parse(await zoneFile.PopItemAsync());

            return new DnsForwarderRecordData(protocol, forwarder, dnssecValidation, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword, priority);
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            string str = _protocol.ToString() + " " + DnsDatagram.EncodeCharacterString(_forwarder) + " " + _dnssecValidation + " " + _proxyType.ToString();

            switch (_proxyType)
            {
                case DnsForwarderRecordProxyType.Http:
                case DnsForwarderRecordProxyType.Socks5:
                    str += " " + DnsDatagram.EncodeCharacterString(_proxyAddress) + " " + _proxyPort;

                    if (string.IsNullOrEmpty(_proxyUsername))
                        str += " -";
                    else
                        str += " " + DnsDatagram.EncodeCharacterString(_proxyUsername);

                    if (string.IsNullOrEmpty(_proxyPassword))
                        str += " -";
                    else
                        str += " " + DnsDatagram.EncodeCharacterString(_proxyPassword);

                    break;
            }

            str += " " + _priority;

            return str;
        }

        #endregion

        #region public

        public NetProxy GetProxy(NetProxy defaultProxy)
        {
            switch (_proxyType)
            {
                case DnsForwarderRecordProxyType.DefaultProxy:
                    return defaultProxy;

                case DnsForwarderRecordProxyType.Http:
                case DnsForwarderRecordProxyType.Socks5:
                    if (_proxy is null)
                    {
                        _proxy = NetProxy.CreateProxy((NetProxyType)_proxyType, _proxyAddress, _proxyPort, _proxyUsername, _proxyPassword);
                        _proxy.BypassList = null;
                    }

                    return _proxy;

                default:
                    return null;
            }
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsForwarderRecordData other)
            {
                if (_protocol != other._protocol)
                    return false;

                if (!_forwarder.Equals(other._forwarder, StringComparison.OrdinalIgnoreCase))
                    return false;

                if (!_isPartialRecordData)
                {
                    if (_dnssecValidation != other._dnssecValidation)
                        return false;

                    if (_proxyType != other._proxyType)
                        return false;

                    if (_proxyAddress != other._proxyAddress)
                        return false;

                    if (_proxyPort != other._proxyPort)
                        return false;

                    if (_proxyUsername != other._proxyUsername)
                        return false;

                    if (_proxyPassword != other._proxyPassword)
                        return false;

                    if (_priority != other._priority)
                        return false;
                }

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_protocol, _forwarder);
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("Protocol", _protocol.ToString());
            jsonWriter.WriteString("Forwarder", _forwarder);
            jsonWriter.WriteNumber("Priority", _priority);
            jsonWriter.WriteBoolean("DnssecValidation", _dnssecValidation);
            jsonWriter.WriteString("ProxyType", _proxyType.ToString());

            switch (_proxyType)
            {
                case DnsForwarderRecordProxyType.Http:
                case DnsForwarderRecordProxyType.Socks5:
                    jsonWriter.WriteString("ProxyAddress", _proxyAddress);
                    jsonWriter.WriteNumber("ProxyPort", _proxyPort);
                    jsonWriter.WriteString("ProxyUsername", _proxyUsername);
                    jsonWriter.WriteString("ProxyPassword", _proxyPassword);
                    break;
            }

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public DnsTransportProtocol Protocol
        { get { return _protocol; } }

        public string Forwarder
        { get { return _forwarder; } }

        public bool DnssecValidation
        { get { return _dnssecValidation; } }

        public DnsForwarderRecordProxyType ProxyType
        { get { return _proxyType; } }

        public string ProxyAddress
        { get { return _proxyAddress; } }

        public ushort ProxyPort
        { get { return _proxyPort; } }

        public string ProxyUsername
        { get { return _proxyUsername; } }

        public string ProxyPassword
        { get { return _proxyPassword; } }

        public byte Priority
        { get { return _priority; } }

        public NameServerAddress NameServer
        {
            get
            {
                if (_nameServer is null)
                {
                    _nameServer = NameServerAddress.Parse(_forwarder);
                    if (_nameServer.Protocol != _protocol)
                        _nameServer = _nameServer.ChangeProtocol(_protocol);
                }

                return _nameServer;
            }
        }

        public override int UncompressedLength
        {
            get
            {
                int length = 1 + 1 + _forwarder.Length + 1 + 1;

                switch (_proxyType)
                {
                    case DnsForwarderRecordProxyType.Http:
                    case DnsForwarderRecordProxyType.Socks5:
                        length += 1 + _proxyAddress.Length + 2 + 1 + _proxyUsername.Length + 1 + _proxyPassword.Length;
                        break;
                }

                length++;

                return length;
            }
        }

        #endregion
    }
}
