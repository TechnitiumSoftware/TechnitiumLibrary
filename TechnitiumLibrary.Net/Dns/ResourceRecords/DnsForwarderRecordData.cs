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
using System.Text;
using System.Text.Json;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsForwarderRecordData : DnsResourceRecordData
    {
        #region variables

        DnsTransportProtocol _protocol;
        string _forwarder;
        bool _dnssecValidation;
        NetProxyType _proxyType;
        string _proxyAddress;
        ushort _proxyPort;
        string _proxyUsername;
        string _proxyPassword;

        NameServerAddress _nameServer;
        NetProxy _proxy;

        #endregion

        #region constructor

        public DnsForwarderRecordData(DnsTransportProtocol protocol, string forwarder)
            : this(protocol, forwarder, false, NetProxyType.None, null, 0, null, null)
        { }

        public DnsForwarderRecordData(DnsTransportProtocol protocol, string forwarder, bool dnssecValidation, NetProxyType proxyType, string proxyAddress, ushort proxyPort, string proxyUsername, string proxyPassword)
        {
            _protocol = protocol;
            _forwarder = forwarder;
            _dnssecValidation = dnssecValidation;
            _proxyType = proxyType;

            if (_proxyType != NetProxyType.None)
            {
                _proxyAddress = proxyAddress;
                _proxyPort = proxyPort;
                _proxyUsername = proxyUsername;
                _proxyPassword = proxyPassword;
            }

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
                _proxyType = (NetProxyType)s.ReadByteValue();

                if (_proxyType != NetProxyType.None)
                {
                    _proxyAddress = s.ReadShortString(Encoding.ASCII);
                    _proxyPort = DnsDatagram.ReadUInt16NetworkOrder(s);
                    _proxyUsername = s.ReadShortString(Encoding.ASCII);
                    _proxyPassword = s.ReadShortString(Encoding.ASCII);
                }
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

            if (_proxyType != NetProxyType.None)
            {
                s.WriteShortString(_proxyAddress, Encoding.ASCII);
                DnsDatagram.WriteUInt16NetworkOrder(_proxyPort, s);
                s.WriteShortString(_proxyUsername, Encoding.ASCII);
                s.WriteShortString(_proxyPassword, Encoding.ASCII);
            }
        }

        #endregion

        #region public

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

                return _forwarder.Equals(other._forwarder, StringComparison.OrdinalIgnoreCase);
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_protocol, _forwarder);
        }

        public override string ToString()
        {
            string str = _protocol.ToString() + " " + _forwarder + " " + _dnssecValidation + " " + _proxyType.ToString();

            if (_proxyType != NetProxyType.None)
            {
                str += " " + _proxyAddress + " " + _proxyPort;

                if (string.IsNullOrEmpty(_proxyUsername))
                    str += " " + _proxyUsername;

                if (string.IsNullOrEmpty(_proxyPassword))
                    str += " " + _proxyPassword;
            }

            return str;
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("protocol", _protocol.ToString());
            jsonWriter.WriteString("forwarder", _forwarder);
            jsonWriter.WriteBoolean("dnssecValidation", _dnssecValidation);
            jsonWriter.WriteString("proxyType", _proxyType.ToString());

            if (_proxyType != NetProxyType.None)
            {
                jsonWriter.WriteString("proxyAddress", _proxyAddress);
                jsonWriter.WriteNumber("proxyPort", _proxyPort);
                jsonWriter.WriteString("proxyUsername", _proxyUsername);
                jsonWriter.WriteString("proxyPassword", _proxyPassword);
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

        public NetProxyType ProxyType
        { get { return _proxyType; } }

        public string ProxyAddress
        { get { return _proxyAddress; } }

        public ushort ProxyPort
        { get { return _proxyPort; } }

        public string ProxyUsername
        { get { return _proxyUsername; } }

        public string ProxyPassword
        { get { return _proxyPassword; } }

        public NameServerAddress NameServer
        {
            get
            {
                if (_nameServer is null)
                    _nameServer = NameServerAddress.Parse(_forwarder, _protocol);

                return _nameServer;
            }
        }

        public NetProxy Proxy
        {
            get
            {
                if (_proxyType == NetProxyType.None)
                    return null;

                if (_proxy is null)
                {
                    _proxy = NetProxy.CreateProxy(_proxyType, _proxyAddress, _proxyPort, _proxyUsername, _proxyPassword);
                    _proxy.BypassList = null;
                }

                return _proxy;
            }
        }

        public override int UncompressedLength
        {
            get
            {
                int length = 1 + 1 + _forwarder.Length + 1 + 1;

                if (_proxyType != NetProxyType.None)
                    length += 1 + _proxyAddress.Length + 2 + 1 + _proxyUsername.Length + 1 + _proxyPassword.Length;

                return length;
            }
        }

        #endregion
    }
}
