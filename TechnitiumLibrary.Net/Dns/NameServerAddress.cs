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
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns
{
    public class NameServerAddress
    {
        #region variables

        DnsTransportProtocol _protocol;
        string _originalAddress;

        Uri _dohEndPoint;
        DomainEndPoint _domainEndPoint;
        IPEndPoint _ipEndPoint;

        bool _ipEndPointExpires;
        DateTime _ipEndPointExpiresOn;
        const int IP_ENDPOINT_DEFAULT_TTL = 900;

        #endregion

        #region constructors

        private NameServerAddress()
        { }

        public NameServerAddress(Uri dohEndPoint)
        {
            _dohEndPoint = dohEndPoint;

            if (IPAddress.TryParse(_dohEndPoint.Host, out IPAddress address))
                _ipEndPoint = new IPEndPoint(address, GetDoHPort());

            _protocol = DnsTransportProtocol.Https;
            _originalAddress = _dohEndPoint.AbsoluteUri;
        }

        public NameServerAddress(Uri dohEndPoint, IPAddress address)
        {
            _dohEndPoint = dohEndPoint;
            _ipEndPoint = new IPEndPoint(address, GetDoHPort());

            _protocol = DnsTransportProtocol.Https;

            if (address.AddressFamily == AddressFamily.InterNetworkV6)
                _originalAddress = _dohEndPoint.AbsoluteUri + " ([" + address.ToString() + "])";
            else
                _originalAddress = _dohEndPoint.AbsoluteUri + " (" + address.ToString() + ")";
        }

        public NameServerAddress(IPAddress address, DnsTransportProtocol protocol = DnsTransportProtocol.Udp)
        {
            _ipEndPoint = new IPEndPoint(address, 53);

            _protocol = protocol;
            _originalAddress = address.ToString();

            ValidateProtocol();
        }

        public NameServerAddress(string domain, IPAddress address, DnsTransportProtocol protocol = DnsTransportProtocol.Udp)
        {
            _domainEndPoint = new DomainEndPoint(domain, 53);
            _ipEndPoint = new IPEndPoint(address, 53);

            _protocol = protocol;

            if (address.AddressFamily == AddressFamily.InterNetworkV6)
                _originalAddress = domain + " ([" + address.ToString() + "])";
            else
                _originalAddress = domain + " (" + address.ToString() + ")";

            ValidateProtocol();
        }

        public NameServerAddress(string domain, IPEndPoint ipEndPoint, DnsTransportProtocol protocol = DnsTransportProtocol.Udp)
        {
            _domainEndPoint = new DomainEndPoint(domain, ipEndPoint.Port);
            _ipEndPoint = ipEndPoint;

            _protocol = protocol;

            if (ipEndPoint.AddressFamily == AddressFamily.InterNetworkV6)
                _originalAddress = domain + " ([" + ipEndPoint.Address.ToString() + "]:" + ipEndPoint.Port + ")";
            else
                _originalAddress = domain + " (" + ipEndPoint.ToString() + ")";

            ValidateProtocol();
        }

        public NameServerAddress(EndPoint endPoint, DnsTransportProtocol protocol = DnsTransportProtocol.Udp)
        {
            switch (endPoint.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                case AddressFamily.InterNetworkV6:
                    _ipEndPoint = endPoint as IPEndPoint;
                    break;

                case AddressFamily.Unspecified:
                    _domainEndPoint = endPoint as DomainEndPoint;
                    break;

                default:
                    throw new NotSupportedException("Address Family not supported.");
            }

            _protocol = protocol;

            if (endPoint.AddressFamily == AddressFamily.InterNetworkV6)
                _originalAddress = "[" + (endPoint as IPEndPoint).Address.ToString() + "]:" + (endPoint as IPEndPoint).Port;
            else
                _originalAddress = endPoint.ToString();

            ValidateProtocol();
        }

        public NameServerAddress(BinaryReader bR)
        {
            switch (bR.ReadByte())
            {
                case 1:
                    if (bR.ReadBoolean())
                        _dohEndPoint = new Uri(bR.ReadShortString());

                    if (bR.ReadBoolean())
                        _domainEndPoint = EndPointExtensions.ReadFrom(bR) as DomainEndPoint;

                    if (bR.ReadBoolean())
                        _ipEndPoint = EndPointExtensions.ReadFrom(bR) as IPEndPoint;

                    if (_dohEndPoint is not null)
                        _originalAddress = _dohEndPoint.AbsoluteUri;
                    else if (_ipEndPoint is not null)
                        _originalAddress = _ipEndPoint.ToString();
                    else if (_domainEndPoint is not null)
                        _originalAddress = _domainEndPoint.ToString();

                    GuessProtocol();
                    break;

                case 2:
                    InternalParse(bR.ReadShortString());
                    GuessProtocol();
                    break;

                case 3:
                    _protocol = (DnsTransportProtocol)bR.ReadByte();
                    InternalParse(bR.ReadShortString());
                    break;

                default:
                    throw new InvalidDataException("NameServerAddress version not supported");
            }
        }

        #endregion

        #region private

        private void ValidateProtocol()
        {
            switch (_protocol)
            {
                case DnsTransportProtocol.Udp:
                case DnsTransportProtocol.Tcp:
                    if (_dohEndPoint is not null)
                        throw new ArgumentException("Invalid DNS transport protocol was specified for current operation: " + _protocol.ToString());

                    if (Port == 853)
                        throw new ArgumentException("Invalid DNS transport protocol was specified for current operation: " + _protocol.ToString());

                    break;

                case DnsTransportProtocol.Tls:
                case DnsTransportProtocol.Quic:
                    if (_dohEndPoint is not null)
                        throw new ArgumentException("Invalid DNS transport protocol was specified for current operation: " + _protocol.ToString());

                    if (Port == 53)
                        throw new ArgumentException("Invalid DNS transport protocol was specified for current operation: " + _protocol.ToString());

                    break;

                case DnsTransportProtocol.Https:
                    if (_dohEndPoint is null)
                        throw new ArgumentException("Invalid DNS transport protocol was specified for current operation: " + _protocol.ToString());

                    switch (Port)
                    {
                        case 53:
                        case 853:
                            throw new ArgumentException("Invalid DNS transport protocol was specified for current operation: " + _protocol.ToString());
                    }

                    break;
            }
        }

        private void GuessProtocol()
        {
            if (_dohEndPoint is not null)
            {
                _protocol = DnsTransportProtocol.Https;
            }
            else if (_originalAddress.StartsWith("udp://", StringComparison.OrdinalIgnoreCase))
            {
                _protocol = DnsTransportProtocol.Udp;
            }
            else if (_originalAddress.StartsWith("tcp://", StringComparison.OrdinalIgnoreCase))
            {
                _protocol = DnsTransportProtocol.Tcp;
            }
            else if (_originalAddress.StartsWith("tls://", StringComparison.OrdinalIgnoreCase))
            {
                _protocol = DnsTransportProtocol.Tls;
            }
            else if (_originalAddress.StartsWith("quic://", StringComparison.OrdinalIgnoreCase))
            {
                _protocol = DnsTransportProtocol.Quic;
            }
            else
            {
                switch (Port)
                {
                    case 853:
                        _protocol = DnsTransportProtocol.Tls;
                        break;

                    default:
                        _protocol = DnsTransportProtocol.Udp;
                        break;
                }
            }
        }

        private void InternalParse(string address)
        {
            _originalAddress = address;

            //parse
            string domainName = null;
            int domainPort = 0;
            string host = null;
            int port = 0;
            bool ipv6Host = false;

            int posRoundBracketStart = address.IndexOf('(');
            if (posRoundBracketStart > -1)
            {
                int posRoundBracketEnd = address.IndexOf(')', posRoundBracketStart + 1);
                if (posRoundBracketEnd < 0)
                    throw new ArgumentException("Invalid name server address was encountered: " + _originalAddress);

                {
                    string strDomainPart = address.Substring(0, posRoundBracketStart).Trim();

                    if (strDomainPart.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || strDomainPart.StartsWith("h3://", StringComparison.OrdinalIgnoreCase) || strDomainPart.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                    {
                        _dohEndPoint = new Uri(strDomainPart);
                    }
                    else if (strDomainPart.StartsWith("udp://", StringComparison.OrdinalIgnoreCase) || strDomainPart.StartsWith("tcp://", StringComparison.OrdinalIgnoreCase))
                    {
                        Uri uri = new Uri(strDomainPart);

                        domainName = uri.Host;

                        if (uri.Port == -1)
                            domainPort = 53;
                        else
                            domainPort = uri.Port;
                    }
                    else if (strDomainPart.StartsWith("tls://", StringComparison.OrdinalIgnoreCase) || strDomainPart.StartsWith("quic://", StringComparison.OrdinalIgnoreCase))
                    {
                        Uri uri = new Uri(strDomainPart);

                        domainName = uri.Host;

                        if (uri.Port == -1)
                            domainPort = 853;
                        else
                            domainPort = uri.Port;
                    }
                    else
                    {
                        string[] strParts = strDomainPart.Split(':');

                        domainName = strParts[0];

                        if (strParts.Length > 1)
                            domainPort = int.Parse(strParts[1]);
                    }
                }

                address = address.Substring(posRoundBracketStart + 1, posRoundBracketEnd - posRoundBracketStart - 1);
            }

            if (address.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || address.StartsWith("h3://", StringComparison.OrdinalIgnoreCase) || address.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            {
                _dohEndPoint = new Uri(address);
            }
            else if (address.StartsWith("udp://", StringComparison.OrdinalIgnoreCase) || address.StartsWith("tcp://", StringComparison.OrdinalIgnoreCase))
            {
                Uri uri = new Uri(address);

                host = uri.Host;

                if (uri.Port == -1)
                    port = 53;
                else
                    port = uri.Port;
            }
            else if (address.StartsWith("tls://", StringComparison.OrdinalIgnoreCase) || address.StartsWith("quic://", StringComparison.OrdinalIgnoreCase))
            {
                Uri uri = new Uri(address);

                host = uri.Host;

                if (uri.Port == -1)
                    port = 853;
                else
                    port = uri.Port;
            }
            else if (address.StartsWith('['))
            {
                //ipv6
                if (address.EndsWith(']'))
                {
                    host = address.Trim('[', ']');
                }
                else
                {
                    int posBracketEnd = address.LastIndexOf(']');

                    host = address.Substring(1, posBracketEnd - 1);

                    int posCollon = address.IndexOf(':', posBracketEnd + 1);
                    if (posCollon > -1)
                        port = int.Parse(address.Substring(posCollon + 1));
                }

                ipv6Host = true;
            }
            else
            {
                string[] strParts = address.Split(':');

                if (strParts.Length == 2)
                {
                    host = strParts[0].Trim();
                    port = int.Parse(strParts[1]);
                }
                else
                {
                    //ipv6 or domain
                    host = address;
                }
            }

            if (_dohEndPoint is null)
            {
                if ((domainPort == 0) && (port == 0))
                {
                    domainPort = 53;
                    port = 53;
                }
                else if (domainPort == 0)
                {
                    domainPort = port;
                }
                else if (port == 0)
                {
                    port = domainPort;
                }
                else if (domainPort != port)
                {
                    throw new ArgumentException("Invalid name server address was encountered: " + _originalAddress);
                }

                if (domainName is not null)
                    _domainEndPoint = new DomainEndPoint(domainName, domainPort);

                if (IPAddress.TryParse(host, out IPAddress ipAddress))
                    _ipEndPoint = new IPEndPoint(ipAddress, port);
                else if ((_domainEndPoint is not null) || ipv6Host)
                    throw new ArgumentException("Invalid name server address was encountered: " + _originalAddress);
                else
                    _domainEndPoint = new DomainEndPoint(host, port);
            }
            else if (host is not null)
            {
                if (port == 0)
                    port = GetDoHPort();
                else if (GetDoHPort() != port)
                    throw new ArgumentException("Invalid name server address was encountered: " + _originalAddress);

                if (IPAddress.TryParse(host, out IPAddress ipAddress))
                    _ipEndPoint = new IPEndPoint(ipAddress, port);
                else
                    throw new ArgumentException("Invalid name server address was encountered: " + _originalAddress);
            }
        }

        private int GetDoHPort()
        {
            if ((_dohEndPoint.Port == -1) && _dohEndPoint.Scheme.Equals("h3", StringComparison.OrdinalIgnoreCase))
                return 443;

            return _dohEndPoint.Port;
        }

        #endregion

        #region static

        public static NameServerAddress Parse(string address, DnsTransportProtocol protocol)
        {
            NameServerAddress nameServerAddress = new NameServerAddress();

            nameServerAddress.InternalParse(address.Trim());
            nameServerAddress._protocol = protocol;
            nameServerAddress.ValidateProtocol();

            return nameServerAddress;
        }

        public static NameServerAddress Parse(string address)
        {
            NameServerAddress nameServerAddress = new NameServerAddress();

            nameServerAddress.InternalParse(address.Trim());
            nameServerAddress.GuessProtocol();

            return nameServerAddress;
        }

        public static List<NameServerAddress> GetNameServersFromResponse(DnsDatagram response, bool preferIPv6, bool filterLoopbackAddresses)
        {
            IReadOnlyList<DnsResourceRecord> authorityRecords;

            if ((response.Question.Count > 0) && (response.Question[0].Type == DnsResourceRecordType.NS) && (response.Answer.Count > 0))
            {
                bool found = false;

                foreach (DnsResourceRecord answer in response.Answer)
                {
                    if (answer.Type == DnsResourceRecordType.NS)
                    {
                        found = true;
                        break;
                    }
                }

                if (found)
                    authorityRecords = response.Answer;
                else
                    authorityRecords = response.Authority;
            }
            else
            {
                authorityRecords = response.Authority;
            }

            List<NameServerAddress> nameServers = new List<NameServerAddress>(authorityRecords.Count);

            foreach (DnsResourceRecord authorityRecord in authorityRecords)
            {
                if (authorityRecord.Type == DnsResourceRecordType.NS)
                {
                    DnsNSRecordData nsRecord = (DnsNSRecordData)authorityRecord.RDATA;

                    if (IPAddress.TryParse(nsRecord.NameServer, out _))
                        continue; //skip misconfigured NS record

                    IPEndPoint endPoint = null;

                    //find ip address of authoritative name server from additional records
                    foreach (DnsResourceRecord rr in response.Additional)
                    {
                        if (nsRecord.NameServer.Equals(rr.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (rr.Type)
                            {
                                case DnsResourceRecordType.A:
                                    endPoint = new IPEndPoint(((DnsARecordData)rr.RDATA).Address, 53);

                                    if (filterLoopbackAddresses && IPAddress.IsLoopback(endPoint.Address))
                                        continue;

                                    nameServers.Add(new NameServerAddress(nsRecord.NameServer, endPoint));
                                    break;

                                case DnsResourceRecordType.AAAA:
                                    endPoint = new IPEndPoint(((DnsAAAARecordData)rr.RDATA).Address, 53);

                                    if (filterLoopbackAddresses && IPAddress.IsLoopback(endPoint.Address))
                                        continue;

                                    if (preferIPv6)
                                        nameServers.Add(new NameServerAddress(nsRecord.NameServer, endPoint));

                                    break;
                            }
                        }
                    }

                    if (endPoint is null)
                        nameServers.Add(new NameServerAddress(new DomainEndPoint(nsRecord.NameServer, 53)));
                }
            }

            return nameServers;
        }

        #endregion

        #region public

        public NameServerAddress ChangeProtocol(DnsTransportProtocol protocol)
        {
            if (_protocol == protocol)
                return this;

            NameServerAddress nsAddress = new NameServerAddress();

            switch (protocol)
            {
                case DnsTransportProtocol.Udp:
                case DnsTransportProtocol.Tcp:
                    {
                        int port;

                        switch (_protocol)
                        {
                            case DnsTransportProtocol.Udp:
                            case DnsTransportProtocol.Tcp:
                                port = Port;
                                break;

                            default:
                                port = 53;
                                break;
                        }

                        if ((_dohEndPoint is not null) && !IPAddress.TryParse(_dohEndPoint.Host, out _))
                            nsAddress._domainEndPoint = new DomainEndPoint(_dohEndPoint.Host, port);
                        else if (_domainEndPoint is not null)
                            nsAddress._domainEndPoint = new DomainEndPoint(_domainEndPoint.Address, port);

                        if ((_dohEndPoint is not null) && IPAddress.TryParse(_dohEndPoint.Host, out IPAddress address))
                            nsAddress._ipEndPoint = new IPEndPoint(address, port);
                        else if (_ipEndPoint is not null)
                            nsAddress._ipEndPoint = new IPEndPoint(_ipEndPoint.Address, port);
                    }
                    break;

                case DnsTransportProtocol.Tls:
                case DnsTransportProtocol.Quic:
                    {
                        int port;

                        if (((_protocol == DnsTransportProtocol.Udp) || (_protocol == DnsTransportProtocol.Tcp)) && (Port != 53))
                            port = Port;
                        else
                            port = 853;

                        if ((_dohEndPoint is not null) && !IPAddress.TryParse(_dohEndPoint.Host, out _))
                            nsAddress._domainEndPoint = new DomainEndPoint(_dohEndPoint.Host, port);
                        else if (_domainEndPoint is not null)
                            nsAddress._domainEndPoint = new DomainEndPoint(_domainEndPoint.Address, port);

                        if ((_dohEndPoint is not null) && IPAddress.TryParse(_dohEndPoint.Host, out IPAddress address))
                            nsAddress._ipEndPoint = new IPEndPoint(address, port);
                        else if (_ipEndPoint is not null)
                            nsAddress._ipEndPoint = new IPEndPoint(_ipEndPoint.Address, port);
                    }
                    break;

                case DnsTransportProtocol.Https:
                    {
                        int port;

                        if (((_protocol == DnsTransportProtocol.Udp) || (_protocol == DnsTransportProtocol.Tcp)) && (Port != 53))
                            port = Port;
                        else
                            port = 443;

                        if (_dohEndPoint is not null)
                            nsAddress._dohEndPoint = _dohEndPoint;
                        else if (_domainEndPoint is not null)
                            nsAddress._dohEndPoint = new Uri("https://" + _domainEndPoint.Address + (port == 443 ? "" : ":" + port) + "/dns-query");
                        else if (_ipEndPoint is not null)
                            nsAddress._dohEndPoint = new Uri("https://" + (_ipEndPoint.Address.AddressFamily == AddressFamily.InterNetworkV6 ? "[" + _ipEndPoint.Address.ToString() + "]" : _ipEndPoint.Address.ToString()) + (port == 443 ? "" : ":" + port) + "/dns-query");

                        if ((_dohEndPoint is not null) && IPAddress.TryParse(_dohEndPoint.Host, out IPAddress address))
                            nsAddress._ipEndPoint = new IPEndPoint(address, port);
                        else if (_ipEndPoint is not null)
                            nsAddress._ipEndPoint = new IPEndPoint(_ipEndPoint.Address, port);
                    }
                    break;

                default:
                    throw new NotSupportedException("DNS transport protocol is not supported: " + protocol.ToString());
            }

            nsAddress._protocol = protocol;
            nsAddress._originalAddress = nsAddress.ToString();
            nsAddress._ipEndPointExpires = _ipEndPointExpires;
            nsAddress._ipEndPointExpiresOn = _ipEndPointExpiresOn;

            nsAddress.ValidateProtocol();

            return nsAddress;
        }

        public async Task ResolveIPAddressAsync(IDnsClient dnsClient, bool preferIPv6 = false, CancellationToken cancellationToken = default)
        {
            if (_ipEndPointExpires && (DateTime.UtcNow < _ipEndPointExpiresOn))
                return;

            string domain;

            if (_dohEndPoint is not null)
                domain = _dohEndPoint.Host;
            else if (_domainEndPoint is not null)
                domain = _domainEndPoint.Address;
            else
                return;

            if (domain == "localhost")
            {
                _ipEndPoint = new IPEndPoint(preferIPv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback, Port);
                return;
            }

            if (IPAddress.TryParse(domain, out IPAddress address))
            {
                _ipEndPoint = new IPEndPoint(address, Port);
                return;
            }

            IReadOnlyList<IPAddress> serverIPs = await DnsClient.ResolveIPAsync(dnsClient, domain, preferIPv6, cancellationToken);

            if (serverIPs.Count == 0)
                throw new DnsClientException("No IP address was found for name server: " + domain);

            _ipEndPoint = new IPEndPoint(serverIPs[0], Port);
            _ipEndPointExpires = true;
            _ipEndPointExpiresOn = DateTime.UtcNow.AddSeconds(IP_ENDPOINT_DEFAULT_TTL);
        }

        public async Task RecursiveResolveIPAddressAsync(IDnsCache cache = null, NetProxy proxy = null, bool preferIPv6 = false, ushort udpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE, bool randomizeName = false, int retries = 2, int timeout = 2000, CancellationToken cancellationToken = default)
        {
            if (_ipEndPointExpires && (DateTime.UtcNow < _ipEndPointExpiresOn))
                return;

            string domain;

            if (_dohEndPoint is not null)
                domain = _dohEndPoint.Host;
            else if (_domainEndPoint is not null)
                domain = _domainEndPoint.Address;
            else
                return;

            if (domain == "localhost")
            {
                _ipEndPoint = new IPEndPoint(preferIPv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback, Port);
                return;
            }

            if (IPAddress.TryParse(domain, out IPAddress address))
            {
                _ipEndPoint = new IPEndPoint(address, Port);
                return;
            }

            IPEndPoint ipEndPoint = null;

            IReadOnlyList<IPAddress> addresses = await DnsClient.RecursiveResolveIPAsync(domain, cache, proxy, preferIPv6, udpPayloadSize, randomizeName, false, false, null, retries, timeout, 16, cancellationToken);
            if (addresses.Count > 0)
                ipEndPoint = new IPEndPoint(addresses[0], Port);

            if (ipEndPoint is null)
                throw new DnsClientException("No IP address was found for name server: " + domain);

            _ipEndPoint = ipEndPoint;
            _ipEndPointExpires = true;
            _ipEndPointExpiresOn = DateTime.UtcNow.AddSeconds(IP_ENDPOINT_DEFAULT_TTL);
        }

        public async Task ResolveDomainNameAsync(IDnsClient dnsClient, CancellationToken cancellationToken = default)
        {
            if (_ipEndPoint is not null)
            {
                try
                {
                    IReadOnlyList<string> ptrDomains = DnsClient.ParseResponsePTR(await dnsClient.ResolveAsync(new DnsQuestionRecord(_ipEndPoint.Address, DnsClass.IN), cancellationToken));
                    if (ptrDomains.Count > 0)
                        _domainEndPoint = new DomainEndPoint(ptrDomains[0], _ipEndPoint.Port);
                }
                catch
                { }
            }
        }

        public async Task RecursiveResolveDomainNameAsync(IDnsCache cache = null, NetProxy proxy = null, bool preferIPv6 = false, ushort udpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE, bool randomizeName = false, int retries = 2, int timeout = 2000, CancellationToken cancellationToken = default)
        {
            if (_ipEndPoint is not null)
            {
                try
                {
                    IReadOnlyList<string> ptrDomains = DnsClient.ParseResponsePTR(await DnsClient.RecursiveResolveQueryAsync(new DnsQuestionRecord(_ipEndPoint.Address, DnsClass.IN), cache, proxy, preferIPv6, udpPayloadSize, randomizeName, false, false, null, retries, timeout, 16, cancellationToken));
                    if (ptrDomains.Count > 0)
                        _domainEndPoint = new DomainEndPoint(ptrDomains[0], _ipEndPoint.Port);
                }
                catch
                { }
            }
        }

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)3); //version
            bW.Write((byte)_protocol);
            bW.WriteShortString(_originalAddress);
        }

        public override string ToString()
        {
            string value;

            if (_dohEndPoint is not null)
            {
                value = _dohEndPoint.AbsoluteUri;
            }
            else if (_domainEndPoint is not null)
            {
                switch (_domainEndPoint.Port)
                {
                    case 53:
                    case 853:
                        value = _domainEndPoint.Address;
                        break;

                    default:
                        value = _domainEndPoint.ToString();
                        break;
                }
            }
            else
            {
                switch (_ipEndPoint.Port)
                {
                    case 53:
                    case 853:
                        return _ipEndPoint.AddressFamily == AddressFamily.InterNetworkV6 ? "[" + _ipEndPoint.Address.ToString() + "]" : _ipEndPoint.Address.ToString();

                    default:
                        return _ipEndPoint.ToString();
                }
            }

            if (_ipEndPoint is not null)
            {
                string address = _ipEndPoint.AddressFamily == AddressFamily.InterNetworkV6 ? "[" + _ipEndPoint.Address.ToString() + "]" : _ipEndPoint.Address.ToString();

                if ((_dohEndPoint is null) || (_dohEndPoint.Host != address))
                    value += " (" + address + ")";
            }

            return value;
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is NameServerAddress other)
            {
                if (!EqualityComparer<DnsTransportProtocol>.Default.Equals(_protocol, other._protocol))
                    return false;

                if (!EqualityComparer<Uri>.Default.Equals(_dohEndPoint, other._dohEndPoint))
                    return false;

                if (!EqualityComparer<DomainEndPoint>.Default.Equals(_domainEndPoint, other._domainEndPoint))
                    return false;

                if (!EqualityComparer<IPEndPoint>.Default.Equals(_ipEndPoint, other._ipEndPoint))
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_protocol, _dohEndPoint, _domainEndPoint, _ipEndPoint);
        }

        #endregion

        #region properties

        public DnsTransportProtocol Protocol
        { get { return _protocol; } }

        public string OriginalAddress
        { get { return _originalAddress; } }

        public bool IsDefaultPort
        {
            get
            {
                if (_dohEndPoint is not null)
                {
                    if (_dohEndPoint.Port == -1)
                        return true;

                    return _dohEndPoint.IsDefaultPort;
                }

                if (_domainEndPoint is not null)
                {
                    switch (_protocol)
                    {
                        case DnsTransportProtocol.Udp:
                        case DnsTransportProtocol.Tcp:
                            return _domainEndPoint.Port == 53;

                        case DnsTransportProtocol.Tls:
                        case DnsTransportProtocol.Quic:
                            return _domainEndPoint.Port == 853;

                        default:
                            return false;
                    }
                }

                switch (_protocol)
                {
                    case DnsTransportProtocol.Udp:
                    case DnsTransportProtocol.Tcp:
                        return _ipEndPoint.Port == 53;

                    case DnsTransportProtocol.Tls:
                    case DnsTransportProtocol.Quic:
                        return _ipEndPoint.Port == 853;

                    default:
                        return false;
                }
            }
        }

        public string Host
        {
            get
            {
                if (_dohEndPoint is not null)
                    return _dohEndPoint.Host;

                if (_domainEndPoint is not null)
                    return _domainEndPoint.Address;

                return _ipEndPoint.Address.ToString();
            }
        }

        public int Port
        {
            get
            {
                if (_dohEndPoint is not null)
                    return GetDoHPort();

                if (_domainEndPoint is not null)
                    return _domainEndPoint.Port;

                return _ipEndPoint.Port;
            }
        }

        public Uri DoHEndPoint
        { get { return _dohEndPoint; } }

        public DomainEndPoint DomainEndPoint
        { get { return _domainEndPoint; } }

        public IPEndPoint IPEndPoint
        { get { return _ipEndPoint; } }

        public EndPoint EndPoint
        {
            get
            {
                if (_ipEndPoint is not null)
                    return _ipEndPoint; //IP endpoint is prefered

                if (_dohEndPoint is not null)
                {
                    if (IPAddress.TryParse(_dohEndPoint.Host, out IPAddress address))
                        return new IPEndPoint(address, GetDoHPort());

                    return new DomainEndPoint(_dohEndPoint.Host, GetDoHPort());
                }

                return _domainEndPoint;
            }
        }

        public bool IsIPEndPointStale
        { get { return (_ipEndPoint is null) || (_ipEndPointExpires && (DateTime.UtcNow > _ipEndPointExpiresOn)); } }

        #endregion
    }
}
