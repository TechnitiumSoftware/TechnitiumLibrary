/*
Technitium Library
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns
{
    public class NameServerAddress : IComparable<NameServerAddress>
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

        public NameServerAddress(Uri dohEndPoint, DnsTransportProtocol protocol = DnsTransportProtocol.Https)
        {
            _dohEndPoint = dohEndPoint;

            if (IPAddress.TryParse(_dohEndPoint.Host, out IPAddress address))
                _ipEndPoint = new IPEndPoint(address, _dohEndPoint.Port);

            _protocol = protocol;
            _originalAddress = _dohEndPoint.AbsoluteUri;

            ValidateProtocol();
        }

        public NameServerAddress(Uri dohEndPoint, IPAddress address, DnsTransportProtocol protocol = DnsTransportProtocol.Https)
        {
            _dohEndPoint = dohEndPoint;
            _ipEndPoint = new IPEndPoint(address, _dohEndPoint.Port);

            _protocol = protocol;

            if (address.AddressFamily == AddressFamily.InterNetworkV6)
                _originalAddress = _dohEndPoint.AbsoluteUri + " ([" + address.ToString() + "])";
            else
                _originalAddress = _dohEndPoint.AbsoluteUri + " (" + address.ToString() + ")";

            ValidateProtocol();
        }

        public NameServerAddress(string address, DnsTransportProtocol protocol)
        {
            Parse(address.Trim());
            _protocol = protocol;
            ValidateProtocol();
        }

        public NameServerAddress(string address)
        {
            Parse(address.Trim());
            GuessProtocol();
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
                    throw new NotSupportedException("AddressFamily not supported.");
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
                        _domainEndPoint = EndPointExtension.Parse(bR) as DomainEndPoint;

                    if (bR.ReadBoolean())
                        _ipEndPoint = EndPointExtension.Parse(bR) as IPEndPoint;

                    if (_dohEndPoint != null)
                        _originalAddress = _dohEndPoint.AbsoluteUri;
                    else if (_ipEndPoint != null)
                        _originalAddress = _ipEndPoint.ToString();
                    else if (_domainEndPoint != null)
                        _originalAddress = _domainEndPoint.ToString();

                    GuessProtocol();
                    break;

                case 2:
                    Parse(bR.ReadShortString());
                    GuessProtocol();
                    break;

                case 3:
                    _protocol = (DnsTransportProtocol)bR.ReadByte();
                    Parse(bR.ReadShortString());
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
                    if (_dohEndPoint != null)
                        throw new ArgumentException("Invalid DNS transport protocol was specified for current operation: " + _protocol.ToString());

                    if (Port == 853)
                        throw new ArgumentException("Invalid DNS transport protocol was specified for current operation: " + _protocol.ToString());

                    break;

                case DnsTransportProtocol.Tls:
                    if (_dohEndPoint != null)
                        throw new ArgumentException("Invalid DNS transport protocol was specified for current operation: " + _protocol.ToString());

                    if (Port == 53)
                        throw new ArgumentException("Invalid DNS transport protocol was specified for current operation: " + _protocol.ToString());

                    break;

                case DnsTransportProtocol.Https:
                case DnsTransportProtocol.HttpsJson:
                    if (_dohEndPoint == null)
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
            if (_dohEndPoint != null)
            {
                _protocol = DnsTransportProtocol.Https;
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

        private void Parse(string address)
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

                    if (strDomainPart.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || strDomainPart.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                    {
                        _dohEndPoint = new Uri(strDomainPart);
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

            if (address.StartsWith("https://", StringComparison.OrdinalIgnoreCase) || address.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            {
                _dohEndPoint = new Uri(address);
            }
            else if (address.StartsWith("["))
            {
                //ipv6
                if (address.EndsWith("]"))
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

                host = strParts[0].Trim();

                if (strParts.Length > 1)
                    port = int.Parse(strParts[1]);
            }

            if (_dohEndPoint == null)
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

                if (domainName != null)
                    _domainEndPoint = new DomainEndPoint(domainName, domainPort);

                if (IPAddress.TryParse(host, out IPAddress ipAddress))
                    _ipEndPoint = new IPEndPoint(ipAddress, port);
                else if ((_domainEndPoint != null) || ipv6Host)
                    throw new ArgumentException("Invalid name server address was encountered: " + _originalAddress);
                else
                    _domainEndPoint = new DomainEndPoint(host, port);
            }
            else if (host != null)
            {
                if (port == 0)
                    port = _dohEndPoint.Port;
                else if (_dohEndPoint.Port != port)
                    throw new ArgumentException("Invalid name server address was encountered: " + _originalAddress);

                if (IPAddress.TryParse(host, out IPAddress ipAddress))
                    _ipEndPoint = new IPEndPoint(ipAddress, port);
                else
                    throw new ArgumentException("Invalid name server address was encountered: " + _originalAddress);
            }
        }

        #endregion

        #region static

        public static List<NameServerAddress> GetNameServersFromResponse(DnsDatagram response, bool preferIPv6)
        {
            IReadOnlyList<DnsResourceRecord> authorityRecords;

            if ((response.Question.Count > 0) && (response.Question[0].Type == DnsResourceRecordType.NS) && (response.Answer.Count > 0) && (response.Answer[0].Type == DnsResourceRecordType.NS))
                authorityRecords = response.Answer;
            else
                authorityRecords = response.Authority;

            List<NameServerAddress> nameServers = new List<NameServerAddress>(authorityRecords.Count);

            foreach (DnsResourceRecord authorityRecord in authorityRecords)
            {
                if (authorityRecord.Type == DnsResourceRecordType.NS)
                {
                    DnsNSRecord nsRecord = (DnsNSRecord)authorityRecord.RDATA;
                    IPEndPoint endPoint = null;

                    //find ip address of authoritative name server from additional records
                    foreach (DnsResourceRecord rr in response.Additional)
                    {
                        if (nsRecord.NameServer.Equals(rr.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (rr.Type)
                            {
                                case DnsResourceRecordType.A:
                                    endPoint = new IPEndPoint(((DnsARecord)rr.RDATA).Address, 53);
                                    nameServers.Add(new NameServerAddress(nsRecord.NameServer, endPoint));
                                    break;

                                case DnsResourceRecordType.AAAA:
                                    endPoint = new IPEndPoint(((DnsAAAARecord)rr.RDATA).Address, 53);

                                    if (preferIPv6)
                                        nameServers.Add(new NameServerAddress(nsRecord.NameServer, endPoint));

                                    break;
                            }
                        }
                    }

                    if (endPoint == null)
                        nameServers.Add(new NameServerAddress(new DomainEndPoint(nsRecord.NameServer, 53)));
                }
            }

            return nameServers;
        }

        #endregion

        #region public

        public NameServerAddress ChangeProtocol(DnsTransportProtocol protocol)
        {
            NameServerAddress nsAddress = new NameServerAddress();

            switch (protocol)
            {
                case DnsTransportProtocol.Udp:
                case DnsTransportProtocol.Tcp:
                    if ((_dohEndPoint is not null) && !IPAddress.TryParse(_dohEndPoint.Host, out _))
                        nsAddress._domainEndPoint = new DomainEndPoint(_dohEndPoint.Host, 53);
                    else if (_domainEndPoint is not null)
                        nsAddress._domainEndPoint = new DomainEndPoint(_domainEndPoint.Address, 53);

                    if ((_dohEndPoint is not null) && IPAddress.TryParse(_dohEndPoint.Host, out IPAddress address1))
                        nsAddress._ipEndPoint = new IPEndPoint(address1, 53);
                    else if (_ipEndPoint is not null)
                        nsAddress._ipEndPoint = new IPEndPoint(_ipEndPoint.Address, 53);

                    break;

                case DnsTransportProtocol.Tls:
                    if ((_dohEndPoint is not null) && !IPAddress.TryParse(_dohEndPoint.Host, out _))
                        nsAddress._domainEndPoint = new DomainEndPoint(_dohEndPoint.Host, 853);
                    else if (_domainEndPoint is not null)
                        nsAddress._domainEndPoint = new DomainEndPoint(_domainEndPoint.Address, 853);

                    if ((_dohEndPoint is not null) && IPAddress.TryParse(_dohEndPoint.Host, out IPAddress address2))
                        nsAddress._ipEndPoint = new IPEndPoint(address2, 853);
                    else if (_ipEndPoint is not null)
                        nsAddress._ipEndPoint = new IPEndPoint(_ipEndPoint.Address, 853);

                    break;

                case DnsTransportProtocol.Https:
                case DnsTransportProtocol.HttpsJson:
                    if (_dohEndPoint is not null)
                        nsAddress._dohEndPoint = _dohEndPoint;
                    else if (_domainEndPoint is not null)
                        nsAddress._dohEndPoint = new Uri("https://" + _domainEndPoint.Address + "/dns-query");
                    else if (_ipEndPoint is not null)
                        nsAddress._dohEndPoint = new Uri("https://" + (_ipEndPoint.Address.AddressFamily == AddressFamily.InterNetworkV6 ? "[" + _ipEndPoint.Address.ToString() + "]" : _ipEndPoint.Address.ToString()) + "/dns-query");

                    if ((_dohEndPoint is not null) && IPAddress.TryParse(_dohEndPoint.Host, out IPAddress address3))
                        nsAddress._ipEndPoint = new IPEndPoint(address3, 443);
                    else if (_ipEndPoint is not null)
                        nsAddress._ipEndPoint = new IPEndPoint(_ipEndPoint.Address, 443);

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

        public async Task ResolveIPAddressAsync(IDnsClient dnsClient, bool preferIPv6 = false)
        {
            if (_ipEndPointExpires && (DateTime.UtcNow < _ipEndPointExpiresOn))
                return;

            string domain;

            if (_dohEndPoint != null)
                domain = _dohEndPoint.Host;
            else if (_domainEndPoint != null)
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

            IReadOnlyList<IPAddress> serverIPs = await DnsClient.ResolveIPAsync(dnsClient, domain, preferIPv6);

            if (serverIPs.Count == 0)
                throw new DnsClientException("No IP address was found for name server: " + domain);

            _ipEndPoint = new IPEndPoint(serverIPs[0], Port);
            _ipEndPointExpires = true;
            _ipEndPointExpiresOn = DateTime.UtcNow.AddSeconds(IP_ENDPOINT_DEFAULT_TTL);
        }

        public async Task RecursiveResolveIPAddressAsync(IDnsCache cache = null, NetProxy proxy = null, bool preferIPv6 = false, bool randomizeName = false, bool qnameMinimization = false, int retries = 2, int timeout = 2000)
        {
            if (_ipEndPointExpires && (DateTime.UtcNow < _ipEndPointExpiresOn))
                return;

            string domain;

            if (_dohEndPoint != null)
                domain = _dohEndPoint.Host;
            else if (_domainEndPoint != null)
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

            IReadOnlyList<IPAddress> addresses = await DnsClient.RecursiveResolveIPAsync(domain, cache, proxy, preferIPv6, randomizeName, qnameMinimization, false, retries, timeout);
            if (addresses.Count > 0)
                ipEndPoint = new IPEndPoint(addresses[0], Port);

            if (ipEndPoint == null)
                throw new DnsClientException("No IP address was found for name server: " + domain);

            _ipEndPoint = ipEndPoint;
            _ipEndPointExpires = true;
            _ipEndPointExpiresOn = DateTime.UtcNow.AddSeconds(IP_ENDPOINT_DEFAULT_TTL);
        }

        public async Task ResolveDomainNameAsync(IDnsClient dnsClient)
        {
            if (_ipEndPoint != null)
            {
                try
                {
                    IReadOnlyList<string> ptrDomains = DnsClient.ParseResponsePTR(await dnsClient.ResolveAsync(new DnsQuestionRecord(_ipEndPoint.Address, DnsClass.IN)));
                    if (ptrDomains.Count > 0)
                        _domainEndPoint = new DomainEndPoint(ptrDomains[0], _ipEndPoint.Port);
                }
                catch
                { }
            }
        }

        public async Task RecursiveResolveDomainNameAsync(IDnsCache cache = null, NetProxy proxy = null, bool preferIPv6 = false, bool randomizeName = false, bool qnameMinimization = false, int retries = 2, int timeout = 2000)
        {
            if (_ipEndPoint != null)
            {
                try
                {
                    IReadOnlyList<string> ptrDomains = DnsClient.ParseResponsePTR(await DnsClient.RecursiveResolveQueryAsync(new DnsQuestionRecord(_ipEndPoint.Address, DnsClass.IN), cache, proxy, preferIPv6, randomizeName, qnameMinimization, false, retries, timeout));
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

            if (_dohEndPoint != null)
            {
                value = _dohEndPoint.AbsoluteUri;
            }
            else if (_domainEndPoint != null)
            {
                if (_domainEndPoint.Port == 53)
                    value = _domainEndPoint.Address;
                else
                    value = _domainEndPoint.ToString();
            }
            else
            {
                if (_ipEndPoint.Port == 53)
                    return _ipEndPoint.Address.ToString();
                else
                    return _ipEndPoint.ToString();
            }

            if (_ipEndPoint != null)
                value += " (" + _ipEndPoint.Address.ToString() + ")";

            return value;
        }

        public int CompareTo(NameServerAddress other)
        {
            if ((_ipEndPoint == null) || (other._ipEndPoint == null))
                return 0;

            if ((_ipEndPoint.AddressFamily == AddressFamily.InterNetwork) && (other._ipEndPoint.AddressFamily == AddressFamily.InterNetworkV6))
                return 1;

            if ((_ipEndPoint.AddressFamily == AddressFamily.InterNetworkV6) && (other._ipEndPoint.AddressFamily == AddressFamily.InterNetwork))
                return -1;

            return 0;
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

        public string Host
        {
            get
            {
                if (_dohEndPoint != null)
                    return _dohEndPoint.Host;

                if (_domainEndPoint != null)
                    return _domainEndPoint.Address;

                return _ipEndPoint.Address.ToString();
            }
        }

        public int Port
        {
            get
            {
                if (_dohEndPoint != null)
                    return _dohEndPoint.Port;

                if (_domainEndPoint != null)
                    return _domainEndPoint.Port;

                return _ipEndPoint.Port;
            }
        }

        public Uri DnsOverHttpEndPoint
        { get { return _dohEndPoint; } }

        public DomainEndPoint DomainEndPoint
        { get { return _domainEndPoint; } }

        public IPEndPoint IPEndPoint
        { get { return _ipEndPoint; } }

        public EndPoint EndPoint
        {
            get
            {
                if (_ipEndPoint != null)
                    return _ipEndPoint; //IP endpoint is prefered

                if (_dohEndPoint != null)
                    return new DomainEndPoint(_dohEndPoint.Host, _dohEndPoint.Port);

                return _domainEndPoint;
            }
        }

        public bool IsIPEndPointStale
        { get { return (_ipEndPoint == null) || (_ipEndPointExpires && (DateTime.UtcNow > _ipEndPointExpiresOn)); } }

        #endregion
    }
}
