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
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns
{
    public class NameServerAddress : IComparable<NameServerAddress>
    {
        #region variables

        Uri _dohEndPoint;
        DomainEndPoint _domainEndPoint;
        IPEndPoint _ipEndPoint;

        string _originalAddress;

        bool _ipEndPointExpires;
        DateTime _ipEndPointExpiresOn;
        readonly object _ipEndPointResolverLock = new object();
        const int IP_ENDPOINT_DEFAULT_TTL = 900;

        #endregion

        #region constructors

        public NameServerAddress(Uri dohEndPoint)
        {
            _dohEndPoint = dohEndPoint;

            if (IPAddress.TryParse(_dohEndPoint.Host, out IPAddress address))
                _ipEndPoint = new IPEndPoint(address, _dohEndPoint.Port);

            _originalAddress = _dohEndPoint.AbsoluteUri;
        }

        public NameServerAddress(Uri dohEndPoint, IPAddress address)
        {
            _dohEndPoint = dohEndPoint;
            _ipEndPoint = new IPEndPoint(address, _dohEndPoint.Port);

            if (address.AddressFamily == AddressFamily.InterNetworkV6)
                _originalAddress = _dohEndPoint.AbsoluteUri + " ([" + address.ToString() + "])";
            else
                _originalAddress = _dohEndPoint.AbsoluteUri + " (" + address.ToString() + ")";
        }

        public NameServerAddress(string address)
        {
            Parse(address.Trim());
        }

        public NameServerAddress(IPAddress address)
        {
            _ipEndPoint = new IPEndPoint(address, 53);

            _originalAddress = address.ToString();
        }

        public NameServerAddress(string domain, IPAddress address)
        {
            _domainEndPoint = new DomainEndPoint(domain, 53);
            _ipEndPoint = new IPEndPoint(address, 53);

            if (address.AddressFamily == AddressFamily.InterNetworkV6)
                _originalAddress = domain + " ([" + address.ToString() + "])";
            else
                _originalAddress = domain + " (" + address.ToString() + ")";
        }

        public NameServerAddress(string domain, IPEndPoint ipEndPoint)
        {
            _domainEndPoint = new DomainEndPoint(domain, ipEndPoint.Port);
            _ipEndPoint = ipEndPoint;

            if (ipEndPoint.AddressFamily == AddressFamily.InterNetworkV6)
                _originalAddress = domain + " ([" + ipEndPoint.Address.ToString() + "]:" + ipEndPoint.Port + ")";
            else
                _originalAddress = domain + " (" + ipEndPoint.ToString() + ")";
        }

        public NameServerAddress(EndPoint endPoint)
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

            if (endPoint.AddressFamily == AddressFamily.InterNetworkV6)
                _originalAddress = "[" + (endPoint as IPEndPoint).Address.ToString() + "]:" + (endPoint as IPEndPoint).Port;
            else
                _originalAddress = endPoint.ToString();
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

                    break;

                case 2:
                    Parse(bR.ReadShortString());
                    break;

                default:
                    throw new InvalidDataException("NameServerAddress version not supported");
            }
        }

        #endregion

        #region private

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

        public static NameServerAddress[] GetNameServersFromResponse(DnsDatagram response, bool preferIPv6, bool selectOnlyNameServersWithGlue)
        {
            List<NameServerAddress> nameServers = new List<NameServerAddress>(response.Authority.Length);

            DnsResourceRecord[] authorityRecords;

            if ((response.Question.Length > 0) && (response.Question[0].Type == DnsResourceRecordType.NS) && (response.Answer.Length > 0))
                authorityRecords = response.Answer;
            else
                authorityRecords = response.Authority;

            foreach (DnsResourceRecord authorityRecord in authorityRecords)
            {
                if (authorityRecord.Type == DnsResourceRecordType.NS)
                {
                    DnsNSRecord nsRecord = (DnsNSRecord)authorityRecord.RDATA;
                    IPEndPoint endPoint = null;

                    //find ip address of authoritative name server from additional records
                    foreach (DnsResourceRecord rr in response.Additional)
                    {
                        if (nsRecord.NSDomainName.Equals(rr.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (rr.Type)
                            {
                                case DnsResourceRecordType.A:
                                    endPoint = new IPEndPoint(((DnsARecord)rr.RDATA).Address, 53);
                                    nameServers.Add(new NameServerAddress(nsRecord.NSDomainName, endPoint));
                                    break;

                                case DnsResourceRecordType.AAAA:
                                    endPoint = new IPEndPoint(((DnsAAAARecord)rr.RDATA).Address, 53);

                                    if (preferIPv6)
                                        nameServers.Add(new NameServerAddress(nsRecord.NSDomainName, endPoint));

                                    break;
                            }
                        }
                    }

                    if ((endPoint == null) && !selectOnlyNameServersWithGlue)
                        nameServers.Add(new NameServerAddress(new DomainEndPoint(nsRecord.NSDomainName, 53)));
                }
            }

            NameServerAddress[] nsArray = nameServers.ToArray();

            DnsClient.ShuffleArray(nsArray);

            if (preferIPv6)
                Array.Sort(nsArray);

            return nsArray;
        }

        #endregion

        #region public

        public void ResolveIPAddress(NameServerAddress[] nameServers = null, NetProxy proxy = null, bool preferIPv6 = false, int retries = 2, int timeout = 2000, DnsTransportProtocol protocol = DnsTransportProtocol.Udp)
        {
            lock (_ipEndPointResolverLock)
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
                    _ipEndPoint = new IPEndPoint((preferIPv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback), this.Port);
                    return;
                }

                if (IPAddress.TryParse(domain, out IPAddress address))
                {
                    _ipEndPoint = new IPEndPoint(address, this.Port);
                    return;
                }

                DnsClient dnsClient;

                if (nameServers == null)
                    dnsClient = new DnsClient();
                else
                    dnsClient = new DnsClient(nameServers);

                dnsClient.Proxy = proxy;
                dnsClient.PreferIPv6 = preferIPv6;
                dnsClient.Protocol = protocol;
                dnsClient.Retries = retries;
                dnsClient.Timeout = timeout;

                IPAddress[] serverIPs = dnsClient.ResolveIP(domain, preferIPv6);

                if (serverIPs.Length == 0)
                    throw new DnsClientException("No IP address was found for name server: " + domain);

                _ipEndPoint = new IPEndPoint(serverIPs[0], this.Port);
                _ipEndPointExpires = true;
                _ipEndPointExpiresOn = DateTime.UtcNow.AddSeconds(IP_ENDPOINT_DEFAULT_TTL);
            }
        }

        public void RecursiveResolveIPAddress(DnsCache cache = null, NetProxy proxy = null, bool preferIPv6 = false, int retries = 2, int timeout = 2000, bool useTcp = false)
        {
            lock (_ipEndPointResolverLock)
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
                    _ipEndPoint = new IPEndPoint((preferIPv6 ? IPAddress.IPv6Loopback : IPAddress.Loopback), this.Port);
                    return;
                }

                if (IPAddress.TryParse(domain, out IPAddress address))
                {
                    _ipEndPoint = new IPEndPoint(address, this.Port);
                    return;
                }

                IPEndPoint ipEndPoint = null;

                IPAddress[] addresses = DnsClient.RecursiveResolveIP(domain, cache, proxy, preferIPv6, retries, timeout, useTcp);
                if (addresses.Length > 0)
                    ipEndPoint = new IPEndPoint(addresses[0], this.Port);

                if (ipEndPoint == null)
                    throw new DnsClientException("No IP address was found for name server: " + domain);

                _ipEndPoint = ipEndPoint;
                _ipEndPointExpires = true;
                _ipEndPointExpiresOn = DateTime.UtcNow.AddSeconds(IP_ENDPOINT_DEFAULT_TTL);
            }
        }

        public void ResolveDomainName(NameServerAddress[] nameServers = null, NetProxy proxy = null, bool preferIPv6 = false, int retries = 2, int timeout = 2000, DnsTransportProtocol protocol = DnsTransportProtocol.Udp)
        {
            if (_ipEndPoint != null)
            {
                DnsClient dnsClient;

                if (nameServers == null)
                    dnsClient = new DnsClient();
                else
                    dnsClient = new DnsClient(nameServers);

                dnsClient.Proxy = proxy;
                dnsClient.PreferIPv6 = preferIPv6;
                dnsClient.Protocol = protocol;
                dnsClient.Retries = retries;
                dnsClient.Timeout = timeout;

                try
                {
                    string domain = dnsClient.ResolvePTR(_ipEndPoint.Address);
                    _domainEndPoint = new DomainEndPoint(domain, _ipEndPoint.Port);
                }
                catch
                { }
            }
        }

        public void RecursiveResolveDomainName(DnsCache cache = null, NetProxy proxy = null, bool preferIPv6 = false, int retries = 2, int timeout = 2000, bool useTcp = false)
        {
            if (_ipEndPoint != null)
            {
                try
                {
                    string ptrDomain = DnsClient.ParseResponsePTR(DnsClient.RecursiveQuery(new DnsQuestionRecord(_ipEndPoint.Address, DnsClass.IN), cache, proxy, preferIPv6, retries, timeout, useTcp));
                    if (ptrDomain != null)
                        _domainEndPoint = new DomainEndPoint(ptrDomain, _ipEndPoint.Port);
                }
                catch
                { }
            }
        }

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)2); //version
            bW.WriteShortString(_originalAddress);
        }

        public override string ToString()
        {
            string value;

            if (_dohEndPoint != null)
                value = _dohEndPoint.AbsoluteUri;
            else if (_domainEndPoint != null)
                value = _domainEndPoint.ToString();
            else
                return _ipEndPoint.ToString();

            if (_ipEndPoint != null)
                value += " (" + _ipEndPoint.ToString() + ")";

            return value;
        }

        public int CompareTo(NameServerAddress other)
        {
            if ((this._ipEndPoint == null) || (other._ipEndPoint == null))
                return 0;

            if ((this._ipEndPoint.AddressFamily == AddressFamily.InterNetwork) && (other._ipEndPoint.AddressFamily == AddressFamily.InterNetworkV6))
                return 1;

            if ((this._ipEndPoint.AddressFamily == AddressFamily.InterNetworkV6) && (other._ipEndPoint.AddressFamily == AddressFamily.InterNetwork))
                return -1;

            return 0;
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            NameServerAddress other = obj as NameServerAddress;
            if (other == null)
                return false;

            if (!EqualityComparer<Uri>.Default.Equals(_dohEndPoint, other._dohEndPoint))
                return false;

            if (!EqualityComparer<DomainEndPoint>.Default.Equals(_domainEndPoint, other._domainEndPoint))
                return false;

            if (!EqualityComparer<IPEndPoint>.Default.Equals(_ipEndPoint, other._ipEndPoint))
                return false;

            return true;
        }

        public override int GetHashCode()
        {
            var hashCode = 563096372;
            hashCode = hashCode * -1521134295 + EqualityComparer<Uri>.Default.GetHashCode(_dohEndPoint);
            hashCode = hashCode * -1521134295 + EqualityComparer<DomainEndPoint>.Default.GetHashCode(_domainEndPoint);
            hashCode = hashCode * -1521134295 + EqualityComparer<IPEndPoint>.Default.GetHashCode(_ipEndPoint);
            hashCode = hashCode * -1521134295 + EqualityComparer<string>.Default.GetHashCode(_originalAddress);
            return hashCode;
        }

        #endregion

        #region properties

        public string OriginalString
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
