/*
Technitium Library
Copyright (C) 2018  Shreyas Zare (shreyas@technitium.com)

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

            _originalAddress = _dohEndPoint.AbsoluteUri;
        }

        public NameServerAddress(string address)
        {
            Parse(address);
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

            _originalAddress = domain;
        }

        public NameServerAddress(string domain, IPEndPoint ipEndPoint)
        {
            _domainEndPoint = new DomainEndPoint(domain, ipEndPoint.Port);
            _ipEndPoint = ipEndPoint;

            _originalAddress = domain + ":" + ipEndPoint.Port;
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

            if (address.StartsWith("https://", StringComparison.CurrentCultureIgnoreCase) || address.StartsWith("http://", StringComparison.CurrentCultureIgnoreCase))
            {
                _dohEndPoint = new Uri(address);
            }
            else if (address.StartsWith("["))
            {
                //ipv6
                int port = 53;

                if (address.EndsWith("]"))
                {
                    address = address.Trim('[', ']');
                }
                else
                {
                    int posBracket = address.LastIndexOf(']');
                    int posCollon = address.IndexOf(':', posBracket);

                    if (posCollon > -1)
                        port = int.Parse(address.Substring(posCollon + 1));

                    address = address.Substring(1, posBracket - 1);
                }

                _ipEndPoint = new IPEndPoint(IPAddress.Parse(address), port);
            }
            else
            {
                string[] strParts = address.Split(':');

                string host = strParts[0];
                int port = 53;

                if (strParts.Length > 1)
                    port = int.Parse(strParts[1]);

                if (IPAddress.TryParse(host, out IPAddress ipAddress))
                    _ipEndPoint = new IPEndPoint(ipAddress, port);
                else
                    _domainEndPoint = new DomainEndPoint(host, port);
            }
        }

        #endregion

        #region static

        internal static NameServerAddress[] GetNameServersFromResponse(DnsDatagram response, bool preferIPv6, bool selectOnlyNameServersWithGlue)
        {
            List<NameServerAddress> nameServers = new List<NameServerAddress>(4);

            foreach (DnsResourceRecord authorityRecord in response.Authority)
            {
                if (authorityRecord.Type == DnsResourceRecordType.NS)
                {
                    DnsNSRecord nsRecord = (DnsNSRecord)authorityRecord.RDATA;
                    IPEndPoint endPoint = null;

                    //find ip address of authoritative name server from additional records
                    foreach (DnsResourceRecord rr in response.Additional)
                    {
                        if (nsRecord.NSDomainName.Equals(rr.Name, StringComparison.CurrentCultureIgnoreCase))
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
                        nameServers.Add(new NameServerAddress(nsRecord.NSDomainName));
                }
            }

            NameServerAddress[] nsArray = nameServers.ToArray();

            Shuffle(nsArray);

            if (preferIPv6 || !selectOnlyNameServersWithGlue)
                Array.Sort(nsArray);

            return nsArray;
        }

        internal static void Shuffle<T>(T[] array)
        {
            Random rng = new Random();

            int n = array.Length;
            while (n > 1)
            {
                int k = rng.Next(n--);
                T temp = array[n];
                array[n] = array[k];
                array[k] = temp;
            }
        }

        #endregion

        #region public

        public void ResolveIPAddress(bool preferIPv6, DnsClientProtocol protocol, int retries)
        {
            string domain;

            if (_dohEndPoint != null)
                domain = _dohEndPoint.Host;
            else if (_domainEndPoint != null)
                domain = _domainEndPoint.Address;
            else
                return;

            IPAddress[] serverIPs = (new DnsClient() { PreferIPv6 = preferIPv6, Protocol = protocol, Retries = retries }).ResolveIP(domain, preferIPv6);

            if (serverIPs.Length == 0)
                throw new DnsClientException("No IP address was found for name server: " + domain);

            _ipEndPoint = new IPEndPoint(serverIPs[0], this.Port);
        }

        public void RecursiveResolveIPAddress(IDnsCache cache, NetProxy proxy, bool preferIPv6, DnsClientProtocol protocol, int retries)
        {
            string domain;

            if (_dohEndPoint != null)
                domain = _dohEndPoint.Host;
            else if (_domainEndPoint != null)
                domain = _domainEndPoint.Address;
            else
                return;

            if (preferIPv6)
            {
                DnsDatagram nsResponse = DnsClient.ResolveViaNameServers(new DnsQuestionRecord(domain, DnsResourceRecordType.AAAA, DnsClass.IN), null, cache, proxy, true, protocol, retries);
                if ((nsResponse.Header.RCODE == DnsResponseCode.NoError) && (nsResponse.Answer.Length > 0) && (nsResponse.Answer[0].Type == DnsResourceRecordType.AAAA))
                    _ipEndPoint = new IPEndPoint((nsResponse.Answer[0].RDATA as DnsAAAARecord).Address, this.Port);
            }

            if (_ipEndPoint == null)
            {
                DnsDatagram nsResponse = DnsClient.ResolveViaNameServers(new DnsQuestionRecord(domain, DnsResourceRecordType.A, DnsClass.IN), null, cache, proxy, false, protocol, retries);
                if ((nsResponse.Header.RCODE == DnsResponseCode.NoError) && (nsResponse.Answer.Length > 0) && (nsResponse.Answer[0].Type == DnsResourceRecordType.A))
                    _ipEndPoint = new IPEndPoint((nsResponse.Answer[0].RDATA as DnsARecord).Address, this.Port);
            }

            if (_ipEndPoint == null)
                throw new DnsClientException("No IP address was found for name server: " + domain);
        }

        public void ResolveDomainName(bool preferIPv6, DnsClientProtocol protocol, int retries)
        {
            if (_ipEndPoint != null)
            {
                try
                {
                    string domain = (new DnsClient() { PreferIPv6 = preferIPv6, Protocol = protocol, Retries = retries }).ResolvePTR(_ipEndPoint.Address);
                    _domainEndPoint = new DomainEndPoint(domain, _ipEndPoint.Port);
                }
                catch
                { }
            }
        }

        public void RecursiveResolveDomainName(IDnsCache cache, NetProxy proxy, DnsClientProtocol protocol, int retries)
        {
            if (_ipEndPoint != null)
            {
                try
                {
                    DnsDatagram nsResponse = DnsClient.ResolveViaNameServers(new DnsQuestionRecord(_ipEndPoint.Address, DnsClass.IN), null, cache, proxy, false, protocol, retries);
                    if ((nsResponse.Header.RCODE == DnsResponseCode.NoError) && (nsResponse.Answer.Length > 0) && (nsResponse.Answer[0].Type == DnsResourceRecordType.PTR))
                        _domainEndPoint = new DomainEndPoint((nsResponse.Answer[0].RDATA as DnsPTRRecord).PTRDomainName, _ipEndPoint.Port);
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
            if ((this._ipEndPoint == null) && (other._ipEndPoint != null))
                return 1;

            if ((this._ipEndPoint != null) && (other._ipEndPoint == null))
                return -1;

            if ((this._ipEndPoint == null) && (other._ipEndPoint == null))
                return 0;

            if ((this._ipEndPoint.AddressFamily == AddressFamily.InterNetwork) && (other._ipEndPoint.AddressFamily == AddressFamily.InterNetworkV6))
                return 1;

            if ((this._ipEndPoint.AddressFamily == AddressFamily.InterNetworkV6) && (other._ipEndPoint.AddressFamily == AddressFamily.InterNetwork))
                return -1;

            return 0;
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

        #endregion
    }
}
