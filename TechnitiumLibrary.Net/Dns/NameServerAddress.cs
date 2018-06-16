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
using System.Net;
using System.Net.Sockets;

namespace TechnitiumLibrary.Net.Dns
{
    public class NameServerAddress : IComparable<NameServerAddress>
    {
        #region variables

        DomainEndPoint _domainEndPoint;
        IPEndPoint _ipEndPoint;

        #endregion

        #region constructors

        public NameServerAddress(string domain)
            : this(new DomainEndPoint(domain, 53), null as IPEndPoint)
        { }

        public NameServerAddress(DomainEndPoint domainEndPoint)
            : this(domainEndPoint, null)
        { }

        public NameServerAddress(IPAddress address)
            : this(null as DomainEndPoint, new IPEndPoint(address, 53))
        { }

        public NameServerAddress(IPEndPoint ipEndPoint)
            : this(null as DomainEndPoint, ipEndPoint)
        { }

        public NameServerAddress(string domain, IPAddress address)
            : this(new DomainEndPoint(domain, 53), new IPEndPoint(address, 53))
        { }

        public NameServerAddress(string domain, IPEndPoint ipEndPoint)
            : this(new DomainEndPoint(domain, ipEndPoint.Port), ipEndPoint)
        { }

        public NameServerAddress(EndPoint endPoint)
            : this(endPoint as DomainEndPoint, endPoint as IPEndPoint)
        { }

        public NameServerAddress(DomainEndPoint domainEndPoint, IPEndPoint ipEndPoint)
        {
            _domainEndPoint = domainEndPoint;
            _ipEndPoint = ipEndPoint;

            if ((_domainEndPoint == null) && (_ipEndPoint == null))
                throw new ArgumentNullException();

            if ((_domainEndPoint != null) && (_ipEndPoint != null))
            {
                if (_domainEndPoint.Port != _ipEndPoint.Port)
                    throw new ArgumentNullException();
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

        #region internal

        internal void ResolveAddress(IDnsCache cache, bool preferIPv6, DnsClientProtocol protocol, int retries)
        {
            if ((_domainEndPoint != null) && (_ipEndPoint == null))
            {
                if (preferIPv6)
                {
                    try
                    {
                        DnsDatagram nsResponse = DnsClient.ResolveViaNameServers(new DnsQuestionRecord(_domainEndPoint.Address, DnsResourceRecordType.AAAA, DnsClass.IN), null, cache, null, true, protocol, retries);
                        if ((nsResponse.Header.RCODE == DnsResponseCode.NoError) && (nsResponse.Answer.Length > 0) && (nsResponse.Answer[0].Type == DnsResourceRecordType.AAAA))
                            _ipEndPoint = new IPEndPoint((nsResponse.Answer[0].RDATA as DnsAAAARecord).Address, _domainEndPoint.Port);
                    }
                    catch
                    { }
                }

                if (_ipEndPoint == null)
                {
                    try
                    {
                        DnsDatagram nsResponse = DnsClient.ResolveViaNameServers(new DnsQuestionRecord(_domainEndPoint.Address, DnsResourceRecordType.A, DnsClass.IN), null, cache, null, false, protocol, retries);
                        if ((nsResponse.Header.RCODE == DnsResponseCode.NoError) && (nsResponse.Answer.Length > 0) && (nsResponse.Answer[0].Type == DnsResourceRecordType.A))
                            _ipEndPoint = new IPEndPoint((nsResponse.Answer[0].RDATA as DnsARecord).Address, _domainEndPoint.Port);
                    }
                    catch
                    { }
                }
            }
        }

        #endregion

        #region public

        public override string ToString()
        {
            if (_domainEndPoint == null)
                return _ipEndPoint.ToString();
            else if (_ipEndPoint == null)
                return _domainEndPoint.ToString();
            else
                return _domainEndPoint.ToString() + " (" + _ipEndPoint.ToString() + ")";
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

        public string Domain
        {
            get
            {
                if (_domainEndPoint == null)
                    return _ipEndPoint.Address.ToString();

                return _domainEndPoint.Address;
            }
        }

        public DomainEndPoint DomainEndPoint
        { get { return _domainEndPoint; } }

        public IPEndPoint IPEndPoint
        { get { return _ipEndPoint; } }

        public EndPoint EndPoint
        {
            get
            {
                if (_ipEndPoint != null)
                    return _ipEndPoint;

                return _domainEndPoint;
            }
        }

        #endregion
    }
}
