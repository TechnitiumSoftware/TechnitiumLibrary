/*
Technitium Library
Copyright (C) 2017  Shreyas Zare (shreyas@technitium.com)

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
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns
{
    public class NameServerAddress : IComparable<NameServerAddress>
    {
        #region variables

        string _domain;
        IPEndPoint _endPoint;

        #endregion

        #region constructors

        public NameServerAddress(IPAddress address)
            : this(null, new IPEndPoint(address, 53))
        { }

        public NameServerAddress(IPEndPoint endPoint)
            : this(null, endPoint)
        { }

        public NameServerAddress(string domain)
            : this(domain, null as IPEndPoint)
        { }

        public NameServerAddress(string domain, IPAddress address)
            : this(domain, new IPEndPoint(address, 53))
        { }

        public NameServerAddress(string domain, IPEndPoint endPoint)
        {
            _domain = domain;
            _endPoint = endPoint;

            if ((_domain == null) && (_endPoint == null))
                throw new ArgumentNullException();
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

        internal void ResolveAddress(IDnsCache cache, NetProxy proxy, bool preferIPv6, bool tcp, int retries)
        {
            if ((_domain != null) && (_endPoint == null))
            {
                if (preferIPv6)
                {
                    try
                    {
                        DnsDatagram nsResponse = DnsClient.ResolveViaNameServers(new DnsQuestionRecord(_domain, DnsResourceRecordType.AAAA, DnsClass.IN), null, cache, proxy, true, tcp, retries);
                        if ((nsResponse.Header.RCODE == DnsResponseCode.NoError) && (nsResponse.Answer.Length > 0) && (nsResponse.Answer[0].Type == DnsResourceRecordType.AAAA))
                            _endPoint = new IPEndPoint((nsResponse.Answer[0].RDATA as DnsAAAARecord).Address, 53);
                    }
                    catch
                    { }
                }

                if (_endPoint == null)
                {
                    try
                    {
                        DnsDatagram nsResponse = DnsClient.ResolveViaNameServers(new DnsQuestionRecord(_domain, DnsResourceRecordType.A, DnsClass.IN), null, cache, proxy, false, tcp, retries);
                        if ((nsResponse.Header.RCODE == DnsResponseCode.NoError) && (nsResponse.Answer.Length > 0) && (nsResponse.Answer[0].Type == DnsResourceRecordType.A))
                            _endPoint = new IPEndPoint((nsResponse.Answer[0].RDATA as DnsARecord).Address, 53);
                    }
                    catch
                    { }
                }
            }
        }

        public override string ToString()
        {
            if (_domain == null)
                return _endPoint.Address.ToString();
            else if (_endPoint == null)
                return _domain;
            else
                return _domain + " [" + _endPoint.Address.ToString() + "]";
        }

        public int CompareTo(NameServerAddress other)
        {
            if ((this._endPoint == null) && (other._endPoint != null))
                return 1;

            if ((this._endPoint != null) && (other._endPoint == null))
                return -1;

            if ((this._endPoint == null) && (other._endPoint == null))
                return 0;

            if ((this._endPoint.AddressFamily == AddressFamily.InterNetwork) && (other._endPoint.AddressFamily == AddressFamily.InterNetworkV6))
                return 1;

            if ((this._endPoint.AddressFamily == AddressFamily.InterNetworkV6) && (other._endPoint.AddressFamily == AddressFamily.InterNetwork))
                return -1;

            return 0;
        }

        #endregion

        #region properties

        public string Domain
        { get { return _domain; } }

        public IPEndPoint EndPoint
        { get { return _endPoint; } }

        #endregion
    }
}
