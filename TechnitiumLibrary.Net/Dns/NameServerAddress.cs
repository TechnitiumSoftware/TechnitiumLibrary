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
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns
{
    public class NameServerAddress
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

        public static NameServerAddress[] GetNameServersFromResponse(DnsDatagram response, bool preferIPv6, bool selectNameServersWithGlue)
        {
            List<NameServerAddress> nameServers = new List<NameServerAddress>(4);

            foreach (DnsResourceRecord authorityRecord in response.Authority)
            {
                if (authorityRecord.Type == DnsResourceRecordType.NS)
                {
                    DnsNSRecord nsRecord = (DnsNSRecord)authorityRecord.RDATA;
                    IPEndPoint endPoint = null;

                    //find ip address of authoritative name server from additional records
                    if (preferIPv6)
                    {
                        foreach (DnsResourceRecord rr in response.Additional)
                        {
                            if ((rr.Name.Equals(nsRecord.NSDomainName, StringComparison.CurrentCultureIgnoreCase)) && (rr.Type == DnsResourceRecordType.AAAA))
                            {
                                endPoint = new IPEndPoint(((DnsAAAARecord)rr.RDATA).Address, 53);
                                nameServers.Add(new NameServerAddress(nsRecord.NSDomainName, endPoint));
                            }
                        }
                    }

                    if (endPoint == null)
                    {
                        foreach (DnsResourceRecord rr in response.Additional)
                        {
                            if ((rr.Name.Equals(nsRecord.NSDomainName, StringComparison.CurrentCultureIgnoreCase)) && (rr.Type == DnsResourceRecordType.A))
                            {
                                endPoint = new IPEndPoint(((DnsARecord)rr.RDATA).Address, 53);
                                nameServers.Add(new NameServerAddress(nsRecord.NSDomainName, endPoint));
                            }
                        }
                    }

                    if ((endPoint == null) && !selectNameServersWithGlue)
                        nameServers.Add(new NameServerAddress(nsRecord.NSDomainName));
                }
            }

            return nameServers.ToArray();
        }

        #endregion

        #region public

        public void ResolveAddress(IDnsCache cache, NetProxy proxy, bool preferIPv6, bool tcp, int retries, int maxRecursionHops)
        {
            if ((_domain != null) && (_endPoint == null))
            {
                if (preferIPv6)
                {
                    try
                    {
                        DnsDatagram nsResponse = DnsClient.ResolveViaNameServers(new DnsQuestionRecord(_domain, DnsResourceRecordType.AAAA, DnsClass.IN), null, cache, proxy, true, tcp, retries, maxRecursionHops);
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
                        DnsDatagram nsResponse = DnsClient.ResolveViaNameServers(new DnsQuestionRecord(_domain, DnsResourceRecordType.A, DnsClass.IN), null, cache, proxy, false, tcp, retries, maxRecursionHops);
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

        #endregion

        #region properties

        public string Domain
        { get { return _domain; } }

        public IPEndPoint EndPoint
        { get { return _endPoint; } }

        #endregion
    }
}
