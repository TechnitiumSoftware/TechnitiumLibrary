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

using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Mail;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns
{
    public enum DnsClientProtocol : byte
    {
        Udp = 0,
        Tcp = 1,
        Tls = 2,
        Https = 3, //IETF DoH draft
        HttpsJson = 4 //Google
    }

    public class DnsClient
    {
        #region variables

        public static readonly NameServerAddress[] ROOT_NAME_SERVERS_IPv4;
        public static readonly NameServerAddress[] ROOT_NAME_SERVERS_IPv6;

        public static DnsClientProtocol RecursiveResolveDefaultProtocol = DnsClientProtocol.Udp;

        readonly internal static RandomNumberGenerator _rnd = new RNGCryptoServiceProvider();

        const int MAX_HOPS = 16;

        readonly NameServerAddress[] _servers;

        NetProxy _proxy;
        bool _preferIPv6 = false;
        DnsClientProtocol _protocol = DnsClientProtocol.Udp;
        int _retries = 2;
        int _connectionTimeout = 2000;
        int _sendTimeout = 2000;
        int _recvTimeout = 2000;

        #endregion

        #region constructor

        static DnsClient()
        {
            ROOT_NAME_SERVERS_IPv4 = new NameServerAddress[]
            {
                new NameServerAddress("a.root-servers.net", IPAddress.Parse("198.41.0.4")), //VeriSign, Inc.
                new NameServerAddress("b.root-servers.net", IPAddress.Parse("192.228.79.201")), //University of Southern California (ISI)
                new NameServerAddress("c.root-servers.net", IPAddress.Parse("192.33.4.12")), //Cogent Communications
                new NameServerAddress("d.root-servers.net", IPAddress.Parse("199.7.91.13")), //University of Maryland
                new NameServerAddress("e.root-servers.net", IPAddress.Parse("192.203.230.10")), //NASA (Ames Research Center)
                new NameServerAddress("f.root-servers.net", IPAddress.Parse("192.5.5.241")), //Internet Systems Consortium, Inc.
                new NameServerAddress("g.root-servers.net", IPAddress.Parse("192.112.36.4")), //US Department of Defense (NIC)
                new NameServerAddress("h.root-servers.net", IPAddress.Parse("198.97.190.53")), //US Army (Research Lab)
                new NameServerAddress("i.root-servers.net", IPAddress.Parse("192.36.148.17")), //Netnod
                new NameServerAddress("j.root-servers.net", IPAddress.Parse("192.58.128.30")), //VeriSign, Inc.
                new NameServerAddress("k.root-servers.net", IPAddress.Parse("193.0.14.129")), //RIPE NCC
                new NameServerAddress("l.root-servers.net", IPAddress.Parse("199.7.83.42")), //ICANN
                new NameServerAddress("m.root-servers.net", IPAddress.Parse("202.12.27.33")) //WIDE Project
            };

            ROOT_NAME_SERVERS_IPv6 = new NameServerAddress[]
            {
                new NameServerAddress("a.root-servers.net", IPAddress.Parse("2001:503:ba3e::2:30")), //VeriSign, Inc.
                new NameServerAddress("b.root-servers.net", IPAddress.Parse("2001:500:84::b")), //University of Southern California (ISI)
                new NameServerAddress("c.root-servers.net", IPAddress.Parse("2001:500:2::c")), //Cogent Communications
                new NameServerAddress("d.root-servers.net", IPAddress.Parse("2001:500:2d::d")), //University of Maryland
                new NameServerAddress("e.root-servers.net", IPAddress.Parse("2001:500:a8::e")), //NASA (Ames Research Center)
                new NameServerAddress("f.root-servers.net", IPAddress.Parse("2001:500:2f::f")), //Internet Systems Consortium, Inc.
                new NameServerAddress("g.root-servers.net", IPAddress.Parse("2001:500:12::d0d")), //US Department of Defense (NIC)
                new NameServerAddress("h.root-servers.net", IPAddress.Parse("2001:500:1::53")), //US Army (Research Lab)
                new NameServerAddress("i.root-servers.net", IPAddress.Parse("2001:7fe::53")), //Netnod
                new NameServerAddress("j.root-servers.net", IPAddress.Parse("2001:503:c27::2:30")), //VeriSign, Inc.
                new NameServerAddress("k.root-servers.net", IPAddress.Parse("2001:7fd::1")), //RIPE NCC
                new NameServerAddress("l.root-servers.net", IPAddress.Parse("2001:500:9f::42")), //ICANN
                new NameServerAddress("m.root-servers.net", IPAddress.Parse("2001:dc3::35")) //WIDE Project
            };
        }

        public DnsClient(Uri dohEndPoint)
        {
            _servers = new NameServerAddress[] { new NameServerAddress(dohEndPoint) };
        }

        public DnsClient(Uri[] dohEndPoints)
        {
            if (dohEndPoints.Length == 0)
                throw new DnsClientException("At least one name server must be available for DnsClient.");

            _servers = new NameServerAddress[dohEndPoints.Length];

            for (int i = 0; i < dohEndPoints.Length; i++)
                _servers[i] = new NameServerAddress(dohEndPoints[i]);
        }

        public DnsClient(bool preferIPv6 = false)
        {
            _preferIPv6 = preferIPv6;

            NetworkInfo defaultNetworkInfo;

            if (_preferIPv6)
            {
                defaultNetworkInfo = NetUtilities.GetDefaultIPv6NetworkInfo();

                if ((defaultNetworkInfo == null) || (defaultNetworkInfo.Interface.GetIPProperties().DnsAddresses.Count == 0))
                    defaultNetworkInfo = NetUtilities.GetDefaultIPv4NetworkInfo();
            }
            else
            {
                defaultNetworkInfo = NetUtilities.GetDefaultIPv4NetworkInfo();
            }

            if (defaultNetworkInfo == null)
                throw new DnsClientException("No default network connection was found on this computer.");

            IPAddressCollection servers = defaultNetworkInfo.Interface.GetIPProperties().DnsAddresses;

            if (servers.Count == 0)
                throw new DnsClientException("Default network does not have any DNS server configured.");

            _servers = new NameServerAddress[servers.Count];

            for (int i = 0; i < servers.Count; i++)
                _servers[i] = new NameServerAddress(servers[i]);
        }

        public DnsClient(IPAddress[] servers)
        {
            if (servers.Length == 0)
                throw new DnsClientException("At least one name server must be available for DnsClient.");

            _servers = new NameServerAddress[servers.Length];

            for (int i = 0; i < servers.Length; i++)
                _servers[i] = new NameServerAddress(servers[i]);
        }

        public DnsClient(IPAddress server)
            : this(new NameServerAddress(server))
        { }

        public DnsClient(IPEndPoint server)
            : this(new NameServerAddress(server))
        { }

        public DnsClient(string server)
            : this(new NameServerAddress(server))
        { }

        public DnsClient(DomainEndPoint server)
            : this(new NameServerAddress(server))
        { }

        public DnsClient(NameServerAddress server)
        {
            _servers = new NameServerAddress[] { server };
        }

        public DnsClient(NameServerAddress[] servers)
        {
            if (servers.Length == 0)
                throw new DnsClientException("Atleast one name server must be available for DnsClient.");

            _servers = servers;
        }

        #endregion

        #region static

        public static DnsDatagram ResolveViaRootNameServers(string domain, DnsResourceRecordType queryType, IDnsCache cache = null, NetProxy proxy = null, bool preferIPv6 = false, DnsClientProtocol protocol = DnsClientProtocol.Udp, int retries = 2, int maxStackCount = 10)
        {
            return ResolveViaNameServers(domain, queryType, null, cache, proxy, preferIPv6, protocol, retries, maxStackCount);
        }

        public static DnsDatagram ResolveViaNameServers(string domain, DnsResourceRecordType queryType, NameServerAddress[] nameServers = null, IDnsCache cache = null, NetProxy proxy = null, bool preferIPv6 = false, DnsClientProtocol protocol = DnsClientProtocol.Udp, int retries = 2, int maxStackCount = 10)
        {
            DnsQuestionRecord question;

            if (queryType == DnsResourceRecordType.PTR)
                question = new DnsQuestionRecord(IPAddress.Parse(domain), DnsClass.IN);
            else
                question = new DnsQuestionRecord(domain, queryType, DnsClass.IN);

            return ResolveViaNameServers(question, nameServers, cache, proxy, preferIPv6, protocol, retries, maxStackCount);
        }

        public static DnsDatagram ResolveViaNameServers(DnsQuestionRecord question, NameServerAddress[] nameServers = null, IDnsCache cache = null, NetProxy proxy = null, bool preferIPv6 = false, DnsClientProtocol protocol = DnsClientProtocol.Udp, int retries = 2, int maxStackCount = 10)
        {
            if ((nameServers != null) && (nameServers.Length > 0))
            {
                //create copy of name servers array so that the values in original array are not messed due to shuffling feature
                NameServerAddress[] nameServersCopy = new NameServerAddress[nameServers.Length];
                Array.Copy(nameServers, nameServersCopy, nameServers.Length);
                nameServers = nameServersCopy;
            }

            Stack<ResolverData> resolverStack = new Stack<ResolverData>();
            int stackNameServerIndex = 0;

            while (true) //stack loop
            {
                if (resolverStack.Count > maxStackCount)
                {
                    while (resolverStack.Count > 0)
                    {
                        ResolverData data = resolverStack.Pop();

                        question = data.Question;
                    }

                    throw new DnsClientException("DnsClient exceeded the maximum stack count to resolve the domain: " + question.Name);
                }

                if (cache != null)
                {
                    DnsDatagram request = new DnsDatagram(new DnsHeader(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, 1, 0, 0, 0), new DnsQuestionRecord[] { question }, null, null, null);
                    DnsDatagram cacheResponse = cache.Query(request);

                    switch (cacheResponse.Header.RCODE)
                    {
                        case DnsResponseCode.NoError:
                            if (cacheResponse.Answer.Length > 0)
                            {
                                if (resolverStack.Count == 0)
                                {
                                    return cacheResponse;
                                }
                                else
                                {
                                    ResolverData data = resolverStack.Pop();

                                    question = data.Question;
                                    nameServers = data.NameServers;
                                    stackNameServerIndex = data.NameServerIndex;
                                    protocol = data.Protocol;

                                    switch (cacheResponse.Answer[0].Type)
                                    {
                                        case DnsResourceRecordType.AAAA:
                                            switch (protocol)
                                            {
                                                case DnsClientProtocol.Https:
                                                case DnsClientProtocol.HttpsJson:
                                                    nameServers[stackNameServerIndex] = new NameServerAddress(nameServers[stackNameServerIndex].DnsOverHttpEndPoint, (cacheResponse.Answer[0].RDATA as DnsAAAARecord).Address);
                                                    break;

                                                default:
                                                    nameServers[stackNameServerIndex] = new NameServerAddress(nameServers[stackNameServerIndex].Domain, (cacheResponse.Answer[0].RDATA as DnsAAAARecord).Address);
                                                    break;
                                            }

                                            break;

                                        case DnsResourceRecordType.A:
                                            switch (protocol)
                                            {
                                                case DnsClientProtocol.Https:
                                                case DnsClientProtocol.HttpsJson:
                                                    nameServers[stackNameServerIndex] = new NameServerAddress(nameServers[stackNameServerIndex].DnsOverHttpEndPoint, (cacheResponse.Answer[0].RDATA as DnsARecord).Address);
                                                    break;

                                                default:
                                                    nameServers[stackNameServerIndex] = new NameServerAddress(nameServers[stackNameServerIndex].Domain, (cacheResponse.Answer[0].RDATA as DnsARecord).Address);
                                                    break;
                                            }

                                            break;

                                        default:
                                            //didnt find IP for current name server
                                            stackNameServerIndex++; //increment to skip current name server
                                            break;
                                    }

                                    continue; //stack loop
                                }
                            }

                            if (cacheResponse.Authority.Length > 0)
                            {
                                if (cacheResponse.Authority[0].Type == DnsResourceRecordType.SOA)
                                {
                                    if (resolverStack.Count == 0)
                                    {
                                        return cacheResponse;
                                    }
                                    else
                                    {
                                        if (question.Type == DnsResourceRecordType.AAAA)
                                        {
                                            question = new DnsQuestionRecord(question.Name, DnsResourceRecordType.A, question.Class);
                                        }
                                        else
                                        {
                                            //didnt find IP for current name server
                                            //pop and try next name server
                                            ResolverData data = resolverStack.Pop();

                                            question = data.Question;
                                            nameServers = data.NameServers;
                                            stackNameServerIndex = data.NameServerIndex + 1; //increment to skip current name server
                                            protocol = data.Protocol;
                                        }

                                        continue; //to stack loop
                                    }
                                }

                                if ((nameServers == null) || (nameServers.Length == 0))
                                {
                                    NameServerAddress[] cacheNameServers = NameServerAddress.GetNameServersFromResponse(cacheResponse, preferIPv6, true);

                                    if (cacheNameServers.Length > 0)
                                        nameServers = cacheNameServers;
                                }
                            }

                            break;

                        case DnsResponseCode.NameError:
                            if (resolverStack.Count == 0)
                            {
                                return cacheResponse;
                            }
                            else
                            {
                                //current name server domain doesnt exists
                                //pop and try next name server
                                ResolverData data = resolverStack.Pop();

                                question = data.Question;
                                nameServers = data.NameServers;
                                stackNameServerIndex = data.NameServerIndex + 1; //increment to skip current name server
                                protocol = data.Protocol;

                                continue; //stack loop
                            }
                    }
                }

                if ((nameServers == null) || (nameServers.Length == 0))
                {
                    //create copy of root name servers array so that the values in original array are not messed due to shuffling feature
                    if (preferIPv6)
                    {
                        nameServers = new NameServerAddress[ROOT_NAME_SERVERS_IPv6.Length];
                        Array.Copy(ROOT_NAME_SERVERS_IPv6, nameServers, ROOT_NAME_SERVERS_IPv6.Length);
                    }
                    else
                    {
                        nameServers = new NameServerAddress[ROOT_NAME_SERVERS_IPv4.Length];
                        Array.Copy(ROOT_NAME_SERVERS_IPv4, nameServers, ROOT_NAME_SERVERS_IPv4.Length);
                    }
                }

                NameServerAddress.Shuffle(nameServers);

                int hopCount = 0;
                while ((hopCount++) < MAX_HOPS) //resolver loop
                {
                    //copy and reset stack name server index since its one time use only after stack pop
                    int i = stackNameServerIndex;
                    stackNameServerIndex = 0;

                    Exception lastException = null;

                    //query name servers one by one
                    for (; i < nameServers.Length; i++) //retry next server loop
                    {
                        NameServerAddress currentNameServer = nameServers[i];

                        if ((currentNameServer.IPEndPoint == null) && (proxy == null))
                        {
                            resolverStack.Push(new ResolverData(question, nameServers, i, protocol));

                            if (preferIPv6)
                                question = new DnsQuestionRecord(currentNameServer.Domain, DnsResourceRecordType.AAAA, question.Class);
                            else
                                question = new DnsQuestionRecord(currentNameServer.Domain, DnsResourceRecordType.A, question.Class);

                            nameServers = null;
                            protocol = RecursiveResolveDefaultProtocol;

                            goto stackLoop;
                        }

                        DnsClient client = new DnsClient(currentNameServer);

                        client._proxy = proxy;
                        client._preferIPv6 = preferIPv6;
                        client._protocol = protocol;
                        client._retries = retries;

                        DnsDatagram request = new DnsDatagram(new DnsHeader(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, 1, 0, 0, 0), new DnsQuestionRecord[] { question }, null, null, null);
                        DnsDatagram response;

                        try
                        {
                            response = client.Resolve(request);
                        }
                        catch (DnsClientException ex)
                        {
                            lastException = ex;
                            continue; //resolver loop
                        }

                        if (response.Header.Truncation)
                        {
                            if (protocol == DnsClientProtocol.Udp)
                            {
                                client.Protocol = DnsClientProtocol.Tcp;
                                response = client.Resolve(request);
                            }
                            else
                            {
                                return response;
                            }
                        }

                        if (cache != null)
                            cache.CacheResponse(response);

                        switch (response.Header.RCODE)
                        {
                            case DnsResponseCode.NoError:
                                if (response.Answer.Length > 0)
                                {
                                    if (!response.Answer[0].Name.Equals(question.Name, StringComparison.CurrentCultureIgnoreCase))
                                        continue; //continue to next name server since current name server may be misconfigured

                                    if (resolverStack.Count == 0)
                                    {
                                        return response;
                                    }
                                    else
                                    {
                                        ResolverData data = resolverStack.Pop();

                                        question = data.Question;
                                        nameServers = data.NameServers;
                                        stackNameServerIndex = data.NameServerIndex;
                                        protocol = data.Protocol;

                                        switch (response.Answer[0].Type)
                                        {
                                            case DnsResourceRecordType.AAAA:
                                                switch (protocol)
                                                {
                                                    case DnsClientProtocol.Https:
                                                    case DnsClientProtocol.HttpsJson:
                                                        nameServers[stackNameServerIndex] = new NameServerAddress(nameServers[stackNameServerIndex].DnsOverHttpEndPoint, (response.Answer[0].RDATA as DnsAAAARecord).Address);
                                                        break;

                                                    default:
                                                        nameServers[stackNameServerIndex] = new NameServerAddress(nameServers[stackNameServerIndex].Domain, (response.Answer[0].RDATA as DnsAAAARecord).Address);
                                                        break;
                                                }

                                                break;

                                            case DnsResourceRecordType.A:
                                                switch (protocol)
                                                {
                                                    case DnsClientProtocol.Https:
                                                    case DnsClientProtocol.HttpsJson:
                                                        nameServers[stackNameServerIndex] = new NameServerAddress(nameServers[stackNameServerIndex].DnsOverHttpEndPoint, (response.Answer[0].RDATA as DnsARecord).Address);
                                                        break;

                                                    default:
                                                        nameServers[stackNameServerIndex] = new NameServerAddress(nameServers[stackNameServerIndex].Domain, (response.Answer[0].RDATA as DnsARecord).Address);
                                                        break;
                                                }

                                                break;

                                            default:
                                                //didnt find IP for current name server
                                                stackNameServerIndex++; //increment to skip current name server
                                                break;
                                        }

                                        goto resolverLoop;
                                    }
                                }

                                if (response.Authority.Length == 0)
                                    continue; //continue to next name server since current name server may be misconfigured

                                if (response.Authority[0].Type == DnsResourceRecordType.SOA)
                                {
                                    //no entry for given type
                                    if (resolverStack.Count == 0)
                                    {
                                        return response;
                                    }
                                    else
                                    {
                                        if (question.Type == DnsResourceRecordType.AAAA)
                                        {
                                            question = new DnsQuestionRecord(question.Name, DnsResourceRecordType.A, question.Class);
                                        }
                                        else
                                        {
                                            //didnt find IP for current name server
                                            //pop and try next name server
                                            ResolverData data = resolverStack.Pop();

                                            question = data.Question;
                                            nameServers = data.NameServers;
                                            stackNameServerIndex = data.NameServerIndex + 1; //increment to skip current name server
                                            protocol = data.Protocol;
                                        }

                                        goto stackLoop; //goto stack loop
                                    }
                                }

                                nameServers = NameServerAddress.GetNameServersFromResponse(response, preferIPv6, false);

                                if (nameServers.Length == 0)
                                    continue; //continue to next name server since current name server may be misconfigured

                                goto resolverLoop;

                            case DnsResponseCode.NameError:
                                if (resolverStack.Count == 0)
                                {
                                    return response;
                                }
                                else
                                {
                                    //current name server domain doesnt exists
                                    //pop and try next name server
                                    ResolverData data = resolverStack.Pop();

                                    question = data.Question;
                                    nameServers = data.NameServers;
                                    stackNameServerIndex = data.NameServerIndex + 1; //increment to skip current name server
                                    protocol = data.Protocol;

                                    goto stackLoop; //goto stack loop
                                }

                            default:
                                continue; //continue to next name server since current name server may be misconfigured
                        }
                    }

                    if (resolverStack.Count == 0)
                    {
                        throw new DnsClientException("DnsClient failed to resolve the request: no response from name servers.", lastException);
                    }
                    else
                    {
                        //didnt find IP for current name server
                        //pop and try next name server
                        ResolverData data = resolverStack.Pop();

                        question = data.Question;
                        nameServers = data.NameServers;
                        stackNameServerIndex = data.NameServerIndex + 1; //increment to skip current name server
                        protocol = data.Protocol;

                        break; //to stack loop
                    }

                    resolverLoop:;
                }

                stackLoop:;
            }
        }

        #endregion

        #region public

        public DnsDatagram Resolve(DnsDatagram request)
        {
            int bytesRecv;
            byte[] responseBuffer = null;
            int nextServerIndex = 0;
            int retries = _retries;
            byte[] requestBuffer;
            IDnsCache dnsCache = null;
            Exception lastException = null;

            //serialize request
            if (_protocol == DnsClientProtocol.HttpsJson)
            {
                //no serialization needed
                requestBuffer = null;
            }
            else
            {
                using (MemoryStream mS = new MemoryStream(32))
                {
                    switch (_protocol)
                    {
                        case DnsClientProtocol.Https:
                            //write dns datagram
                            request.WriteTo(mS);

                            requestBuffer = mS.ToArray();
                            break;

                        default:
                            //16 bit length placeholder
                            mS.Position = 2;

                            //write dns datagram
                            request.WriteTo(mS);

                            requestBuffer = mS.ToArray();

                            //update 16 bit length in network byte order
                            byte[] length = BitConverter.GetBytes(Convert.ToUInt16(requestBuffer.Length - 2));
                            requestBuffer[0] = length[1];
                            requestBuffer[1] = length[0];
                            break;
                    }
                }
            }

            //init server selection parameters
            if (_servers.Length > 1)
            {
                retries = retries * _servers.Length; //retries on per server basis

                byte[] select = new byte[1];
                _rnd.GetBytes(select);

                nextServerIndex = select[0] % _servers.Length;
            }

            int retry = 0;
            while (retry < retries)
            {
                //select server
                NameServerAddress server;

                if (_servers.Length > 1)
                {
                    server = _servers[nextServerIndex];
                    nextServerIndex = (nextServerIndex + 1) % _servers.Length;
                }
                else
                {
                    server = _servers[0];
                }

                if ((server.IPEndPoint == null) && (_proxy == null))
                {
                    if (dnsCache == null)
                        dnsCache = new SimpleDnsCache();

                    //recursive resolve name server via root servers
                    server.RecursiveResolveIPAddress(dnsCache, _preferIPv6, RecursiveResolveDefaultProtocol, _retries);

                    if (server.IPEndPoint == null)
                    {
                        retry++;
                        continue;
                    }
                }

                //query server
                Socket _socket = null;
                SocksUdpAssociateRequestHandler proxyUdpRequestHandler = null;

                try
                {
                    retry++;

                    DateTime sentAt = DateTime.UtcNow;
                    DnsClientProtocol protocolUsed;

                    switch (_protocol)
                    {
                        case DnsClientProtocol.Https:
                            #region http

                            using (WebClientEx wC = new WebClientEx())
                            {
                                wC.AddHeader("content-type", "application/dns-message");
                                wC.AddHeader("accept", "application/dns-message");
                                wC.AddHeader("host", server.DomainEndPoint.ToString());
                                wC.UserAgent = "Technitium DNS Client";
                                wC.Proxy = _proxy;

                                if (_proxy == null)
                                    responseBuffer = wC.UploadData(new Uri(server.DnsOverHttpEndPoint.Scheme + "://" + server.IPEndPoint.ToString() + server.DnsOverHttpEndPoint.PathAndQuery), requestBuffer);
                                else
                                    responseBuffer = wC.UploadData(server.DnsOverHttpEndPoint, requestBuffer);

                                bytesRecv = responseBuffer.Length;
                            }

                            protocolUsed = DnsClientProtocol.Https;

                            #endregion
                            break;

                        case DnsClientProtocol.HttpsJson:
                            #region http json

                            using (WebClientEx wC = new WebClientEx())
                            {
                                wC.AddHeader("accept", "application/dns-json");
                                wC.AddHeader("host", server.DomainEndPoint.ToString());
                                wC.UserAgent = "Technitium DNS Client";
                                wC.Proxy = _proxy;

                                Uri queryUri;

                                if (_proxy == null)
                                    queryUri = new Uri(server.DnsOverHttpEndPoint.Scheme + "://" + server.IPEndPoint.ToString() + server.DnsOverHttpEndPoint.PathAndQuery);
                                else
                                    queryUri = server.DnsOverHttpEndPoint;

                                wC.QueryString.Clear();
                                wC.QueryString.Add("name", request.Question[0].Name);
                                wC.QueryString.Add("type", Convert.ToString(((int)request.Question[0].Type)));

                                responseBuffer = wC.DownloadData(queryUri);
                                bytesRecv = responseBuffer.Length;
                            }

                            protocolUsed = DnsClientProtocol.HttpsJson;

                            #endregion
                            break;

                        default:
                            #region standard dns

                            //connect
                            if (_proxy == null)
                            {
                                if (_protocol == DnsClientProtocol.Udp)
                                {
                                    _socket = new Socket(server.IPEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);

                                    _socket.SendTimeout = _sendTimeout;
                                    _socket.ReceiveTimeout = _recvTimeout;
                                }
                                else
                                {
                                    _socket = new Socket(server.IPEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                                    _socket.NoDelay = true;
                                    _socket.SendTimeout = _sendTimeout;
                                    _socket.ReceiveTimeout = _recvTimeout;

                                    IAsyncResult result = _socket.BeginConnect(server.IPEndPoint, null, null);
                                    if (!result.AsyncWaitHandle.WaitOne(_connectionTimeout))
                                        throw new SocketException((int)SocketError.TimedOut);

                                    if (!_socket.Connected)
                                        throw new SocketException((int)SocketError.ConnectionRefused);
                                }

                                protocolUsed = _protocol;
                            }
                            else
                            {
                                switch (_proxy.Type)
                                {
                                    case NetProxyType.Http:
                                        _socket = _proxy.HttpProxy.Connect(server.EndPoint, _connectionTimeout);

                                        _socket.NoDelay = true;
                                        _socket.SendTimeout = _sendTimeout;
                                        _socket.ReceiveTimeout = _recvTimeout;

                                        protocolUsed = DnsClientProtocol.Tcp;
                                        break;

                                    case NetProxyType.Socks5:
                                        if (_protocol == DnsClientProtocol.Udp)
                                        {
                                            try
                                            {
                                                proxyUdpRequestHandler = _proxy.SocksProxy.UdpAssociate(_connectionTimeout);
                                                proxyUdpRequestHandler.ReceiveTimeout = _recvTimeout;

                                                protocolUsed = DnsClientProtocol.Udp;
                                                break;
                                            }
                                            catch (SocksClientException)
                                            { }
                                        }

                                        using (SocksConnectRequestHandler requestHandler = _proxy.SocksProxy.Connect(server.EndPoint, _connectionTimeout))
                                        {
                                            _socket = requestHandler.GetSocket();

                                            _socket.NoDelay = true;
                                            _socket.SendTimeout = _sendTimeout;
                                            _socket.ReceiveTimeout = _recvTimeout;

                                            protocolUsed = DnsClientProtocol.Tcp;
                                        }

                                        break;

                                    default:
                                        throw new NotSupportedException("Proxy type not supported by DnsClient.");
                                }
                            }

                            //query
                            if (protocolUsed != DnsClientProtocol.Udp)
                            {
                                Stream stream;

                                if (_protocol == DnsClientProtocol.Tls)
                                {
                                    SslStream ssl = new SslStream(new NetworkStream(_socket));
                                    ssl.AuthenticateAsClient(server.Domain);
                                    stream = ssl;

                                    protocolUsed = DnsClientProtocol.Tls;
                                }
                                else
                                {
                                    stream = new NetworkStream(_socket);
                                }

                                //send request
                                stream.Write(requestBuffer);

                                //read response
                                byte[] lengthBuffer = stream.ReadBytes(2);
                                Array.Reverse(lengthBuffer, 0, 2);
                                int length = BitConverter.ToUInt16(lengthBuffer, 0);

                                if ((responseBuffer == null) || (responseBuffer.Length < length))
                                    responseBuffer = new byte[length];

                                stream.ReadBytes(responseBuffer, 0, length);
                                bytesRecv = length;
                            }
                            else
                            {
                                if (responseBuffer == null)
                                    responseBuffer = new byte[512];

                                EndPoint remoteEP = null;

                                if (proxyUdpRequestHandler == null)
                                {
                                    _socket.SendTo(requestBuffer, 2, requestBuffer.Length - 2, SocketFlags.None, server.IPEndPoint);

                                    if (server.IPEndPoint.AddressFamily == AddressFamily.InterNetworkV6)
                                        remoteEP = new IPEndPoint(IPAddress.IPv6Any, 0);
                                    else
                                        remoteEP = new IPEndPoint(IPAddress.Any, 0);

                                    do
                                    {
                                        bytesRecv = _socket.ReceiveFrom(responseBuffer, ref remoteEP);
                                    } while (!server.IPEndPoint.Equals(remoteEP));
                                }
                                else
                                {
                                    proxyUdpRequestHandler.SendTo(requestBuffer, 2, requestBuffer.Length - 2, server.EndPoint);

                                    bytesRecv = proxyUdpRequestHandler.ReceiveFrom(responseBuffer, 0, responseBuffer.Length, out remoteEP);
                                }
                            }

                            #endregion
                            break;
                    }

                    //parse response
                    if (protocolUsed == DnsClientProtocol.HttpsJson)
                    {
                        dynamic jsonResponse = JsonConvert.DeserializeObject(Encoding.ASCII.GetString(responseBuffer, 0, bytesRecv));

                        return new DnsDatagram(jsonResponse, bytesRecv, server, protocolUsed, (DateTime.UtcNow - sentAt).TotalMilliseconds);
                    }
                    else
                    {
                        using (MemoryStream mS = new MemoryStream(responseBuffer, 0, bytesRecv, false))
                        {
                            DnsDatagram response = new DnsDatagram(mS, server, protocolUsed, (DateTime.UtcNow - sentAt).TotalMilliseconds);

                            if (response.Header.Identifier == request.Header.Identifier)
                                return response;
                        }
                    }
                }
                catch (IOException ex)
                {
                    lastException = ex;
                }
                catch (SocketException ex)
                {
                    lastException = ex;
                }
                finally
                {
                    if (_socket != null)
                        _socket.Dispose();

                    if (proxyUdpRequestHandler != null)
                        proxyUdpRequestHandler.Dispose();
                }
            }

            throw new DnsClientException("DnsClient failed to resolve the request: no response from name servers.", lastException);
        }

        public DnsDatagram Resolve(DnsQuestionRecord questionRecord)
        {
            return Resolve(new DnsDatagram(new DnsHeader(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, 1, 0, 0, 0), new DnsQuestionRecord[] { questionRecord }, null, null, null));
        }

        public DnsDatagram Resolve(string domain, DnsResourceRecordType queryType)
        {
            if (queryType == DnsResourceRecordType.PTR)
                return Resolve(new DnsQuestionRecord(IPAddress.Parse(domain), DnsClass.IN));
            else
                return Resolve(new DnsQuestionRecord(domain, queryType, DnsClass.IN));
        }

        public string[] ResolveMX(MailAddress emailAddress, bool resolveIP = false, bool preferIPv6 = false)
        {
            return ResolveMX(emailAddress.Host, resolveIP, preferIPv6);
        }

        public string[] ResolveMX(string domain, bool resolveIP = false, bool preferIPv6 = false)
        {
            if (IPAddress.TryParse(domain, out IPAddress parsedIP))
            {
                //host is valid ip address
                return new string[] { domain };
            }

            int hopCount = 0;

            while ((hopCount++) < MAX_HOPS)
            {
                DnsDatagram response = Resolve(new DnsQuestionRecord(domain, DnsResourceRecordType.MX, DnsClass.IN));

                switch (response.Header.RCODE)
                {
                    case DnsResponseCode.NoError:
                        if (response.Header.ANCOUNT == 0)
                            return new string[] { };

                        List<DnsMXRecord> mxRecordsList = new List<DnsMXRecord>();

                        foreach (DnsResourceRecord record in response.Answer)
                        {
                            if (record.Name.Equals(domain, StringComparison.CurrentCultureIgnoreCase))
                            {
                                switch (record.Type)
                                {
                                    case DnsResourceRecordType.MX:
                                        mxRecordsList.Add((DnsMXRecord)record.RDATA);
                                        break;

                                    case DnsResourceRecordType.CNAME:
                                        domain = ((DnsCNAMERecord)record.RDATA).CNAMEDomainName;
                                        break;

                                    default:
                                        throw new DnsClientException("Name server [" + response.NameServerAddress.ToString() + "] returned unexpected record type [" + record.Type.ToString() + "] for domain: " + domain);
                                }
                            }
                        }

                        if (mxRecordsList.Count > 0)
                        {
                            DnsMXRecord[] mxRecords = mxRecordsList.ToArray();

                            //sort by mx preference
                            Array.Sort(mxRecords);

                            if (resolveIP)
                            {
                                List<string> mxEntries = new List<string>();

                                //check glue records
                                for (int i = 0; i < mxRecords.Length; i++)
                                {
                                    string mxDomain = mxRecords[i].Exchange;
                                    bool glueRecordFound = false;

                                    foreach (DnsResourceRecord record in response.Additional)
                                    {
                                        if (record.Name.Equals(mxDomain, StringComparison.CurrentCultureIgnoreCase))
                                        {
                                            switch (record.Type)
                                            {
                                                case DnsResourceRecordType.A:
                                                    if (!preferIPv6)
                                                    {
                                                        mxEntries.Add(((DnsARecord)record.RDATA).Address.ToString());
                                                        glueRecordFound = true;
                                                    }
                                                    break;

                                                case DnsResourceRecordType.AAAA:
                                                    if (preferIPv6)
                                                    {
                                                        mxEntries.Add(((DnsAAAARecord)record.RDATA).Address.ToString());
                                                        glueRecordFound = true;
                                                    }
                                                    break;
                                            }
                                        }
                                    }

                                    if (!glueRecordFound)
                                    {
                                        try
                                        {
                                            IPAddress[] ipList = ResolveIP(mxDomain, preferIPv6);

                                            foreach (IPAddress ip in ipList)
                                                mxEntries.Add(ip.ToString());
                                        }
                                        catch (NameErrorDnsClientException)
                                        { }
                                        catch (DnsClientException)
                                        {
                                            mxEntries.Add(mxDomain);
                                        }
                                    }
                                }

                                return mxEntries.ToArray();
                            }
                            else
                            {
                                string[] mxEntries = new string[mxRecords.Length];

                                for (int i = 0; i < mxRecords.Length; i++)
                                    mxEntries[i] = mxRecords[i].Exchange;

                                return mxEntries;
                            }
                        }

                        break;

                    case DnsResponseCode.NameError:
                        throw new NameErrorDnsClientException("Domain does not exists: " + domain + "; Name server: " + response.NameServerAddress.ToString());

                    default:
                        throw new DnsClientException("Name server returned error. DNS RCODE: " + response.Header.RCODE.ToString() + " (" + response.Header.RCODE + ")");
                }
            }

            throw new DnsClientException("No answer received from name server for domain: " + domain);
        }

        public string ResolvePTR(IPAddress ip)
        {
            DnsDatagram response = Resolve(new DnsQuestionRecord(ip, DnsClass.IN));

            switch (response.Header.RCODE)
            {
                case DnsResponseCode.NoError:
                    if ((response.Header.ANCOUNT > 0) && (response.Answer[0].Type == DnsResourceRecordType.PTR))
                        return ((DnsPTRRecord)response.Answer[0].RDATA).PTRDomainName;

                    return null;

                case DnsResponseCode.NameError:
                    throw new NameErrorDnsClientException("PTR record does not exists for ip: " + ip.ToString() + "; Name server: " + response.NameServerAddress.ToString());

                default:
                    throw new DnsClientException("Name server returned error. DNS RCODE: " + response.Header.RCODE.ToString() + " (" + response.Header.RCODE + ")");
            }
        }

        public IPAddress[] ResolveIP(string domain, bool preferIPv6 = false)
        {
            int hopCount = 0;
            DnsResourceRecordType type = preferIPv6 ? DnsResourceRecordType.AAAA : DnsResourceRecordType.A;

            while ((hopCount++) < MAX_HOPS)
            {
                DnsDatagram response = Resolve(new DnsQuestionRecord(domain, type, DnsClass.IN));

                switch (response.Header.RCODE)
                {
                    case DnsResponseCode.NoError:
                        if (response.Header.ANCOUNT == 0)
                        {
                            if (type == DnsResourceRecordType.AAAA)
                            {
                                type = DnsResourceRecordType.A;
                                continue;
                            }

                            return new IPAddress[] { };
                        }

                        List<IPAddress> ipAddresses = new List<IPAddress>();

                        foreach (DnsResourceRecord record in response.Answer)
                        {
                            if (record.Name.Equals(domain, StringComparison.CurrentCultureIgnoreCase))
                            {
                                switch (record.Type)
                                {
                                    case DnsResourceRecordType.A:
                                        ipAddresses.Add(((DnsARecord)record.RDATA).Address);
                                        break;

                                    case DnsResourceRecordType.AAAA:
                                        ipAddresses.Add(((DnsAAAARecord)record.RDATA).Address);
                                        break;

                                    case DnsResourceRecordType.CNAME:
                                        domain = ((DnsCNAMERecord)record.RDATA).CNAMEDomainName;
                                        break;

                                    default:
                                        throw new DnsClientException("Name server [" + response.NameServerAddress.ToString() + "] returned unexpected record type [ " + record.Type.ToString() + "] for domain: " + domain);
                                }
                            }
                        }

                        if (ipAddresses.Count > 0)
                            return ipAddresses.ToArray();

                        break;

                    case DnsResponseCode.NameError:
                        throw new NameErrorDnsClientException("Domain does not exists: " + domain + "; Name server: " + response.NameServerAddress.ToString());

                    default:
                        throw new DnsClientException("Name server returned error. DNS RCODE: " + response.Header.RCODE.ToString() + " (" + response.Header.RCODE + ")");
                }
            }

            throw new DnsClientException("No answer received from name server for domain: " + domain);
        }

        #endregion

        #region property

        public NameServerAddress[] Servers
        { get { return _servers; } }

        public NetProxy Proxy
        {
            get { return _proxy; }
            set
            {
                _proxy = value;

                if (_proxy != null)
                {
                    if (_connectionTimeout < 5000)
                        _connectionTimeout = 10000;

                    if (_sendTimeout < 5000)
                        _sendTimeout = 10000;

                    if (_recvTimeout < 5000)
                        _recvTimeout = 10000;
                }
            }
        }

        public bool PreferIPv6
        {
            get { return _preferIPv6; }
            set { _preferIPv6 = value; }
        }

        public DnsClientProtocol Protocol
        {
            get { return _protocol; }
            set { _protocol = value; }
        }

        public int Retries
        {
            get { return _retries; }
            set { _retries = value; }
        }

        public int ConnectionTimeout
        {
            get { return _connectionTimeout; }
            set { _connectionTimeout = value; }
        }

        public int SendTimeout
        {
            get { return _sendTimeout; }
            set { _sendTimeout = value; }
        }

        public int ReceiveTimeout
        {
            get { return _recvTimeout; }
            set { _recvTimeout = value; }
        }

        #endregion

        class ResolverData
        {
            public DnsQuestionRecord Question;
            public NameServerAddress[] NameServers;
            public int NameServerIndex;
            public DnsClientProtocol Protocol;

            public ResolverData(DnsQuestionRecord question, NameServerAddress[] nameServers, int nameServerIndex, DnsClientProtocol protocol)
            {
                this.Question = question;
                this.NameServers = nameServers;
                this.NameServerIndex = nameServerIndex;
                this.Protocol = protocol;
            }
        }
    }
}
