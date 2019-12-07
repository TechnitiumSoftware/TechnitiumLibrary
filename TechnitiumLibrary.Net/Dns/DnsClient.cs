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
using System.Net.Mail;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using TechnitiumLibrary.Net.Dns.ClientConnection;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net.Dns
{
    public enum DnsTransportProtocol : byte
    {
        Udp = 0,
        Tcp = 1,
        Tls = 2, //RFC-7858
        Https = 3, //RFC-8484
        HttpsJson = 4 //Google
    }

    public class DnsClient
    {
        #region variables

        public static readonly NameServerAddress[] ROOT_NAME_SERVERS_IPv4;
        public static readonly NameServerAddress[] ROOT_NAME_SERVERS_IPv6;

        readonly static RandomNumberGenerator _rnd = new RNGCryptoServiceProvider();

        const int MAX_HOPS = 16;

        readonly NameServerAddress[] _servers;

        NetProxy _proxy;
        bool _preferIPv6 = false;
        DnsTransportProtocol _protocol = DnsTransportProtocol.Udp;
        int _retries = 2;
        int _timeout = 2000;

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

            IPAddressCollection servers = GetSystemDnsServers(_preferIPv6);

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

        public DnsClient(EndPoint server)
            : this(new NameServerAddress(server))
        { }

        public DnsClient(string address)
            : this(new NameServerAddress(address))
        { }

        public DnsClient(NameServerAddress server)
        {
            _servers = new NameServerAddress[] { server };
        }

        public DnsClient(NameServerAddress[] servers)
        {
            if (servers.Length == 0)
                throw new DnsClientException("At least one name server must be available for DnsClient.");

            _servers = servers;
        }

        #endregion

        #region static

        public static DnsDatagram RecursiveResolve(DnsQuestionRecord question, NameServerAddress[] nameServers = null, DnsCache cache = null, NetProxy proxy = null, bool preferIPv6 = false, int retries = 2, int timeout = 2000, bool useTcp = false, int maxStackCount = 10, bool getDelegationNS = false)
        {
            if (cache == null)
                cache = new SimpleDnsCache();

            if ((nameServers != null) && (nameServers.Length > 0))
            {
                //create copy of name servers array so that the values in original array are not messed due to shuffling feature
                NameServerAddress[] nameServersCopy = new NameServerAddress[nameServers.Length];
                Array.Copy(nameServers, nameServersCopy, nameServers.Length);
                nameServers = nameServersCopy;

                ShuffleArray(nameServers);

                if (preferIPv6)
                    Array.Sort(nameServers);
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

                    throw new DnsClientException("DnsClient recursive resolution exceeded the maximum stack count for domain: " + question.Name);
                }

                //query cache
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

                                    switch (cacheResponse.Answer[0].Type)
                                    {
                                        case DnsResourceRecordType.AAAA:
                                            nameServers[stackNameServerIndex] = new NameServerAddress(nameServers[stackNameServerIndex].Host, new IPEndPoint((cacheResponse.Answer[0].RDATA as DnsAAAARecord).Address, nameServers[stackNameServerIndex].Port));
                                            break;

                                        case DnsResourceRecordType.A:
                                            nameServers[stackNameServerIndex] = new NameServerAddress(nameServers[stackNameServerIndex].Host, new IPEndPoint((cacheResponse.Answer[0].RDATA as DnsARecord).Address, nameServers[stackNameServerIndex].Port));
                                            break;

                                        default:
                                            //didnt find IP for current name server
                                            stackNameServerIndex++; //increment to skip current name server
                                            break;
                                    }

                                    continue; //stack loop
                                }
                            }
                            else if (cacheResponse.Authority.Length > 0)
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
                                        }

                                        continue; //to stack loop
                                    }
                                }
                                else if ((nameServers == null) || (nameServers.Length == 0))
                                {
                                    //select only name servers with glue from cache to avoid getting stack overflow due to getting same set of NS records with no address every time from cache
                                    NameServerAddress[] cacheNameServers = NameServerAddress.GetNameServersFromResponse(cacheResponse, preferIPv6, true);

                                    if (cacheNameServers.Length > 0)
                                        nameServers = cacheNameServers;
                                }
                            }
                            else
                            {
                                if (resolverStack.Count == 0)
                                    return cacheResponse;
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

                                continue; //stack loop
                            }
                    }
                }

                if ((nameServers == null) || (nameServers.Length == 0))
                {
                    //create copy of root name servers array so that the values in original array are not messed due to shuffling feature
                    if (preferIPv6)
                    {
                        nameServers = new NameServerAddress[ROOT_NAME_SERVERS_IPv6.Length + ROOT_NAME_SERVERS_IPv4.Length];
                        Array.Copy(ROOT_NAME_SERVERS_IPv6, nameServers, ROOT_NAME_SERVERS_IPv6.Length);
                        Array.Copy(ROOT_NAME_SERVERS_IPv4, 0, nameServers, ROOT_NAME_SERVERS_IPv6.Length, ROOT_NAME_SERVERS_IPv4.Length);

                        ShuffleArray(nameServers);
                        Array.Sort(nameServers);
                    }
                    else
                    {
                        nameServers = new NameServerAddress[ROOT_NAME_SERVERS_IPv4.Length];
                        Array.Copy(ROOT_NAME_SERVERS_IPv4, nameServers, ROOT_NAME_SERVERS_IPv4.Length);

                        ShuffleArray(nameServers);
                    }
                }

                int hopCount = 0;
                while (hopCount++ < MAX_HOPS) //resolver loop
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
                            resolverStack.Push(new ResolverData(question, nameServers, i));

                            if (preferIPv6)
                                question = new DnsQuestionRecord(currentNameServer.Host, DnsResourceRecordType.AAAA, question.Class);
                            else
                                question = new DnsQuestionRecord(currentNameServer.Host, DnsResourceRecordType.A, question.Class);

                            nameServers = null;
                            goto stackLoop;
                        }

                        DnsClient client = new DnsClient(currentNameServer);
                        client._proxy = proxy;
                        client._protocol = useTcp ? DnsTransportProtocol.Tcp : DnsTransportProtocol.Udp;
                        client._retries = retries;
                        client._timeout = timeout;

                        DnsDatagram request = new DnsDatagram(new DnsHeader(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, 1, 0, 0, 0), new DnsQuestionRecord[] { question }, null, null, null);
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

                        if (response.Header.Truncation && (client._protocol == DnsTransportProtocol.Udp))
                        {
                            client._protocol = DnsTransportProtocol.Tcp;

                            try
                            {
                                response = client.Resolve(request);
                            }
                            catch (DnsClientException ex)
                            {
                                lastException = ex;
                                continue; //resolver loop
                            }
                        }

                        if (response.Header.Truncation)
                        {
                            lastException = new DnsClientException("DnsClient received a truncated response for " + client._protocol.ToString() + " protocol from name server: " + currentNameServer.ToString());
                            continue; //resolver loop
                        }

                        cache.CacheResponse(response);

                        switch (response.Header.RCODE)
                        {
                            case DnsResponseCode.NoError:
                                if (response.Answer.Length > 0)
                                {
                                    if (!response.Answer[0].Name.Equals(question.Name, StringComparison.OrdinalIgnoreCase))
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

                                        switch (response.Answer[0].Type)
                                        {
                                            case DnsResourceRecordType.AAAA:
                                                nameServers[stackNameServerIndex] = new NameServerAddress(nameServers[stackNameServerIndex].Host, new IPEndPoint((response.Answer[0].RDATA as DnsAAAARecord).Address, nameServers[stackNameServerIndex].Port));
                                                break;

                                            case DnsResourceRecordType.A:
                                                nameServers[stackNameServerIndex] = new NameServerAddress(nameServers[stackNameServerIndex].Host, new IPEndPoint((response.Answer[0].RDATA as DnsARecord).Address, nameServers[stackNameServerIndex].Port));
                                                break;

                                            default:
                                                //didnt find IP for current name server
                                                stackNameServerIndex++; //increment to skip current name server
                                                break;
                                        }

                                        goto resolverLoop;
                                    }
                                }
                                else if (response.Authority.Length > 0)
                                {
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
                                            }

                                            goto stackLoop; //goto stack loop
                                        }
                                    }
                                    else
                                    {
                                        if ((resolverStack.Count == 0) && (question.Type == DnsResourceRecordType.NS) && getDelegationNS && (response.Authority[0].Type == DnsResourceRecordType.NS) && question.Name.Equals(response.Authority[0].Name, StringComparison.OrdinalIgnoreCase))
                                            return response; //query needs NS from delegation

                                        //check if empty response was received from the authoritative name server
                                        foreach (DnsResourceRecord authorityRecord in response.Authority)
                                        {
                                            if ((authorityRecord.Type == DnsResourceRecordType.NS) && (authorityRecord.RDATA as DnsNSRecord).NSDomainName.Equals(response.Metadata.NameServerAddress.Host, StringComparison.OrdinalIgnoreCase))
                                            {
                                                //empty response from authoritative name server
                                                if (resolverStack.Count == 0)
                                                {
                                                    return response;
                                                }
                                                else
                                                {
                                                    //unable to resolve current name server domain
                                                    //pop and try next name server
                                                    ResolverData data = resolverStack.Pop();

                                                    question = data.Question;
                                                    nameServers = data.NameServers;
                                                    stackNameServerIndex = data.NameServerIndex + 1; //increment to skip current name server

                                                    goto stackLoop; //goto stack loop
                                                }
                                            }
                                        }

                                        //check for hop limit
                                        if (hopCount == MAX_HOPS)
                                        {
                                            //max hop count reached
                                            if (resolverStack.Count == 0)
                                            {
                                                return response;
                                            }
                                            else
                                            {
                                                //unable to resolve current name server domain due to hop limit
                                                //pop and try next name server
                                                ResolverData data = resolverStack.Pop();

                                                question = data.Question;
                                                nameServers = data.NameServers;
                                                stackNameServerIndex = data.NameServerIndex + 1; //increment to skip current name server

                                                goto stackLoop; //goto stack loop
                                            }
                                        }

                                        //get next hop name servers
                                        nameServers = NameServerAddress.GetNameServersFromResponse(response, preferIPv6, false);

                                        if (nameServers.Length == 0)
                                        {
                                            if ((i + 1) == nameServers.Length)
                                            {
                                                if (resolverStack.Count == 0)
                                                {
                                                    return response; //return response since this is last name server
                                                }
                                                else
                                                {
                                                    //pop and try next name server
                                                    ResolverData data = resolverStack.Pop();

                                                    question = data.Question;
                                                    nameServers = data.NameServers;
                                                    stackNameServerIndex = data.NameServerIndex + 1; //increment to skip current name server

                                                    goto stackLoop; //goto stack loop
                                                }
                                            }

                                            continue; //continue to next name server since current name server may be misconfigured
                                        }

                                        goto resolverLoop;
                                    }
                                }
                                else
                                {
                                    if ((i + 1) == nameServers.Length)
                                    {
                                        if (resolverStack.Count == 0)
                                        {
                                            return response; //return response since this is last name server
                                        }
                                        else
                                        {
                                            //pop and try next name server
                                            ResolverData data = resolverStack.Pop();

                                            question = data.Question;
                                            nameServers = data.NameServers;
                                            stackNameServerIndex = data.NameServerIndex + 1; //increment to skip current name server

                                            goto stackLoop; //goto stack loop
                                        }
                                    }

                                    continue; //continue to next name server since current name server may be misconfigured
                                }

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

                                    goto stackLoop; //goto stack loop
                                }

                            default:
                                if ((i + 1) == nameServers.Length)
                                {
                                    if (resolverStack.Count == 0)
                                    {
                                        return response; //return response since this is last name server
                                    }
                                    else
                                    {
                                        //pop and try next name server
                                        ResolverData data = resolverStack.Pop();

                                        question = data.Question;
                                        nameServers = data.NameServers;
                                        stackNameServerIndex = data.NameServerIndex + 1; //increment to skip current name server

                                        goto stackLoop; //goto stack loop
                                    }
                                }

                                continue; //continue to next name server since current name server may be misconfigured
                        }
                    }

                    if (resolverStack.Count == 0)
                    {
                        string strNameServers = null;

                        foreach (NameServerAddress nameServer in nameServers)
                        {
                            if (strNameServers == null)
                                strNameServers = nameServer.ToString();
                            else
                                strNameServers += ", " + nameServer.ToString();
                        }

                        throw new DnsClientException("DnsClient recursive resolution failed: no response from name servers [" + strNameServers + "]", lastException);
                    }
                    else
                    {
                        //didnt find IP for current name server
                        //pop and try next name server
                        ResolverData data = resolverStack.Pop();

                        question = data.Question;
                        nameServers = data.NameServers;
                        stackNameServerIndex = data.NameServerIndex + 1; //increment to skip current name server

                        break; //to stack loop
                    }

                resolverLoop:;
                }

            stackLoop:;
            }
        }

        public static DnsDatagram RecursiveQuery(DnsQuestionRecord question, DnsCache cache = null, NetProxy proxy = null, bool preferIPv6 = false, int retries = 2, int timeout = 2000, bool useTcp = false, int maxStackCount = 10)
        {
            if (cache == null)
                cache = new SimpleDnsCache();

            DnsDatagram response = RecursiveResolve(question, null, cache, proxy, preferIPv6, retries, timeout, useTcp, maxStackCount);

            DnsResourceRecord[] authority;
            DnsResourceRecord[] additional;

            if (response.Answer.Length > 0)
            {
                DnsResourceRecord lastRR = response.Answer[response.Answer.Length - 1];

                if ((lastRR.Type != question.Type) && (lastRR.Type == DnsResourceRecordType.CNAME) && (question.Type != DnsResourceRecordType.ANY))
                {
                    List<DnsResourceRecord> responseAnswer = new List<DnsResourceRecord>();
                    responseAnswer.AddRange(response.Answer);

                    DnsDatagram lastResponse;
                    int queryCount = 0;

                    while (true)
                    {
                        DnsQuestionRecord cnameQuestion = new DnsQuestionRecord((lastRR.RDATA as DnsCNAMERecord).CNAMEDomainName, question.Type, question.Class);

                        lastResponse = RecursiveResolve(cnameQuestion, null, cache, proxy, preferIPv6, retries, timeout, useTcp, maxStackCount);

                        if (lastResponse.Answer.Length == 0)
                            break;

                        responseAnswer.AddRange(lastResponse.Answer);

                        lastRR = lastResponse.Answer[lastResponse.Answer.Length - 1];

                        if (lastRR.Type == question.Type)
                            break;

                        if (lastRR.Type != DnsResourceRecordType.CNAME)
                            throw new DnsClientException("Invalid response received from DNS server.");

                        queryCount++;
                        if (queryCount > MAX_HOPS)
                            throw new DnsClientException("Recursive resolution exceeded max hops.");
                    }

                    if ((lastResponse.Authority.Length > 0) && (lastResponse.Authority[0].Type == DnsResourceRecordType.SOA))
                        authority = lastResponse.Authority;
                    else
                        authority = new DnsResourceRecord[] { };

                    if ((response.Additional.Length > 0) && (question.Type == DnsResourceRecordType.MX))
                        additional = response.Additional;
                    else
                        additional = new DnsResourceRecord[] { };

                    DnsDatagram compositeResponse = new DnsDatagram(new DnsHeader(0, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, lastResponse.Header.RCODE, 1, (ushort)responseAnswer.Count, (ushort)authority.Length, (ushort)additional.Length), new DnsQuestionRecord[] { question }, responseAnswer.ToArray(), authority, additional);

                    if (lastResponse.Metadata != null)
                        compositeResponse.SetMetadata(new DnsDatagramMetadata(lastResponse.Metadata.NameServerAddress, lastResponse.Metadata.Protocol, -1, lastResponse.Metadata.RTT));

                    return compositeResponse;
                }
            }

            if ((response.Authority.Length > 0) && (response.Authority[0].Type == DnsResourceRecordType.SOA))
                authority = response.Authority;
            else
                authority = new DnsResourceRecord[] { };

            if ((response.Additional.Length > 0) && (question.Type == DnsResourceRecordType.MX))
                additional = response.Additional;
            else
                additional = new DnsResourceRecord[] { };

            DnsDatagram finalResponse = new DnsDatagram(new DnsHeader(0, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, response.Header.RCODE, 1, (ushort)response.Answer.Length, (ushort)authority.Length, (ushort)additional.Length), new DnsQuestionRecord[] { question }, response.Answer, authority, additional);

            if (response.Metadata != null)
                finalResponse.SetMetadata(new DnsDatagramMetadata(response.Metadata.NameServerAddress, response.Metadata.Protocol, -1, response.Metadata.RTT));

            return finalResponse;
        }

        public static IPAddress[] RecursiveResolveIP(string domain, DnsCache cache = null, NetProxy proxy = null, bool preferIPv6 = false, int retries = 2, int timeout = 2000, bool useTcp = false, int maxStackCount = 10)
        {
            if (cache == null)
                cache = new SimpleDnsCache();

            if (preferIPv6)
            {
                IPAddress[] addresses = ParseResponseAAAA(RecursiveQuery(new DnsQuestionRecord(domain, DnsResourceRecordType.AAAA, DnsClass.IN), cache, proxy, preferIPv6, retries, timeout, useTcp, maxStackCount));
                if (addresses.Length > 0)
                    return addresses;
            }

            return ParseResponseA(RecursiveQuery(new DnsQuestionRecord(domain, DnsResourceRecordType.A, DnsClass.IN), cache, proxy, preferIPv6, retries, timeout, useTcp, maxStackCount));
        }

        public static IPAddress[] ParseResponseA(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.Header.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Header.ANCOUNT == 0)
                        return new IPAddress[] { };

                    List<IPAddress> ipAddresses = new List<IPAddress>();

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.A:
                                    ipAddresses.Add(((DnsARecord)record.RDATA).Address);
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = ((DnsCNAMERecord)record.RDATA).CNAMEDomainName;
                                    break;
                            }
                        }
                    }

                    return ipAddresses.ToArray();

                case DnsResponseCode.NameError:
                    throw new NameErrorDnsClientException("Domain does not exists: " + domain + (response.Metadata == null ? "" : "; Name server: " + response.Metadata.NameServerAddress.ToString()));

                default:
                    throw new DnsClientException("Name server returned error. DNS RCODE: " + response.Header.RCODE.ToString() + " (" + response.Header.RCODE + ")");
            }
        }

        public static IPAddress[] ParseResponseAAAA(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.Header.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Header.ANCOUNT == 0)
                        return new IPAddress[] { };

                    List<IPAddress> ipAddresses = new List<IPAddress>();

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.AAAA:
                                    ipAddresses.Add(((DnsAAAARecord)record.RDATA).Address);
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = ((DnsCNAMERecord)record.RDATA).CNAMEDomainName;
                                    break;
                            }
                        }
                    }

                    return ipAddresses.ToArray();

                case DnsResponseCode.NameError:
                    throw new NameErrorDnsClientException("Domain does not exists: " + domain + (response.Metadata == null ? "" : "; Name server: " + response.Metadata.NameServerAddress.ToString()));

                default:
                    throw new DnsClientException("Name server returned error. DNS RCODE: " + response.Header.RCODE.ToString() + " (" + response.Header.RCODE + ")");
            }
        }

        public static string[] ParseResponseTXT(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.Header.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Header.ANCOUNT == 0)
                        return new string[] { };

                    List<string> txtRecords = new List<string>();

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.TXT:
                                    txtRecords.Add(((DnsTXTRecord)record.RDATA).TXTData);
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = ((DnsCNAMERecord)record.RDATA).CNAMEDomainName;
                                    break;
                            }
                        }
                    }

                    return txtRecords.ToArray();

                case DnsResponseCode.NameError:
                    throw new NameErrorDnsClientException("Domain does not exists: " + domain + (response.Metadata == null ? "" : "; Name server: " + response.Metadata.NameServerAddress.ToString()));

                default:
                    throw new DnsClientException("Name server returned error. DNS RCODE: " + response.Header.RCODE.ToString() + " (" + response.Header.RCODE + ")");
            }
        }

        public static string ParseResponsePTR(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.Header.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Header.ANCOUNT == 0)
                        return null;

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.PTR:
                                    return ((DnsPTRRecord)record.RDATA).PTRDomainName;

                                case DnsResourceRecordType.CNAME:
                                    domain = ((DnsCNAMERecord)record.RDATA).CNAMEDomainName;
                                    break;
                            }
                        }
                    }

                    return null;

                case DnsResponseCode.NameError:
                    throw new NameErrorDnsClientException("Domain does not exists: " + domain + (response.Metadata == null ? "" : "; Name server: " + response.Metadata.NameServerAddress.ToString()));

                default:
                    throw new DnsClientException("Name server returned error. DNS RCODE: " + response.Header.RCODE.ToString() + " (" + response.Header.RCODE + ")");
            }
        }

        public static string[] ParseResponseMX(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.Header.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Header.ANCOUNT == 0)
                        return new string[] { };

                    List<DnsMXRecord> mxRecordsList = new List<DnsMXRecord>();

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.MX:
                                    mxRecordsList.Add((DnsMXRecord)record.RDATA);
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = ((DnsCNAMERecord)record.RDATA).CNAMEDomainName;
                                    break;
                            }
                        }
                    }

                    if (mxRecordsList.Count > 0)
                    {
                        DnsMXRecord[] mxRecords = mxRecordsList.ToArray();

                        //sort by mx preference
                        Array.Sort(mxRecords);

                        string[] mxEntries = new string[mxRecords.Length];

                        for (int i = 0; i < mxRecords.Length; i++)
                            mxEntries[i] = mxRecords[i].Exchange;

                        return mxEntries;
                    }

                    return new string[] { };

                case DnsResponseCode.NameError:
                    throw new NameErrorDnsClientException("Domain does not exists: " + domain + (response.Metadata == null ? "" : "; Name server: " + response.Metadata.NameServerAddress.ToString()));

                default:
                    throw new DnsClientException("Name server returned error. DNS RCODE: " + response.Header.RCODE.ToString() + " (" + response.Header.RCODE + ")");
            }
        }

        public static Uri[] FindResolverAssociatedDohServers(bool preferIPv6 = false)
        {
            IPAddress[] resolverAddresses;

            try
            {
                //find system dns servers
                IPAddressCollection servers = GetSystemDnsServers(preferIPv6);

                resolverAddresses = new IPAddress[servers.Count];
                servers.CopyTo(resolverAddresses, 0);
            }
            catch
            {
                //error while finding system configured dns servers, try query method
                resolverAddresses = System.Net.Dns.GetHostAddresses("resolver-addresses.arpa");
                if ((resolverAddresses == null) || (resolverAddresses.Length < 1))
                    return new Uri[] { };
            }

            return FindResolverAssociatedDohServers(resolverAddresses);
        }

        public static Uri[] FindResolverAssociatedDohServers(IPAddress[] resolverAddresses)
        {
            DnsClient client = new DnsClient(resolverAddresses);

            string[] values = client.ResolveTXT("resolver-associated-doh.arpa");
            List<Uri> dohUris = new List<Uri>();

            foreach (string value in values)
            {
                string uriValue = value;

                if (uriValue.EndsWith("{?dns}"))
                    uriValue = uriValue.Replace("{?dns}", "");

                if (Uri.TryCreate(uriValue, UriKind.Absolute, out Uri dohUri))
                {
                    if (dohUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                        dohUris.Add(dohUri);
                }
            }

            return dohUris.ToArray();
        }

        public static IPAddressCollection GetSystemDnsServers(bool preferIPv6 = false)
        {
            NetworkInfo defaultNetworkInfo;

            if (preferIPv6)
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

            return servers;
        }

        public static bool IsDomainNameValid(string domain, bool throwException = false)
        {
            if (domain.Length == 0)
                return true; //domain is root zone

            if (domain.Length > 255)
            {
                if (throwException)
                    throw new DnsClientException("Invalid domain name [" + domain + "]: length cannot exceed 255 bytes.");

                return false;
            }

            string[] labels = domain.Split('.');

            foreach (string label in labels)
            {
                if (label.Length == 0)
                {
                    if (throwException)
                        throw new DnsClientException("Invalid domain name [" + domain + "]: label length cannot be 0 byte.");

                    return false;
                }

                if (label.Length > 63)
                {
                    if (throwException)
                        throw new DnsClientException("Invalid domain name [" + domain + "]: label length cannot exceed 63 bytes.");

                    return false;
                }

                if (label.StartsWith("-"))
                {
                    if (throwException)
                        throw new DnsClientException("Invalid domain name [" + domain + "]: label cannot start with hyphen.");

                    return false;
                }

                if (label.EndsWith("-"))
                {
                    if (throwException)
                        throw new DnsClientException("Invalid domain name [" + domain + "]: label cannot end with hyphen.");

                    return false;
                }

                if (label.Equals("*"))
                    continue; //[*] allowed for wild card domain entries in dns server

                byte[] labelBytes = Encoding.ASCII.GetBytes(label);

                foreach (byte labelByte in labelBytes)
                {
                    if ((labelByte >= 97) && (labelByte <= 122)) //[a-z]
                        continue;

                    if ((labelByte >= 65) && (labelByte <= 90)) //[A-Z]
                        continue;

                    if ((labelByte >= 48) && (labelByte <= 57)) //[0-9]
                        continue;

                    if (labelByte == 45) //[-]
                        continue;

                    if (labelByte == 95) //[_]
                        continue;

                    if (throwException)
                        throw new DnsClientException("Invalid domain name: invalid character [" + labelByte + "] found in domain name [" + domain + "].");

                    return false;
                }
            }

            return true;
        }

        public static void ShuffleArray<T>(T[] array)
        {
            byte[] buffer = new byte[4];

            int n = array.Length;
            while (n > 1)
            {
                _rnd.GetBytes(buffer);
                int k = (int)(BitConverter.ToUInt32(buffer, 0) % n--);
                T temp = array[n];
                array[n] = array[k];
                array[k] = temp;
            }
        }

        #endregion

        #region public

        public DnsDatagram Resolve(DnsDatagram request)
        {
            int nextServerIndex = 0;
            int retries = _retries;
            Exception lastException = null;
            DnsTransportProtocol protocol = _protocol;

            if (_proxy != null)
            {
                //upgrade protocol to TCP when UDP is not supported by proxy
                if ((protocol == DnsTransportProtocol.Udp) && !_proxy.IsUdpAvailable())
                    protocol = DnsTransportProtocol.Tcp;
            }

            //init server selection parameters
            if (_servers.Length > 1)
            {
                retries *= _servers.Length; //retries on per server basis

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

                if (server.IsIPEndPointStale && (_proxy == null))
                {
                    //recursive resolve name server via root servers when proxy is null else let proxy resolve it
                    try
                    {
                        server.RecursiveResolveIPAddress(null, null, _preferIPv6, _retries, _timeout, false);
                    }
                    catch
                    {
                        retry++;
                        continue;
                    }
                }

                //query server
                try
                {
                    retry++;

                    request.Header.SetRandomIdentifier(); //each retry must have differnt ID

                    DnsClientConnection connection = DnsClientConnection.GetConnection(protocol, server, _proxy);
                    connection.Timeout = _timeout;

                    DnsDatagram response = connection.Query(request);
                    if (response != null)
                        return response;
                }
                catch (WebException ex)
                {
                    lastException = ex;
                }
                catch (IOException ex)
                {
                    lastException = ex;
                }
                catch (SocketException ex)
                {
                    lastException = ex;
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
            if ((queryType == DnsResourceRecordType.PTR) && IPAddress.TryParse(domain, out IPAddress address))
                return Resolve(new DnsQuestionRecord(address, DnsClass.IN));
            else
                return Resolve(new DnsQuestionRecord(domain, queryType, DnsClass.IN));
        }

        public string[] ResolveMX(MailAddress emailAddress, bool resolveIP = false, bool preferIPv6 = false)
        {
            return ResolveMX(emailAddress.Host, resolveIP, preferIPv6);
        }

        public string[] ResolveMX(string domain, bool resolveIP = false, bool preferIPv6 = false)
        {
            if (IPAddress.TryParse(domain, out _))
            {
                //host is valid ip address
                return new string[] { domain };
            }

            DnsDatagram response = Resolve(new DnsQuestionRecord(domain, DnsResourceRecordType.MX, DnsClass.IN));
            string[] mxEntries = ParseResponseMX(response);

            if (!resolveIP)
                return mxEntries;

            //resolve IP addresses
            List<string> mxAddresses = new List<string>();

            //check glue records
            foreach (string mxEntry in mxEntries)
            {
                bool glueRecordFound = false;

                foreach (DnsResourceRecord record in response.Additional)
                {
                    if (record.Name.Equals(mxEntry, StringComparison.OrdinalIgnoreCase))
                    {
                        switch (record.Type)
                        {
                            case DnsResourceRecordType.A:
                                if (!preferIPv6)
                                {
                                    mxAddresses.Add(((DnsARecord)record.RDATA).Address.ToString());
                                    glueRecordFound = true;
                                }
                                break;

                            case DnsResourceRecordType.AAAA:
                                if (preferIPv6)
                                {
                                    mxAddresses.Add(((DnsAAAARecord)record.RDATA).Address.ToString());
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
                        IPAddress[] ipList = ResolveIP(mxEntry, preferIPv6);

                        foreach (IPAddress ip in ipList)
                            mxAddresses.Add(ip.ToString());
                    }
                    catch (NameErrorDnsClientException)
                    { }
                    catch (DnsClientException)
                    {
                        mxAddresses.Add(mxEntry);
                    }
                }
            }

            return mxAddresses.ToArray();
        }

        public string ResolvePTR(IPAddress ip)
        {
            return ParseResponsePTR(Resolve(new DnsQuestionRecord(ip, DnsClass.IN)));
        }

        public string[] ResolveTXT(string domain)
        {
            return ParseResponseTXT(Resolve(new DnsQuestionRecord(domain, DnsResourceRecordType.TXT, DnsClass.IN)));
        }

        public IPAddress[] ResolveIP(string domain, bool preferIPv6 = false)
        {
            if (preferIPv6)
            {
                IPAddress[] addresses = ParseResponseAAAA(Resolve(new DnsQuestionRecord(domain, DnsResourceRecordType.AAAA, DnsClass.IN)));
                if (addresses.Length > 0)
                    return addresses;
            }

            return ParseResponseA(Resolve(new DnsQuestionRecord(domain, DnsResourceRecordType.A, DnsClass.IN)));
        }

        #endregion

        #region property

        public NameServerAddress[] Servers
        { get { return _servers; } }

        public NetProxy Proxy
        {
            get { return _proxy; }
            set { _proxy = value; }
        }

        public bool PreferIPv6
        {
            get { return _preferIPv6; }
            set { _preferIPv6 = value; }
        }

        public DnsTransportProtocol Protocol
        {
            get { return _protocol; }
            set { _protocol = value; }
        }

        public int Retries
        {
            get { return _retries; }
            set { _retries = value; }
        }

        public int Timeout
        {
            get { return _timeout; }
            set { _timeout = value; }
        }

        #endregion

        class ResolverData
        {
            public DnsQuestionRecord Question;
            public NameServerAddress[] NameServers;
            public int NameServerIndex;

            public ResolverData(DnsQuestionRecord question, NameServerAddress[] nameServers, int nameServerIndex)
            {
                this.Question = question;
                this.NameServers = nameServers;
                this.NameServerIndex = nameServerIndex;
            }
        }
    }
}
