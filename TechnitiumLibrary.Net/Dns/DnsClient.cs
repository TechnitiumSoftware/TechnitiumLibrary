﻿/*
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
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
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

    public class DnsClient : IDnsClient
    {
        #region variables

        readonly static IReadOnlyList<NameServerAddress> ROOT_NAME_SERVERS_IPv4;
        readonly static IReadOnlyList<NameServerAddress> ROOT_NAME_SERVERS_IPv6;

        readonly static IReadOnlyList<DnsResourceRecord> ROOT_TRUST_ANCHORS;

        const int MAX_DELEGATION_HOPS = 16;
        internal const int MAX_CNAME_HOPS = 16;

        readonly IReadOnlyList<NameServerAddress> _servers;

        IDnsCache _cache;
        NetProxy _proxy;
        bool _preferIPv6;
        ushort _udpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE;
        bool _randomizeName;
        bool _dnssecValidation;
        int _retries = 2;
        int _timeout = 2000;
        int _concurrency = 2;

        #endregion

        #region constructor

        static DnsClient()
        {
            try
            {
                string rootHintsFile = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "named.root");

                if (File.Exists(rootHintsFile))
                {
                    using (StreamReader sR = new StreamReader(rootHintsFile))
                    {
                        List<string> rootServers = new List<string>();
                        List<NameServerAddress> ipv4RootNameServers = new List<NameServerAddress>(13);
                        List<NameServerAddress> ipv6RootNameServers = new List<NameServerAddress>(13);

                        while (true)
                        {
                            string line = sR.ReadLine();
                            if (line is null)
                                break;

                            if (line.Length == 0)
                                continue;

                            if (line.StartsWith(";"))
                                continue;

                            string name = PopWord(ref line);
                            if (name.Equals("."))
                            {
                                _ = PopWord(ref line); //TTL
                                string type = PopWord(ref line);

                                if (type.Equals("NS", StringComparison.OrdinalIgnoreCase))
                                {
                                    string rootServer = PopWord(ref line);
                                    rootServers.Add(rootServer.ToLower());
                                }
                            }
                            else
                            {
                                name = name.ToLower();
                                _ = PopWord(ref line); //TTL
                                string type = PopWord(ref line);

                                switch (type.ToUpper())
                                {
                                    case "A":
                                        if (rootServers.Contains(name))
                                        {
                                            if (name.EndsWith("."))
                                                name = name.Substring(0, name.Length - 1);

                                            string strAddress = PopWord(ref line);
                                            if (IPAddress.TryParse(strAddress, out IPAddress address) && address.AddressFamily == AddressFamily.InterNetwork)
                                                ipv4RootNameServers.Add(new NameServerAddress(name, address));
                                        }
                                        break;

                                    case "AAAA":
                                        if (rootServers.Contains(name))
                                        {
                                            if (name.EndsWith("."))
                                                name = name.Substring(0, name.Length - 1);

                                            string strAddress = PopWord(ref line);
                                            if (IPAddress.TryParse(strAddress, out IPAddress address) && address.AddressFamily == AddressFamily.InterNetworkV6)
                                                ipv6RootNameServers.Add(new NameServerAddress(name, address));
                                        }
                                        break;
                                }
                            }
                        }

                        ROOT_NAME_SERVERS_IPv4 = ipv4RootNameServers;
                        ROOT_NAME_SERVERS_IPv6 = ipv6RootNameServers;
                    }
                }
            }
            catch
            { }

            try
            {
                string rootTrustXmlFile = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "root-anchors.xml");

                XmlDocument rootTrustXml = new XmlDocument();
                rootTrustXml.Load(rootTrustXmlFile);

                XmlNamespaceManager nsMgr = new XmlNamespaceManager(rootTrustXml.NameTable);
                XmlNodeList nodeList = rootTrustXml.SelectNodes("//TrustAnchor/KeyDigest", nsMgr);

                const string dateFormat = "yyyy-MM-ddTHH:mm:sszzz";
                List<DnsResourceRecord> rootTrustAnchors = new List<DnsResourceRecord>();

                foreach (XmlNode keyDigestNode in nodeList)
                {
                    DateTime validFrom = DateTime.MinValue;
                    DateTime validUntil = DateTime.MinValue;

                    foreach (XmlAttribute attribute in keyDigestNode.Attributes)
                    {
                        switch (attribute.Name)
                        {
                            case "validFrom":
                                validFrom = DateTime.ParseExact(attribute.Value, dateFormat, CultureInfo.CurrentCulture);
                                break;

                            case "validUntil":
                                validUntil = DateTime.ParseExact(attribute.Value, dateFormat, CultureInfo.CurrentCulture);
                                break;
                        }
                    }

                    if ((validFrom != DateTime.MinValue) && (validFrom > DateTime.UtcNow))
                        continue;

                    if ((validUntil != DateTime.MinValue) && (validUntil < DateTime.UtcNow))
                        continue;

                    ushort keyTag = 0;
                    DnssecAlgorithm algorithm = DnssecAlgorithm.Unknown;
                    DnssecDigestType digestType = DnssecDigestType.Unknown;
                    string digest = null;

                    foreach (XmlNode childNode in keyDigestNode.ChildNodes)
                    {
                        switch (childNode.Name.ToLower())
                        {
                            case "keytag":
                                keyTag = ushort.Parse(childNode.InnerText);
                                break;

                            case "algorithm":
                                algorithm = (DnssecAlgorithm)byte.Parse(childNode.InnerText);
                                break;

                            case "digesttype":
                                digestType = (DnssecDigestType)byte.Parse(childNode.InnerText);
                                break;

                            case "digest":
                                digest = childNode.InnerText;
                                break;
                        }
                    }

                    rootTrustAnchors.Add(new DnsResourceRecord("", DnsResourceRecordType.DS, DnsClass.IN, 0, new DnsDSRecord(keyTag, algorithm, digestType, Convert.FromHexString(digest))));
                }

                ROOT_TRUST_ANCHORS = rootTrustAnchors;
            }
            catch
            { }

            if (ROOT_NAME_SERVERS_IPv4 is null)
            {
                ROOT_NAME_SERVERS_IPv4 = new NameServerAddress[]
                {
                    new NameServerAddress("a.root-servers.net", IPAddress.Parse("198.41.0.4")), //VeriSign, Inc.
                    new NameServerAddress("b.root-servers.net", IPAddress.Parse("199.9.14.201")), //University of Southern California (ISI)
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
            }

            if (ROOT_NAME_SERVERS_IPv6 is null)
            {
                ROOT_NAME_SERVERS_IPv6 = new NameServerAddress[]
                {
                    new NameServerAddress("a.root-servers.net", IPAddress.Parse("2001:503:ba3e::2:30")), //VeriSign, Inc.
                    new NameServerAddress("b.root-servers.net", IPAddress.Parse("2001:500:200::b")), //University of Southern California (ISI)
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

            if (ROOT_TRUST_ANCHORS is null)
            {
                ROOT_TRUST_ANCHORS = new DnsResourceRecord[]
                {
                    new DnsResourceRecord("", DnsResourceRecordType.DS, DnsClass.IN,0, new DnsDSRecord(20326, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256, Convert.FromHexString("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")))
                };
            }
        }

        public DnsClient(Uri dohEndPoint)
        {
            _servers = new NameServerAddress[] { new NameServerAddress(dohEndPoint) };
        }

        public DnsClient(Uri[] dohEndPoints)
        {
            if (dohEndPoints.Length == 0)
                throw new DnsClientException("At least one name server must be available for DnsClient.");

            NameServerAddress[] servers = new NameServerAddress[dohEndPoints.Length];

            for (int i = 0; i < dohEndPoints.Length; i++)
                servers[i] = new NameServerAddress(dohEndPoints[i]);

            _servers = servers;
        }

        public DnsClient(bool preferIPv6 = false)
        {
            _preferIPv6 = preferIPv6;

            IReadOnlyList<IPAddress> systemDnsServers = GetSystemDnsServers(_preferIPv6);
            if (systemDnsServers.Count == 0)
                throw new DnsClientException("No DNS servers were found configured on this system.");

            NameServerAddress[] servers = new NameServerAddress[systemDnsServers.Count];

            for (int i = 0; i < systemDnsServers.Count; i++)
                servers[i] = new NameServerAddress(systemDnsServers[i]);

            _servers = servers;
        }

        public DnsClient(IPAddress[] servers)
        {
            if (servers.Length == 0)
                throw new DnsClientException("At least one name server must be available for DnsClient.");

            NameServerAddress[] nameServers = new NameServerAddress[servers.Length];

            for (int i = 0; i < servers.Length; i++)
                nameServers[i] = new NameServerAddress(servers[i]);

            _servers = nameServers;
        }

        public DnsClient(IPAddress server)
            : this(new NameServerAddress(server))
        { }

        public DnsClient(EndPoint server)
            : this(new NameServerAddress(server))
        { }

        public DnsClient(string addresses)
        {
            string[] strServers = addresses.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

            if (strServers.Length == 0)
                throw new DnsClientException("At least one name server must be available for DnsClient.");

            NameServerAddress[] servers = new NameServerAddress[strServers.Length];

            for (int i = 0; i < strServers.Length; i++)
                servers[i] = new NameServerAddress(strServers[i]);

            _servers = servers;
        }

        public DnsClient(string address, DnsTransportProtocol protocol)
            : this(new NameServerAddress(address, protocol))
        { }

        public DnsClient(NameServerAddress server)
        {
            _servers = new NameServerAddress[] { server };
        }

        public DnsClient(params NameServerAddress[] servers)
        {
            if (servers.Length == 0)
                throw new DnsClientException("At least one name server must be available for DnsClient.");

            _servers = servers;
        }

        public DnsClient(IReadOnlyList<NameServerAddress> servers)
        {
            if (servers.Count == 0)
                throw new DnsClientException("At least one name server must be available for DnsClient.");

            _servers = servers;
        }

        #endregion

        #region static

        public static async Task<DnsDatagram> RecursiveResolveAsync(DnsQuestionRecord question, IDnsCache cache = null, NetProxy proxy = null, bool preferIPv6 = false, ushort udpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE, bool randomizeName = false, bool qnameMinimization = false, bool asyncNsRevalidation = false, bool dnssecValidation = false, int retries = 2, int timeout = 2000, int maxStackCount = 16)
        {
            if ((udpPayloadSize < 512) && dnssecValidation)
                throw new ArgumentOutOfRangeException(nameof(UdpPayloadSize), "EDNS cannot be disabled by setting UDP payload size to less than 512 when DNSSEC validation is enabled.");

            if (cache is null)
                cache = new DnsCache();

            if (qnameMinimization)
            {
                question = question.Clone(); //clone question so that original object is not affected
                question.ZoneCut = ""; //enable QNAME minimization by setting zone cut to <root>
            }

            //ns revalidation
            Dictionary<string, IReadOnlyList<NameServerAddress>> nsRevalidationTasks = null;

            if (asyncNsRevalidation)
                nsRevalidationTasks = new Dictionary<string, IReadOnlyList<NameServerAddress>>();

            void TriggerNsRevalidation()
            {
                if (!asyncNsRevalidation || nsRevalidationTasks.Count == 0)
                    return;

                _ = Task.Factory.StartNew(async delegate ()
                {
                    List<Task> tasks = new List<Task>(nsRevalidationTasks.Count);

                    foreach (KeyValuePair<string, IReadOnlyList<NameServerAddress>> entry in nsRevalidationTasks)
                        tasks.Add(RevalidateNameServers(entry.Key, entry.Value, cache, proxy, preferIPv6, udpPayloadSize, randomizeName, retries, timeout));

                    await Task.WhenAll(tasks);
                }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current);
            }

            //main stack
            Stack<ResolverData> resolverStack = new Stack<ResolverData>();

            //current stack variables
            string zoneCut = null;
            EDnsHeaderFlags ednsFlags = dnssecValidation ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None;
            IReadOnlyList<DnsResourceRecord> lastDSRecords = dnssecValidation ? ROOT_TRUST_ANCHORS : null;
            IList<NameServerAddress> nameServers = null;
            int nameServerIndex = 0;
            int hopCount = 0;
            DnsDatagram lastResponse = null;
            Exception lastException = null;

            void PushStack(string nextQName, DnsResourceRecordType nextQType)
            {
                resolverStack.Push(new ResolverData(question, zoneCut, ednsFlags, lastDSRecords, nameServers, nameServerIndex, hopCount, lastResponse, lastException));

                question = new DnsQuestionRecord(nextQName, nextQType, question.Class);

                if (qnameMinimization)
                    question.ZoneCut = ""; //enable QNAME minimization by setting zone cut to <root>

                zoneCut = null; //find zone cut in stack loop
                ednsFlags = dnssecValidation ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None;
                lastDSRecords = dnssecValidation ? ROOT_TRUST_ANCHORS : null;
                nameServers = null;
                nameServerIndex = 0;
                hopCount = 0;
                lastResponse = null;
                lastException = null;
            }

            void PopStack()
            {
                ResolverData data = resolverStack.Pop();

                question = data.Question;
                zoneCut = data.ZoneCut;
                ednsFlags = data.EDnsFlags;
                lastDSRecords = data.LastDSRecords;
                nameServers = data.NameServers;
                nameServerIndex = data.NameServerIndex;
                hopCount = data.HopCount;
                lastResponse = data.LastResponse;
                lastException = data.LastException;
            }

            void InspectCacheNameServersForLoops(List<NameServerAddress> cacheNameServers)
            {
                bool allCacheNameServersHaveGlue = true;

                foreach (NameServerAddress cacheNameServer in cacheNameServers)
                {
                    if (cacheNameServer.IsIPEndPointStale)
                    {
                        allCacheNameServersHaveGlue = false;
                        break;
                    }
                }

                if (allCacheNameServersHaveGlue)
                    return; //no inspection needed since all cache name servers have a glue record

                //inspect stack to see if the name servers returned by cache have repeated to avoid stack overflow
                foreach (ResolverData stack in resolverStack)
                {
                    foreach (NameServerAddress stackNameServer in stack.NameServers)
                    {
                        if (cacheNameServers.Contains(stackNameServer))
                        {
                            //one of name servers returned by cache already exists in stack; so dont use these set of name servers from cache
                            cacheNameServers.Clear();
                            return;
                        }
                    }
                }
            }

            while (true) //stack loop
            {
                if (resolverStack.Count > maxStackCount)
                {
                    while (resolverStack.Count > 0)
                    {
                        PopStack();
                    }

                    //cache this as failure
                    cache.CacheResponse(new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { question }));

                    throw new DnsClientException("DnsClient recursive resolution exceeded the maximum stack count for domain: " + question.Name);
                }

                //query cache
                {
                    DnsDatagram cacheRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, true, DnsResponseCode.NoError, new DnsQuestionRecord[] { question }, null, null, null, udpPayloadSize, ednsFlags);
                    DnsDatagram cacheResponse = cache.Query(cacheRequest, false, true);
                    if (cacheResponse is not null)
                    {
                        switch (cacheResponse.RCODE)
                        {
                            case DnsResponseCode.NoError:
                                {
                                    if (cacheResponse.Answer.Count > 0)
                                    {
                                        if (resolverStack.Count == 0)
                                        {
                                            TriggerNsRevalidation();
                                            return cacheResponse;
                                        }
                                        else
                                        {
                                            PopStack();

                                            switch (cacheResponse.Answer[0].Type)
                                            {
                                                case DnsResourceRecordType.AAAA:
                                                    nameServers[nameServerIndex] = new NameServerAddress(nameServers[nameServerIndex].Host, new IPEndPoint((cacheResponse.Answer[0].RDATA as DnsAAAARecord).Address, nameServers[nameServerIndex].Port));
                                                    break;

                                                case DnsResourceRecordType.A:
                                                    nameServers[nameServerIndex] = new NameServerAddress(nameServers[nameServerIndex].Host, new IPEndPoint((cacheResponse.Answer[0].RDATA as DnsARecord).Address, nameServers[nameServerIndex].Port));
                                                    break;

                                                case DnsResourceRecordType.DS:
                                                    if (!TryGetDSFromResponse(cacheResponse, cacheResponse.Question[0].Name, out IReadOnlyList<DnsResourceRecord> cacheDSRecords))
                                                        throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due to unable to find DS records for owner name: " + cacheResponse.Question[0].Name, cacheResponse);

                                                    if (cacheDSRecords is null)
                                                    {
                                                        //zone is unsigned
                                                        //removing DNSSEC_OK flag
                                                        ednsFlags &= (EDnsHeaderFlags)0x7FFF;
                                                        lastDSRecords = null;
                                                    }
                                                    else if (cacheDSRecords.Count > 0)
                                                    {
                                                        lastDSRecords = cacheDSRecords;
                                                    }

                                                    break;

                                                default:
                                                    //didnt find IP for current name server
                                                    nameServerIndex++; //increment to skip current name server
                                                    break;
                                            }

                                            //proceed to resolver loop
                                        }
                                    }
                                    else if (cacheResponse.Authority.Count > 0)
                                    {
                                        DnsResourceRecord firstAuthority = cacheResponse.FindFirstAuthorityRecord();

                                        if ((firstAuthority is not null) && (firstAuthority.Type == DnsResourceRecordType.SOA))
                                        {
                                            if (resolverStack.Count == 0)
                                            {
                                                TriggerNsRevalidation();
                                                return cacheResponse;
                                            }
                                            else
                                            {
                                                if (question.Type == DnsResourceRecordType.AAAA)
                                                {
                                                    question = new DnsQuestionRecord(question.Name, DnsResourceRecordType.A, question.Class);

                                                    continue; //to stack loop to query cache for A record
                                                }
                                                else
                                                {
                                                    //NO DATA - domain does not resolve 
                                                    PopStack();

                                                    switch (cacheResponse.Question[0].Type)
                                                    {
                                                        case DnsResourceRecordType.A:
                                                        case DnsResourceRecordType.AAAA:
                                                            //didnt find IP for current name server; try next name server
                                                            nameServerIndex++; //increment to skip current name server
                                                            break;

                                                        case DnsResourceRecordType.DS:
                                                            //DS does not exists so the zone is unsigned
                                                            //removing DNSSEC_OK flag
                                                            ednsFlags &= (EDnsHeaderFlags)0x7FFF;
                                                            lastDSRecords = null;
                                                            break;
                                                    }

                                                    //proceed to resolver loop
                                                }
                                            }
                                        }
                                        else
                                        {
                                            string nextZoneCut = null;
                                            EDnsHeaderFlags nextEdnsFlags = ednsFlags;
                                            IReadOnlyList<DnsResourceRecord> nextDSRecords = lastDSRecords;
                                            List<NameServerAddress> nextNameServers = null;

                                            nextNameServers = NameServerAddress.GetNameServersFromResponse(cacheResponse, preferIPv6);
                                            InspectCacheNameServersForLoops(nextNameServers);

                                            if (nextNameServers.Count > 0)
                                            {
                                                //found name servers from response
                                                nextZoneCut = firstAuthority.Name;

                                                if (ednsFlags.HasFlag(EDnsHeaderFlags.DNSSEC_OK) && TryGetDSFromResponse(cacheResponse, nextZoneCut, out IReadOnlyList<DnsResourceRecord> cacheDsRecords))
                                                {
                                                    //get DS records from response
                                                    if (cacheDsRecords is null)
                                                    {
                                                        //removing DNSSEC_OK flag
                                                        nextEdnsFlags &= (EDnsHeaderFlags)0x7FFF;
                                                        nextDSRecords = null;
                                                    }
                                                    else if (cacheDsRecords.Count > 0)
                                                    {
                                                        //found DS records in cache
                                                        nextDSRecords = cacheDsRecords;
                                                    }
                                                }
                                            }

                                            if (nextNameServers.Count == 0)
                                            {
                                                //didnt find NS from response
                                                //find name servers with glue from cache for closest parent zone
                                                string currentDomain = question.Name;

                                                while (true)
                                                {
                                                    //get parent domain
                                                    int i = currentDomain.IndexOf('.');
                                                    if (i < 0)
                                                        break;

                                                    currentDomain = currentDomain.Substring(i + 1);

                                                    //find name servers with glue; cannot find DS with this query
                                                    DnsDatagram cachedNsResponse = cache.Query(new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(currentDomain, DnsResourceRecordType.NS, DnsClass.IN) }), false, true);
                                                    if (cachedNsResponse is null)
                                                        continue;

                                                    nextNameServers = NameServerAddress.GetNameServersFromResponse(cachedNsResponse, preferIPv6);
                                                    InspectCacheNameServersForLoops(nextNameServers);

                                                    if (nextNameServers.Count > 0)
                                                    {
                                                        //found NS for parent from cache
                                                        nextZoneCut = currentDomain;
                                                        break;
                                                    }
                                                }
                                            }

                                            if (nextNameServers.Count > 0)
                                            {
                                                //found NS and/or DS (or proof of no DS)
                                                nextNameServers.Shuffle();

                                                if (preferIPv6)
                                                    nextNameServers.Sort();

                                                if (question.ZoneCut is not null)
                                                    question.ZoneCut = nextZoneCut;

                                                zoneCut = nextZoneCut;
                                                ednsFlags = nextEdnsFlags;
                                                lastDSRecords = nextDSRecords;
                                                nameServers = nextNameServers;
                                                nameServerIndex = 0;
                                                lastResponse = null;
                                            }
                                        }
                                    }
                                    else
                                    {
                                        //both answer and authority sections are empty
                                        if (resolverStack.Count == 0)
                                        {
                                            TriggerNsRevalidation();
                                            return cacheResponse;
                                        }
                                        else
                                        {
                                            //domain does not resolve
                                            PopStack();

                                            switch (cacheResponse.Question[0].Type)
                                            {
                                                case DnsResourceRecordType.A:
                                                case DnsResourceRecordType.AAAA:
                                                    //current name server domain does not resolve
                                                    nameServerIndex++; //increment to skip current name server
                                                    break;

                                                case DnsResourceRecordType.DS:
                                                    //DS does not resolve so cannot proceed
                                                    throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due to unable to find DS records for owner name: " + cacheResponse.Question[0].Name, cacheResponse);
                                            }

                                            //proceed to resolver loop
                                        }
                                    }
                                }
                                break;

                            case DnsResponseCode.NxDomain:
                                {
                                    if (resolverStack.Count == 0)
                                    {
                                        TriggerNsRevalidation();
                                        return cacheResponse;
                                    }
                                    else
                                    {
                                        //domain does not exists
                                        PopStack();

                                        switch (cacheResponse.Question[0].Type)
                                        {
                                            case DnsResourceRecordType.A:
                                            case DnsResourceRecordType.AAAA:
                                                //current name server domain does not exists
                                                nameServerIndex++; //increment to skip current name server
                                                break;

                                            case DnsResourceRecordType.DS:
                                                //DS does not exists so the zone is unsigned
                                                //removing DNSSEC_OK flag
                                                ednsFlags &= (EDnsHeaderFlags)0x7FFF;
                                                lastDSRecords = null;
                                                break;
                                        }

                                        //proceed to resolver loop
                                        break;
                                    }
                                }

                            default:
                                {
                                    if (resolverStack.Count == 0)
                                    {
                                        TriggerNsRevalidation();
                                        return cacheResponse;
                                    }
                                    else
                                    {
                                        //domain does not resolve
                                        PopStack();

                                        switch (cacheResponse.Question[0].Type)
                                        {
                                            case DnsResourceRecordType.A:
                                            case DnsResourceRecordType.AAAA:
                                                //current name server domain does not resolve; try next name server
                                                nameServerIndex++; //increment to skip current name server
                                                break;

                                            case DnsResourceRecordType.DS:
                                                //DS does not resolve so cannot proceed
                                                throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due to unable to find DS records for owner name: " + cacheResponse.Question[0].Name, cacheResponse);
                                        }

                                        //proceed to resolver loop
                                        break;
                                    }
                                }
                        }
                    }
                }

                if ((nameServers is null) || (nameServers.Count == 0))
                {
                    //create copy of root name servers array so that the values in original array are not messed due to shuffling feature
                    IList<NameServerAddress> nameServersCopy;

                    if (preferIPv6)
                    {
                        List<NameServerAddress> nameServersList = new List<NameServerAddress>(ROOT_NAME_SERVERS_IPv6.Count + ROOT_NAME_SERVERS_IPv4.Count);

                        nameServersList.AddRange(ROOT_NAME_SERVERS_IPv6);
                        nameServersList.AddRange(ROOT_NAME_SERVERS_IPv4);
                        nameServersList.Shuffle();
                        nameServersList.Sort();

                        nameServersCopy = nameServersList;
                    }
                    else
                    {
                        List<NameServerAddress> nameServersList = new List<NameServerAddress>(ROOT_NAME_SERVERS_IPv4);
                        nameServersList.Shuffle();

                        nameServersCopy = nameServersList;
                    }

                    zoneCut = "";
                    nameServers = nameServersCopy;
                    nameServerIndex = 0;
                    lastResponse = null;
                }

                while (true) //resolver loop
                {
                    if ((lastDSRecords is not null) && !lastDSRecords[0].Name.Equals(zoneCut))
                    {
                        //find the DS for current zone cut recursively in next stack
                        PushStack(zoneCut, DnsResourceRecordType.DS);
                        goto stackLoop;
                    }

                    //query name servers one by one
                    for (; nameServerIndex < nameServers.Count; nameServerIndex++) //try next server loop
                    {
                        NameServerAddress nameServer = nameServers[nameServerIndex];

                        if (nameServer.IPEndPoint is null)
                        {
                            if (proxy is null)
                            {
                                PushStack(nameServer.Host, preferIPv6 ? DnsResourceRecordType.AAAA : DnsResourceRecordType.A);
                                goto stackLoop;
                            }
                        }
                        else if (IPAddress.IsLoopback(nameServer.IPEndPoint.Address))
                        {
                            //skip this name server since it will cause resolution loops
                            continue; //try next name server
                        }

                        DnsClient dnsClient = new DnsClient(nameServer);
                        dnsClient._proxy = proxy;
                        dnsClient._randomizeName = randomizeName;
                        dnsClient._retries = retries;
                        dnsClient._timeout = timeout;

                        DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { question }, null, null, null, udpPayloadSize, ednsFlags);
                        DnsDatagram response;

                        try
                        {
                            response = await dnsClient.InternalResolveAsync(request);

                            if (ednsFlags.HasFlag(EDnsHeaderFlags.DNSSEC_OK))
                            {
                                if ((response.EDNS is null) || !response.EDNS.Flags.HasFlag(EDnsHeaderFlags.DNSSEC_OK))
                                {
                                    //name server is not security aware
                                    continue; //try next name server
                                }

                                //dnssec validate response
                                await DnssecValidateResponseAsync(response, lastDSRecords, dnsClient, cache, udpPayloadSize);
                            }
                            else if (dnssecValidation)
                            {
                                //set insecure status
                                response.SetDnssecStatusForAllRecords(DnssecStatus.Insecure);
                            }
                            else
                            {
                                //dnssec validation is disabled
                                response.SetDnssecStatusForAllRecords(DnssecStatus.Disabled);
                            }
                        }
                        catch (DnsClientResponseDnssecValidationException ex)
                        {
                            //dnssec validation failed
                            lastException = ex;
                            continue; //try next name server
                        }
                        catch (DnsClientResponseValidationException ex)
                        {
                            if (question.ZoneCut is not null)
                            {
                                if (question.Name.Equals(question.MinimizedName, StringComparison.OrdinalIgnoreCase))
                                {
                                    if ((question.Type == DnsResourceRecordType.A) || (question.Type == DnsResourceRecordType.AAAA) || (question.Type == DnsResourceRecordType.DS))
                                    {
                                        //domain wont resolve
                                    }
                                    else
                                    {
                                        //disable QNAME minimization and query again to current server to get correct type response
                                        question.ZoneCut = null;
                                        nameServerIndex--;
                                        continue;
                                    }
                                }
                                else
                                {
                                    //use minimized name as zone cut and query again to current server to move to next label
                                    question.ZoneCut = question.MinimizedName;
                                    nameServerIndex--;
                                    continue;
                                }
                            }

                            //continue for loop to next name server since current name server may be misconfigured
                            lastException = ex;
                            continue; //try next name server
                        }
                        catch (Exception ex)
                        {
                            lastException = ex;
                            continue; //try next name server
                        }

                        //sanitize response
                        response = SanitizeResponseAnswer(response, zoneCut); //sanitize answer section
                        response = SanitizeResponseAuthority(response, zoneCut); //sanitize authority section

                        //cache response
                        cache.CacheResponse(response);

                        //set as last response
                        lastResponse = response;

                        switch (response.RCODE)
                        {
                            case DnsResponseCode.NoError:
                                {
                                    if (response.Answer.Count > 0)
                                    {
                                        if (response.Answer[0].Name.Equals(question.Name, StringComparison.OrdinalIgnoreCase) || (response.Answer[0].Type == DnsResourceRecordType.DNAME)) //checking for DNAME since response was sanitized
                                        {
                                            if ((question.Type == DnsResourceRecordType.A) || (question.Type == DnsResourceRecordType.AAAA) || (question.Type == DnsResourceRecordType.DS))
                                            {
                                                //found answer as QNAME minimization uses A, AAAA, or DS type queries
                                            }
                                            else if (question.ZoneCut is not null)
                                            {
                                                //disable QNAME minimization and query again to current server to get correct type response
                                                question.ZoneCut = null;
                                                nameServerIndex--;
                                                continue;
                                            }
                                        }
                                        else if (question.ZoneCut is not null)
                                        {
                                            //disable QNAME minimization and query again to current server
                                            question.ZoneCut = null;
                                            nameServerIndex--;
                                            continue;
                                        }
                                        else
                                        {
                                            //continue to next name server since current name server may be misconfigured
                                            continue;
                                        }

                                        if (resolverStack.Count == 0)
                                        {
                                            TriggerNsRevalidation();
                                            return response;
                                        }
                                        else
                                        {
                                            PopStack();

                                            switch (response.Answer[0].Type)
                                            {
                                                case DnsResourceRecordType.AAAA:
                                                    nameServers[nameServerIndex] = new NameServerAddress(nameServers[nameServerIndex].Host, new IPEndPoint((response.Answer[0].RDATA as DnsAAAARecord).Address, nameServers[nameServerIndex].Port));
                                                    break;

                                                case DnsResourceRecordType.A:
                                                    nameServers[nameServerIndex] = new NameServerAddress(nameServers[nameServerIndex].Host, new IPEndPoint((response.Answer[0].RDATA as DnsARecord).Address, nameServers[nameServerIndex].Port));
                                                    break;

                                                case DnsResourceRecordType.DS:
                                                    if (!TryGetDSFromResponse(response, response.Question[0].Name, out IReadOnlyList<DnsResourceRecord> dsRecords))
                                                        throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due to unable to find DS records for owner name: " + response.Question[0].Name, response);

                                                    if (dsRecords is null)
                                                    {
                                                        //zone is unsigned
                                                        ednsFlags &= (EDnsHeaderFlags)0x7FFF;
                                                        lastDSRecords = null;
                                                    }
                                                    else if (dsRecords.Count > 0)
                                                    {
                                                        lastDSRecords = dsRecords;
                                                    }

                                                    break;

                                                default:
                                                    //didnt find IP for current name server
                                                    nameServerIndex++; //increment to skip current name server
                                                    break;
                                            }

                                            goto resolverLoop;
                                        }
                                    }
                                    else if (response.Authority.Count > 0)
                                    {
                                        DnsResourceRecord firstAuthority = response.FindFirstAuthorityRecord();

                                        if (firstAuthority.Type == DnsResourceRecordType.SOA)
                                        {
                                            if (ednsFlags.HasFlag(EDnsHeaderFlags.DNSSEC_OK) && (firstAuthority.DnssecStatus == DnssecStatus.Insecure))
                                            {
                                                //found the current zone as unsigned since SOA status is insecure so disable DNSSEC validation
                                                //removing DNSSEC_OK flag
                                                ednsFlags &= (EDnsHeaderFlags)0x7FFF;
                                                lastDSRecords = null;
                                            }

                                            if (question.ZoneCut is not null)
                                            {
                                                if (question.Name.Equals(question.MinimizedName, StringComparison.OrdinalIgnoreCase))
                                                {
                                                    if ((question.Type == DnsResourceRecordType.A) || (question.Type == DnsResourceRecordType.AAAA) || (question.Type == DnsResourceRecordType.DS))
                                                    {
                                                        //record does not exists
                                                    }
                                                    else
                                                    {
                                                        //disable QNAME minimization and query again to current server to get correct type response
                                                        question.ZoneCut = null;
                                                        nameServerIndex--;
                                                        continue;
                                                    }
                                                }
                                                else
                                                {
                                                    //use minimized name as zone cut and query again to current server to move to next label
                                                    question.ZoneCut = question.MinimizedName;
                                                    nameServerIndex--;
                                                    continue;
                                                }
                                            }

                                            //NO DATA - no entry for given type
                                            if (resolverStack.Count == 0)
                                            {
                                                TriggerNsRevalidation();
                                                return response;
                                            }
                                            else
                                            {
                                                if (question.Type == DnsResourceRecordType.AAAA)
                                                {
                                                    question = new DnsQuestionRecord(question.Name, DnsResourceRecordType.A, question.Class);

                                                    //try same server again with AAAA query
                                                    nameServerIndex--;
                                                    continue;
                                                }
                                                else
                                                {
                                                    //NO DATA - domain does not resolve 
                                                    PopStack();

                                                    switch (response.Question[0].Type)
                                                    {
                                                        case DnsResourceRecordType.A:
                                                        case DnsResourceRecordType.AAAA:
                                                            //didnt find IP for current name server; try next name server
                                                            nameServerIndex++; //increment to skip current name server
                                                            break;

                                                        case DnsResourceRecordType.DS:
                                                            //DS does not exists so the zone is unsigned
                                                            //removing DNSSEC_OK flag
                                                            ednsFlags &= (EDnsHeaderFlags)0x7FFF;
                                                            lastDSRecords = null;
                                                            break;
                                                    }

                                                    goto resolverLoop;
                                                }
                                            }
                                        }
                                        else
                                        {
                                            //check if empty response was received from the authoritative name server
                                            foreach (DnsResourceRecord authorityRecord in response.Authority)
                                            {
                                                if ((authorityRecord.Type == DnsResourceRecordType.NS) && (authorityRecord.RDATA as DnsNSRecord).NameServer.Equals(response.Metadata.NameServerAddress.Host, StringComparison.OrdinalIgnoreCase))
                                                {
                                                    //empty response from authoritative name server
                                                    if (resolverStack.Count == 0)
                                                    {
                                                        TriggerNsRevalidation();
                                                        return response;
                                                    }
                                                    else
                                                    {
                                                        //unable to resolve current name server domain
                                                        //pop and try next name server
                                                        PopStack();
                                                        nameServerIndex++; //increment to skip current name server

                                                        goto resolverLoop;
                                                    }
                                                }
                                            }

                                            //check for hop limit
                                            if (hopCount >= MAX_DELEGATION_HOPS)
                                            {
                                                //max hop count reached
                                                if (resolverStack.Count == 0)
                                                {
                                                    //cannot proceed forever; return what we have and stop
                                                    TriggerNsRevalidation();
                                                    return response;
                                                }
                                                else
                                                {
                                                    //unable to resolve current name server domain due to hop limit
                                                    //pop and try next name server
                                                    PopStack();
                                                    nameServerIndex++; //increment to skip current name server

                                                    goto resolverLoop;
                                                }
                                            }

                                            //get next hop name servers
                                            List<NameServerAddress> nextNameServers = NameServerAddress.GetNameServersFromResponse(response, preferIPv6);

                                            if (nextNameServers.Count > 0)
                                            {
                                                string nextZoneCut = firstAuthority.Name;

                                                EDnsHeaderFlags nextEdnsFlags = ednsFlags;
                                                IReadOnlyList<DnsResourceRecord> nextDSRecords = lastDSRecords;

                                                if (ednsFlags.HasFlag(EDnsHeaderFlags.DNSSEC_OK))
                                                {
                                                    if (!TryGetDSFromResponse(response, nextZoneCut, out IReadOnlyList<DnsResourceRecord> dsRecords))
                                                    {
                                                        //current name server didnt return DS that was expected; try next server
                                                        //continue for loop to next name server since current name server may be misconfigured
                                                        continue;
                                                    }

                                                    if (dsRecords is null)
                                                    {
                                                        //next zone cut is validated to be unsigned
                                                        //removing DNSSEC_OK flag
                                                        nextEdnsFlags = ednsFlags & (EDnsHeaderFlags)0x7FFF;
                                                        nextDSRecords = null;
                                                    }
                                                    else if (dsRecords.Count > 0)
                                                    {
                                                        nextDSRecords = dsRecords;
                                                    }
                                                }

                                                nextNameServers.Shuffle();

                                                if (preferIPv6)
                                                    nextNameServers.Sort();

                                                if (question.ZoneCut is not null)
                                                    question.ZoneCut = nextZoneCut;

                                                zoneCut = nextZoneCut;
                                                ednsFlags = nextEdnsFlags;
                                                lastDSRecords = nextDSRecords;
                                                nameServers = nextNameServers;
                                                nameServerIndex = 0;
                                                hopCount++;
                                                lastResponse = null; //reset last response for current zone cut

                                                //add to NS revalidation task list
                                                if (asyncNsRevalidation)
                                                    nsRevalidationTasks.TryAdd(zoneCut.ToLower(), nextNameServers);

                                                goto resolverLoop;
                                            }

                                            //continue for loop to next name server since current name server may be misconfigured
                                            break;
                                        }
                                    }
                                    else
                                    {
                                        //empty response: no answer, no authority
                                        if (question.ZoneCut is not null)
                                        {
                                            if (question.Name.Equals(question.MinimizedName, StringComparison.OrdinalIgnoreCase))
                                            {
                                                if ((question.Type == DnsResourceRecordType.A) || (question.Type == DnsResourceRecordType.AAAA) || (question.Type == DnsResourceRecordType.DS))
                                                {
                                                    //record does not exists
                                                }
                                                else
                                                {
                                                    //disable QNAME minimization and query again to current server to get correct type response
                                                    question.ZoneCut = null;
                                                    nameServerIndex--;
                                                    continue;
                                                }
                                            }
                                            else
                                            {
                                                //use minimized name as zone cut and query again to current server to move to next label
                                                question.ZoneCut = question.MinimizedName;
                                                nameServerIndex--;
                                                continue;
                                            }
                                        }

                                        //continue for loop to next name server since current name server may be misconfigured
                                        break;
                                    }
                                }

                            case DnsResponseCode.NxDomain:
                                {
                                    if (question.ZoneCut is not null)
                                    {
                                        if (question.Name.Equals(question.MinimizedName, StringComparison.OrdinalIgnoreCase))
                                        {
                                            //domain does not exists
                                        }
                                        else
                                        {
                                            //disable QNAME minimization and query again to current server to confirm full name response
                                            question.ZoneCut = null;
                                            nameServerIndex--;
                                            continue;
                                        }
                                    }

                                    if (resolverStack.Count == 0)
                                    {
                                        TriggerNsRevalidation();
                                        return response;
                                    }
                                    else
                                    {
                                        //domain does not exists
                                        PopStack();

                                        switch (response.Question[0].Type)
                                        {
                                            case DnsResourceRecordType.A:
                                            case DnsResourceRecordType.AAAA:
                                                //current name server domain does not exists
                                                nameServerIndex++; //increment to skip current name server
                                                break;

                                            case DnsResourceRecordType.DS:
                                                //DS does not exists so the zone is unsigned
                                                //removing DNSSEC_OK flag
                                                ednsFlags &= (EDnsHeaderFlags)0x7FFF;
                                                lastDSRecords = null;
                                                break;
                                        }

                                        goto resolverLoop;
                                    }
                                }

                            default:
                                {
                                    if (question.ZoneCut is not null)
                                    {
                                        if (question.Name.Equals(question.MinimizedName, StringComparison.OrdinalIgnoreCase))
                                        {
                                            if ((question.Type == DnsResourceRecordType.A) || (question.Type == DnsResourceRecordType.AAAA) || (question.Type == DnsResourceRecordType.DS))
                                            {
                                                //domain wont resolve
                                            }
                                            else
                                            {
                                                //disable QNAME minimization and query again to current server to get correct type response
                                                question.ZoneCut = null;
                                                nameServerIndex--;
                                                continue;
                                            }
                                        }
                                        else
                                        {
                                            //use minimized name as zone cut and query again to current server to move to next label
                                            question.ZoneCut = question.MinimizedName;
                                            nameServerIndex--;
                                            continue;
                                        }
                                    }

                                    //continue for loop to next name server since current name server may be misconfigured
                                    break;
                                }
                        }
                    }

                    //no successfull response was received from any of the name servers
                    if (resolverStack.Count == 0)
                    {
                        TriggerNsRevalidation();

                        if (lastResponse is not null)
                        {
                            if (lastResponse.Question[0].Equals(question))
                                return lastResponse;
                        }

                        string strNameServers = null;

                        foreach (NameServerAddress nameServer in nameServers)
                        {
                            if (strNameServers is null)
                                strNameServers = nameServer.ToString();
                            else
                                strNameServers += ", " + nameServer.ToString();
                        }

                        if (lastException is DnsClientResponseDnssecValidationException ex && (ex.Response.Question.Count > 0) && ex.Response.Question[0].Equals(question))
                        {
                            //cache as bad cache
                            cache.CacheResponse(ex.Response, true);
                        }
                        else
                        {
                            //cache as failure
                            cache.CacheResponse(new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { question }));
                        }

                        throw new DnsClientException("DnsClient recursive resolution failed: no response from name servers [" + strNameServers + "]", lastException);
                    }
                    else
                    {
                        DnsQuestionRecord lastQuestion = question;
                        PopStack();

                        switch (lastQuestion.Type)
                        {
                            case DnsResourceRecordType.A:
                            case DnsResourceRecordType.AAAA:
                                //current name server domain does not resolve; try next name server
                                nameServerIndex++; //increment to skip current name server
                                break;

                            case DnsResourceRecordType.DS:
                                //DS does not resolve so cannot proceed

                                //cache as failure
                                cache.CacheResponse(new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { question }));

                                throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due to unable to find DS records for owner name: " + lastQuestion.Name, null);
                        }

                        //proceed to resolver loop
                    }

                    resolverLoop:;
                }

                stackLoop:;
            }
        }

        public static Task<DnsDatagram> RecursiveResolveQueryAsync(DnsQuestionRecord question, IDnsCache cache = null, NetProxy proxy = null, bool preferIPv6 = false, ushort udpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE, bool randomizeName = false, bool qnameMinimization = false, bool asyncNsRevalidation = false, bool dnssecValidation = false, int retries = 2, int timeout = 2000, int maxStackCount = 16)
        {
            if (cache is null)
                cache = new DnsCache();

            return ResolveQueryAsync(question, delegate (DnsQuestionRecord q)
            {
                return RecursiveResolveAsync(q, cache, proxy, preferIPv6, udpPayloadSize, randomizeName, qnameMinimization, asyncNsRevalidation, dnssecValidation, retries, timeout, maxStackCount);
            });
        }

        public static async Task<IReadOnlyList<IPAddress>> RecursiveResolveIPAsync(string domain, IDnsCache cache = null, NetProxy proxy = null, bool preferIPv6 = false, ushort udpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE, bool randomizeName = false, bool qnameMinimization = false, bool asyncNsRevalidation = false, bool dnssecValidation = false, int retries = 2, int timeout = 2000, int maxStackCount = 16)
        {
            if (cache is null)
                cache = new DnsCache();

            if (preferIPv6)
            {
                IReadOnlyList<IPAddress> addresses = ParseResponseAAAA(await RecursiveResolveQueryAsync(new DnsQuestionRecord(domain, DnsResourceRecordType.AAAA, DnsClass.IN), cache, proxy, preferIPv6, udpPayloadSize, randomizeName, qnameMinimization, asyncNsRevalidation, dnssecValidation, retries, timeout, maxStackCount));
                if (addresses.Count > 0)
                    return addresses;
            }

            return ParseResponseA(await RecursiveResolveQueryAsync(new DnsQuestionRecord(domain, DnsResourceRecordType.A, DnsClass.IN), cache, proxy, preferIPv6, udpPayloadSize, randomizeName, qnameMinimization, asyncNsRevalidation, dnssecValidation, retries, timeout, maxStackCount));
        }

        public static async Task<IReadOnlyList<IPAddress>> ResolveIPAsync(IDnsClient dnsClient, string domain, bool preferIPv6 = false)
        {
            if (preferIPv6)
            {
                IReadOnlyList<IPAddress> addresses = ParseResponseAAAA(await dnsClient.ResolveAsync(new DnsQuestionRecord(domain, DnsResourceRecordType.AAAA, DnsClass.IN)));
                if (addresses.Count > 0)
                    return addresses;
            }

            return ParseResponseA(await dnsClient.ResolveAsync(new DnsQuestionRecord(domain, DnsResourceRecordType.A, DnsClass.IN)));
        }

        public static async Task<IReadOnlyList<string>> ResolveMXAsync(IDnsClient dnsClient, string domain, bool resolveIP = false, bool preferIPv6 = false)
        {
            if (IPAddress.TryParse(domain, out _))
            {
                //host is valid ip address
                return new string[] { domain };
            }

            DnsDatagram response = await dnsClient.ResolveAsync(new DnsQuestionRecord(domain, DnsResourceRecordType.MX, DnsClass.IN));
            IReadOnlyList<string> mxEntries = ParseResponseMX(response);

            if (!resolveIP)
                return mxEntries;

            //resolve IP addresses
            List<string> mxAddresses = new List<string>(preferIPv6 ? mxEntries.Count * 2 : mxEntries.Count);

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
                        IReadOnlyList<IPAddress> ipList = await ResolveIPAsync(dnsClient, mxEntry, preferIPv6);

                        foreach (IPAddress ip in ipList)
                            mxAddresses.Add(ip.ToString());
                    }
                    catch (DnsClientException)
                    { }
                }
            }

            return mxAddresses;
        }

        public static IReadOnlyList<IPAddress> ParseResponseA(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return Array.Empty<IPAddress>();

                    List<IPAddress> ipAddresses = new List<IPAddress>(response.Answer.Count);

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
                                    domain = ((DnsCNAMERecord)record.RDATA).Domain;
                                    break;
                            }
                        }
                    }

                    return ipAddresses;

                case DnsResponseCode.NxDomain:
                    throw new NameErrorDnsClientException("Domain does not exists: " + domain + (response.Metadata is null ? "" : "; Name server: " + response.Metadata.NameServerAddress.ToString()));

                default:
                    throw new DnsClientException("Name server returned error. DNS RCODE: " + response.RCODE + " (" + (int)response.RCODE + ")" + (response.Metadata is null ? "" : "; Name server: " + response.Metadata.NameServerAddress.ToString()));
            }
        }

        public static IReadOnlyList<IPAddress> ParseResponseAAAA(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return Array.Empty<IPAddress>();

                    List<IPAddress> ipAddresses = new List<IPAddress>(response.Answer.Count);

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
                                    domain = ((DnsCNAMERecord)record.RDATA).Domain;
                                    break;
                            }
                        }
                    }

                    return ipAddresses;

                case DnsResponseCode.NxDomain:
                    throw new NameErrorDnsClientException("Domain does not exists: " + domain + (response.Metadata is null ? "" : "; Name server: " + response.Metadata.NameServerAddress.ToString()));

                default:
                    throw new DnsClientException("Name server returned error. DNS RCODE: " + response.RCODE + " (" + (int)response.RCODE + ")" + (response.Metadata is null ? "" : "; Name server: " + response.Metadata.NameServerAddress.ToString()));
            }
        }

        public static IReadOnlyList<string> ParseResponseTXT(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return Array.Empty<string>();

                    List<string> txtRecords = new List<string>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.TXT:
                                    txtRecords.Add(((DnsTXTRecord)record.RDATA).Text);
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = ((DnsCNAMERecord)record.RDATA).Domain;
                                    break;
                            }
                        }
                    }

                    return txtRecords;

                case DnsResponseCode.NxDomain:
                    throw new NameErrorDnsClientException("Domain does not exists: " + domain + (response.Metadata is null ? "" : "; Name server: " + response.Metadata.NameServerAddress.ToString()));

                default:
                    throw new DnsClientException("Name server returned error. DNS RCODE: " + response.RCODE + " (" + (int)response.RCODE + ")" + (response.Metadata is null ? "" : "; Name server: " + response.Metadata.NameServerAddress.ToString()));
            }
        }

        public static IReadOnlyList<string> ParseResponsePTR(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return Array.Empty<string>();

                    List<string> values = new List<string>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.PTR:
                                    values.Add(((DnsPTRRecord)record.RDATA).Domain);
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = ((DnsCNAMERecord)record.RDATA).Domain;
                                    break;
                            }
                        }
                    }

                    return values;

                case DnsResponseCode.NxDomain:
                    throw new NameErrorDnsClientException("Domain does not exists: " + domain + (response.Metadata is null ? "" : "; Name server: " + response.Metadata.NameServerAddress.ToString()));

                default:
                    throw new DnsClientException("Name server returned error. DNS RCODE: " + response.RCODE + " (" + (int)response.RCODE + ")" + (response.Metadata is null ? "" : "; Name server: " + response.Metadata.NameServerAddress.ToString()));
            }
        }

        public static IReadOnlyList<string> ParseResponseMX(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return Array.Empty<string>();

                    List<DnsMXRecord> mxRecords = new List<DnsMXRecord>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.MX:
                                    mxRecords.Add((DnsMXRecord)record.RDATA);
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = ((DnsCNAMERecord)record.RDATA).Domain;
                                    break;
                            }
                        }
                    }

                    if (mxRecords.Count > 0)
                    {
                        //sort by mx preference
                        mxRecords.Sort();

                        string[] mxEntries = new string[mxRecords.Count];

                        for (int i = 0; i < mxEntries.Length; i++)
                            mxEntries[i] = mxRecords[i].Exchange;

                        return mxEntries;
                    }

                    return Array.Empty<string>();

                case DnsResponseCode.NxDomain:
                    throw new NameErrorDnsClientException("Domain does not exists: " + domain + (response.Metadata is null ? "" : "; Name server: " + response.Metadata.NameServerAddress.ToString()));

                default:
                    throw new DnsClientException("Name server returned error. DNS RCODE: " + response.RCODE + " (" + (int)response.RCODE + ")" + (response.Metadata is null ? "" : "; Name server: " + response.Metadata.NameServerAddress.ToString()));
            }
        }

        public static IReadOnlyList<IPAddress> GetSystemDnsServers(bool preferIPv6 = false)
        {
            List<IPAddress> dnsAddresses = new List<IPAddress>();

            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;

                foreach (IPAddress dnsAddress in nic.GetIPProperties().DnsAddresses)
                {
                    if (!preferIPv6 && (dnsAddress.AddressFamily == AddressFamily.InterNetworkV6))
                        continue;

                    if ((dnsAddress.AddressFamily == AddressFamily.InterNetworkV6) && dnsAddress.IsIPv6SiteLocal)
                        continue;

                    if (!dnsAddresses.Contains(dnsAddress))
                        dnsAddresses.Add(dnsAddress);
                }
            }

            return dnsAddresses;
        }

        public static bool IsDomainNameValid(string domain, bool throwException = false)
        {
            if (domain is null)
            {
                if (throwException)
                    throw new ArgumentNullException(nameof(domain));

                return false;
            }

            if (domain.Length == 0)
                return true; //domain is root zone

            if (domain.Length > 255)
            {
                if (throwException)
                    throw new DnsClientException("Invalid domain name [" + domain + "]: length cannot exceed 255 bytes.");

                return false;
            }

            int labelStart = 0;
            int labelEnd;
            int labelLength;
            int labelChar;
            int i;

            do
            {
                labelEnd = domain.IndexOf('.', labelStart);
                if (labelEnd < 0)
                    labelEnd = domain.Length;

                labelLength = labelEnd - labelStart;

                if (labelLength == 0)
                {
                    if (throwException)
                        throw new DnsClientException("Invalid domain name [" + domain + "]: label length cannot be 0 byte.");

                    return false;
                }

                if (labelLength > 63)
                {
                    if (throwException)
                        throw new DnsClientException("Invalid domain name [" + domain + "]: label length cannot exceed 63 bytes.");

                    return false;
                }

                if (domain[labelStart] == '-')
                {
                    if (throwException)
                        throw new DnsClientException("Invalid domain name [" + domain + "]: label cannot start with hyphen.");

                    return false;
                }

                if (domain[labelEnd - 1] == '-')
                {
                    if (throwException)
                        throw new DnsClientException("Invalid domain name [" + domain + "]: label cannot end with hyphen.");

                    return false;
                }

                if (labelLength != 1 || domain[labelStart] != '*')
                {
                    for (i = labelStart; i < labelEnd; i++)
                    {
                        labelChar = domain[i];

                        if ((labelChar >= 97) && (labelChar <= 122)) //[a-z]
                            continue;

                        if ((labelChar >= 65) && (labelChar <= 90)) //[A-Z]
                            continue;

                        if ((labelChar >= 48) && (labelChar <= 57)) //[0-9]
                            continue;

                        if (labelChar == 45) //[-]
                            continue;

                        if (labelChar == 95) //[_]
                            continue;

                        if (throwException)
                            throw new DnsClientException("Invalid domain name [" + domain + "]: invalid character [" + labelChar + "] was found.");

                        return false;
                    }
                }

                labelStart = labelEnd + 1;
            }
            while (labelEnd < domain.Length);

            return true;
        }

        #endregion

        #region private

        private static string PopWord(ref string line)
        {
            if (line.Length == 0)
                return line;

            line = line.TrimStart(' ', '\t');

            int i = line.IndexOfAny(new char[] { ' ', '\t' });
            string word;

            if (i < 0)
            {
                word = line;
                line = "";
            }
            else
            {
                word = line.Substring(0, i);
                line = line.Substring(i + 1);
            }

            return word;
        }

        private static async Task DnssecValidateResponseAsync(DnsDatagram response, IReadOnlyList<DnsResourceRecord> lastDSRecords, DnsClient dnsClient, IDnsCache cache, ushort udpPayloadSize)
        {
            //find current DNSKEY
            IReadOnlyList<DnsResourceRecord> currentDnsKeyRecords = await GetDnsKeyForAsync(lastDSRecords, dnsClient, cache, udpPayloadSize);

            string lastDSOwnerName = lastDSRecords[0].Name;
            DnsClass @class = response.Question[0].Class;
            List<DnsResourceRecord> allDnsKeyRecords = new List<DnsResourceRecord>(4);
            List<string> unsignedZones = null;

            //add current dns key
            allDnsKeyRecords.AddRange(currentDnsKeyRecords);

            //find signer's names for verification
            List<string> signersNames = new List<string>();

            FindSignersNames(response, signersNames);

            //find DNSKEYs for all signers that are sub domain names for last DS record owner name
            foreach (string signersName in signersNames)
            {
                if (!signersName.Equals(lastDSOwnerName, StringComparison.OrdinalIgnoreCase) && (signersName.EndsWith("." + lastDSOwnerName, StringComparison.OrdinalIgnoreCase) || (lastDSOwnerName.Length == 0)))
                {
                    //signer's name is a subdomain for last DS record owner name
                    //find DNSKEY
                    IReadOnlyList<DnsResourceRecord> dnsKeyRecords = await FindDnsKeyForAsync(signersName, @class, currentDnsKeyRecords, dnsClient, cache, udpPayloadSize);
                    if (dnsKeyRecords is null)
                    {
                        if (unsignedZones is null)
                            unsignedZones = new List<string>(2);

                        unsignedZones.Add(signersName);
                    }
                    else
                    {
                        allDnsKeyRecords.AddRange(dnsKeyRecords);
                    }
                }
            }

            //verify signature for all records in response
            DnssecValidateSignature(response, allDnsKeyRecords, unsignedZones);

            //validate proofs for response
            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count > 0)
                    {
                        foreach (DnsResourceRecord record in response.Answer)
                        {
                            if (record.Type != DnsResourceRecordType.RRSIG)
                                continue;

                            if (DnsRRSIGRecord.IsWildcard(record, out string nextCloserName))
                            {
                                //For every wildcard expansion, we need to prove that the expansion was allowed.

                                //validate wildcard
                                DnssecProofOfNonExistence proofOfNonExistence = GetValidatedProofOfNonExistence(response.Authority, record.Name, (record.RDATA as DnsRRSIGRecord).TypeCovered, true, nextCloserName);
                                switch (proofOfNonExistence)
                                {
                                    case DnssecProofOfNonExistence.OptOut:
                                    case DnssecProofOfNonExistence.NxDomain:
                                        //record does not exists so wildcard is valid
                                        break;

                                    default:
                                        throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed as the response was unable to prove non-existence (Wildcard) for owner name: " + record.Name + "/" + record.Type, response);
                                }
                            }
                        }
                    }
                    else if (response.Authority.Count > 0)
                    {
                        DnsQuestionRecord question = response.Question[0];
                        DnsResourceRecord firstAuthority = response.FindFirstAuthorityRecord();

                        switch (firstAuthority.Type)
                        {
                            case DnsResourceRecordType.SOA:
                                {
                                    //NO DATA

                                    if (IsDomainUnsigned(question.Name, unsignedZones))
                                        break;

                                    DnssecProofOfNonExistence proofOfNonExistence = GetValidatedProofOfNonExistence(response.Authority, question.Name, question.Type);
                                    switch (proofOfNonExistence)
                                    {
                                        case DnssecProofOfNonExistence.OptOut:
                                        case DnssecProofOfNonExistence.NoData:
                                        case DnssecProofOfNonExistence.InsecureDelegation: //proves no DS record exists
                                        case DnssecProofOfNonExistence.NxDomain: //proves NO DATA due to empty non terminal (ENT) caused by qname minimization
                                            //no data for the type was found
                                            break;

                                        default:
                                            throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed as the response was unable to prove non-existence (No Data) for owner name: " + question.Name + "/" + question.Type.ToString(), response);
                                    }
                                }
                                break;

                            case DnsResourceRecordType.NS:
                                {
                                    //validate if DS records are really missing
                                    DnssecProofOfNonExistence proofOfNonExistence = GetValidatedProofOfNonExistence(response.Authority, question.Name, DnsResourceRecordType.DS);
                                    switch (proofOfNonExistence)
                                    {
                                        case DnssecProofOfNonExistence.InsecureDelegation:
                                        case DnssecProofOfNonExistence.OptOut:
                                        case DnssecProofOfNonExistence.NoData:
                                            //proved that DS is missing and the zone is unsigned
                                            //mark NS records as Insecure as a signal to identify the unsigned zone cut
                                            foreach (DnsResourceRecord record in response.Authority)
                                            {
                                                if (record.Type == DnsResourceRecordType.NS)
                                                    record.SetDnssecStatus(DnssecStatus.Insecure, true);
                                            }

                                            break;
                                    }
                                }
                                break;

                            default:
                                throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed as the response was unable to prove non-existence (No Data) for owner name: " + question.Name + "/" + question.Type.ToString(), response);
                        }
                    }

                    break;

                case DnsResponseCode.NxDomain:
                    {
                        DnsQuestionRecord question = response.Question[0];

                        if (IsDomainUnsigned(question.Name, unsignedZones))
                            break;

                        DnssecProofOfNonExistence proofOfNonExistence = GetValidatedProofOfNonExistence(response.Authority, question.Name, question.Type);
                        switch (proofOfNonExistence)
                        {
                            case DnssecProofOfNonExistence.OptOut:
                            case DnssecProofOfNonExistence.NxDomain:
                                //domain does not exists or could not prove it exists due to opt-opt
                                break;

                            default:
                                throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed as the response was unable to prove non-existence (NX Domain) for owner name: " + question.Name, response);
                        }
                    }
                    break;
            }
        }

        private static void DnssecValidateSignature(DnsDatagram response, IReadOnlyList<DnsResourceRecord> dnsKeyRecords, IReadOnlyList<string> unsignedZones)
        {
            //verify signature for all records in response
            if (response.Answer.Count > 0)
                DnssecValidateSignature(response, response.Answer, dnsKeyRecords, unsignedZones, false, false);

            if (response.Authority.Count > 0)
                DnssecValidateSignature(response, response.Authority, dnsKeyRecords, unsignedZones, true, false);

            if (response.Additional.Count > 1) //OPT record always exists
                DnssecValidateSignature(response, response.Additional, dnsKeyRecords, unsignedZones, false, true);

            //update all record status
            response.SetDnssecStatusForAllRecords(DnssecStatus.Indeterminate);
        }

        private static void DnssecValidateSignature(DnsDatagram response, IReadOnlyList<DnsResourceRecord> records, IReadOnlyList<DnsResourceRecord> dnsKeyRecords, IReadOnlyList<string> unsignedZones, bool isAuthoritySection, bool isAdditionalSection)
        {
            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedRecords = DnsResourceRecord.GroupRecords(records);

            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedRecord in groupedRecords)
            {
                string ownerName = groupedRecord.Key;
                Dictionary<DnsResourceRecordType, List<DnsResourceRecord>> rrsets = groupedRecord.Value;

                if (IsDomainUnsigned(ownerName, unsignedZones))
                {
                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> rrset in rrsets)
                        foreach (DnsResourceRecord record in rrset.Value)
                            record.SetDnssecStatus(DnssecStatus.Insecure);

                    continue;
                }

                foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> rrset in rrsets)
                {
                    DnsResourceRecordType rrsetType = rrset.Key;

                    switch (rrsetType)
                    {
                        case DnsResourceRecordType.RRSIG:
                            continue;

                        case DnsResourceRecordType.OPT:
                            foreach (DnsResourceRecord record in rrset.Value)
                                record.SetDnssecStatus(DnssecStatus.Indeterminate);

                            continue;
                    }

                    if (isAuthoritySection && (response.Answer.Count == 0) && (rrsetType == DnsResourceRecordType.NS))
                    {
                        //referrer NS records are never signed

                        foreach (DnsResourceRecord record in rrset.Value)
                            record.SetDnssecStatus(DnssecStatus.Indeterminate);

                        continue;
                    }

                    DnsClass rrsetClass = rrset.Value[0].Class;
                    bool foundValidSignature = false;
                    bool isSignatureInvalid = false;

                    //find RRSIG for current RRSET
                    foreach (DnsResourceRecord rrsigRecord in records)
                    {
                        if (rrsigRecord.Type != DnsResourceRecordType.RRSIG)
                            continue;

                        //The RRSIG RR and the RRset MUST have the same owner name and the same class.
                        if (rrsigRecord.Name.Equals(ownerName, StringComparison.OrdinalIgnoreCase) && (rrsigRecord.Class == rrsetClass))
                        {
                            DnsRRSIGRecord rrsig = rrsigRecord.RDATA as DnsRRSIGRecord;

                            //The RRSIG RR's Signer's Name field MUST be the name of the zone that contains the RRset.
                            if ((rrsig.SignersName.Length > 0) && !ownerName.Equals(rrsig.SignersName, StringComparison.OrdinalIgnoreCase) && !ownerName.EndsWith("." + rrsig.SignersName, StringComparison.OrdinalIgnoreCase))
                                continue;

                            //The RRSIG RR's Type Covered field MUST equal the RRset's type.
                            if (rrsig.TypeCovered != rrsetType)
                                continue;

                            //validate records
                            DnssecSignatureStatus signatureStatus = rrsig.IsSignatureValid(rrset.Value, dnsKeyRecords);
                            switch (signatureStatus)
                            {
                                case DnssecSignatureStatus.Valid:
                                    foundValidSignature = true;
                                    rrsigRecord.SetDnssecStatus(DnssecStatus.Secure);
                                    break;

                                case DnssecSignatureStatus.Bogus:
                                    isSignatureInvalid = true;
                                    rrsigRecord.SetDnssecStatus(DnssecStatus.Bogus);
                                    break;

                                case DnssecSignatureStatus.NoDnsKey:
                                    rrsigRecord.SetDnssecStatus(DnssecStatus.Indeterminate);
                                    break;

                                default:
                                    throw new InvalidOperationException();
                            }
                        }
                    }

                    if (!foundValidSignature)
                    {
                        if (isSignatureInvalid)
                        {
                            //RRSIG with invalid signature

                            foreach (DnsResourceRecord record in rrset.Value)
                                record.SetDnssecStatus(DnssecStatus.Bogus);

                            if (!isAdditionalSection)
                                throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due to invalid signature for owner name: " + ownerName + "/" + rrsetType, response);
                        }
                        else
                        {
                            //missing RRSIG for the RRSet

                            if ((rrsetType == DnsResourceRecordType.CNAME) && rrsets.TryGetValue(DnsResourceRecordType.DNAME, out List<DnsResourceRecord> dnameRRset))
                            {
                                //check if CNAME was synthesized from DNAME
                                DnsResourceRecord cnameRecord = rrset.Value[0];
                                DnsResourceRecord dnameRecord = dnameRRset[0];

                                string synthesizedCNAME = (dnameRecord.RDATA as DnsDNAMERecord).Substitute(cnameRecord.Name, dnameRecord.Name);
                                string CNAME = (cnameRecord.RDATA as DnsCNAMERecord).Domain;

                                if (synthesizedCNAME.Equals(CNAME, StringComparison.OrdinalIgnoreCase))
                                {
                                    //found CNAME synthesized from DNAME
                                    cnameRecord.SetDnssecStatus(DnssecStatus.Secure);

                                    continue; //continue to next rrset
                                }
                            }

                            foreach (DnsResourceRecord record in rrset.Value)
                                record.SetDnssecStatus(DnssecStatus.Indeterminate);

                            if (!isAuthoritySection && !isAdditionalSection)
                                throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due to missing RRSIG for owner name: " + ownerName + "/" + rrsetType, response);
                        }
                    }
                }
            }
        }

        private static async Task<IReadOnlyList<DnsResourceRecord>> FindDnsKeyForAsync(string ownerName, DnsClass @class, IReadOnlyList<DnsResourceRecord> currentDnsKeyRecords, DnsClient dnsClient, IDnsCache cache, ushort udpPayloadSize)
        {
            string dnsKeyOwnerName = currentDnsKeyRecords[0].Name;

            if (ownerName.Equals(dnsKeyOwnerName) || ((dnsKeyOwnerName.Length > 0) && !ownerName.EndsWith("." + dnsKeyOwnerName)))
                throw new InvalidOperationException();

            string[] labels = ownerName.Split('.');
            string nextDomain = null;

            for (int i = 0; i < labels.Length; i++)
            {
                if (nextDomain is null)
                    nextDomain = labels[labels.Length - 1 - i];
                else
                    nextDomain = labels[labels.Length - 1 - i] + "." + nextDomain;

                if (nextDomain.Length <= dnsKeyOwnerName.Length)
                    continue; //continue till current DNSKEY domain name

                //find DS
                IReadOnlyList<DnsResourceRecord> nextDSRecords = await GetDSForAsync(nextDomain, @class, currentDnsKeyRecords, dnsClient, cache, udpPayloadSize);

                if (nextDSRecords is null)
                {
                    //zone is validated to be unsigned
                    return null;
                }
                else if (nextDSRecords.Count > 0)
                {
                    //get next DNSKEY
                    currentDnsKeyRecords = await GetDnsKeyForAsync(nextDSRecords, dnsClient, cache, udpPayloadSize);
                }
                else
                {
                    //NO DATA; must be a subdomain so next DNSKEY remains same
                }
            }

            return currentDnsKeyRecords;
        }

        private static async Task<IReadOnlyList<DnsResourceRecord>> GetDnsKeyForAsync(IReadOnlyList<DnsResourceRecord> lastDSRecords, DnsClient dnsClient, IDnsCache cache, ushort udpPayloadSize)
        {
            DnsResourceRecord lastDSRecord = lastDSRecords[0];
            DnsQuestionRecord dnsKeyQuestion = new DnsQuestionRecord(lastDSRecord.Name, DnsResourceRecordType.DNSKEY, lastDSRecord.Class);
            DnsDatagram dnsKeyRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, true, DnsResponseCode.NoError, new DnsQuestionRecord[] { dnsKeyQuestion }, null, null, null, udpPayloadSize, EDnsHeaderFlags.DNSSEC_OK);

            //query cache
            DnsDatagram cachedDnsKeyResponse = QueryCache(cache, dnsKeyRequest);
            if (cachedDnsKeyResponse is not null)
                return cachedDnsKeyResponse.Answer; //found in cache

            //query name server
            DnsDatagram dnsKeyResponse = await dnsClient.InternalResolveAsync(dnsKeyRequest);
            if (dnsKeyResponse.Answer.Count == 0)
                throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due to unable to find DNSKEY records for owner name: " + dnsKeyQuestion.Name, dnsKeyResponse);

            //validate DNSKEY using DS digest
            bool foundValidDnsKey = false;

            foreach (DnsResourceRecord dnsKeyRecord in dnsKeyResponse.Answer)
            {
                if (dnsKeyRecord.Type != DnsResourceRecordType.DNSKEY)
                    continue;

                DnsDNSKEYRecord dnsKey = dnsKeyRecord.RDATA as DnsDNSKEYRecord;

                foreach (DnsResourceRecord dsRecord in lastDSRecords)
                {
                    if (!dsRecord.Name.Equals(dnsKeyQuestion.Name, StringComparison.OrdinalIgnoreCase))
                        continue;

                    DnsDSRecord ds = dsRecord.RDATA as DnsDSRecord;

                    if ((ds.KeyTag == dnsKey.ComputedKeyTag) && (ds.Algorithm == dnsKey.Algorithm) && dnsKey.IsDnsKeyValid(dnsKeyRecord.Name, ds))
                    {
                        foundValidDnsKey = true;
                        break;
                    }
                }

                if (foundValidDnsKey)
                    break;
            }

            if (!foundValidDnsKey)
                throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due to unable to find a valid DNSKEY record for owner name: " + dnsKeyQuestion.Name, dnsKeyResponse);

            //validate signature for DNSKEY response
            DnssecValidateSignature(dnsKeyResponse, dnsKeyResponse.Answer, null);

            cache.CacheResponse(dnsKeyResponse);

            return dnsKeyResponse.Answer;
        }

        private static async Task<IReadOnlyList<DnsResourceRecord>> GetDSForAsync(string ownerName, DnsClass @class, IReadOnlyList<DnsResourceRecord> currentDnsKeyRecords, DnsClient dnsClient, IDnsCache cache, ushort udpPayloadSize)
        {
            string dnsKeyOwnerName = currentDnsKeyRecords[0].Name;

            if (ownerName.Equals(dnsKeyOwnerName) || ((dnsKeyOwnerName.Length > 0) && !ownerName.EndsWith("." + dnsKeyOwnerName)))
                throw new InvalidOperationException();

            DnsQuestionRecord dsQuestion = new DnsQuestionRecord(ownerName, DnsResourceRecordType.DS, @class);
            DnsDatagram dsRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, true, DnsResponseCode.NoError, new DnsQuestionRecord[] { dsQuestion }, null, null, null, udpPayloadSize, EDnsHeaderFlags.DNSSEC_OK);

            //query cache
            DnsDatagram dsCacheResponse = QueryCache(cache, dsRequest);
            if ((dsCacheResponse is not null) && TryGetDSFromResponse(dsCacheResponse, ownerName, out IReadOnlyList<DnsResourceRecord> cacheDSRecords))
                return cacheDSRecords;

            //query dns server
            DnsDatagram dsResponse = await dnsClient.InternalResolveAsync(dsRequest);

            DnssecValidateSignature(dsResponse, currentDnsKeyRecords, null);

            cache.CacheResponse(dsResponse);

            if (TryGetDSFromResponse(dsResponse, ownerName, out IReadOnlyList<DnsResourceRecord> dsRecords))
                return dsRecords;

            throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due to unable to find DS records for owner name: " + ownerName, dsResponse);
        }

        private static bool TryGetDSFromResponse(DnsDatagram response, string ownerName, out IReadOnlyList<DnsResourceRecord> dsRecords)
        {
            switch (response.RCODE)
            {
                case DnsResponseCode.NxDomain:
                    //NX Domain was already validated
                    dsRecords = null;
                    return true;

                case DnsResponseCode.NoError:
                    if (response.Question[0].Type == DnsResourceRecordType.DS)
                    {
                        //DS query response
                        if (response.Answer.Count > 0)
                        {
                            dsRecords = GetFilterdDSRecords(response.Answer, ownerName);
                            if (dsRecords.Count > 0)
                            {
                                if (!DnsDSRecord.IsAlgorithmSupported(dsRecords))
                                {
                                    //If the validator does not support any of the algorithms listed in an
                                    //authenticated DS RRset, then the resolver has no supported
                                    //authentication path leading from the parent to the child.  The
                                    //resolver should treat this case as it would the case of an
                                    //authenticated NSEC RRset proving that no DS RRset exists, as
                                    //described above.

                                    dsRecords = null;
                                }

                                return true;
                            }
                        }
                        else if (response.Authority.Count > 0)
                        {
                            //validate if DS records are really missing
                            DnssecProofOfNonExistence proofOfNonExistence = GetValidatedProofOfNonExistence(response.Authority, ownerName, DnsResourceRecordType.DS);
                            switch (proofOfNonExistence)
                            {
                                case DnssecProofOfNonExistence.InsecureDelegation:
                                case DnssecProofOfNonExistence.OptOut:
                                    //proved that DS is missing and the zone is unsigned
                                    dsRecords = null;
                                    return true;

                                case DnssecProofOfNonExistence.NoData:
                                    //NO DATA; must be a sub domain
                                    dsRecords = Array.Empty<DnsResourceRecord>();
                                    return true;
                            }

                            //check if response is from dnssec validated unsigned zone
                            DnsResourceRecord firstAuthority = response.FindFirstAuthorityRecord();
                            if ((firstAuthority is not null) && (firstAuthority.Type == DnsResourceRecordType.SOA) && (firstAuthority.DnssecStatus == DnssecStatus.Insecure))
                            {
                                //NO DATA; zone is unsigned
                                dsRecords = null;
                                return true;
                            }
                        }
                    }
                    else
                    {
                        //referral response
                        DnsResourceRecord firstAuthority = response.FindFirstAuthorityRecord();
                        if ((firstAuthority is not null) && (firstAuthority.Type == DnsResourceRecordType.NS) && (firstAuthority.DnssecStatus == DnssecStatus.Insecure))
                        {
                            //referral response is from unsigned zone
                            dsRecords = null;
                            return true;
                        }

                        dsRecords = GetFilterdDSRecords(response.Authority, ownerName);
                        if (dsRecords.Count > 0)
                        {
                            if (!DnsDSRecord.IsAlgorithmSupported(dsRecords))
                            {
                                //If the validator does not support any of the algorithms listed in an
                                //authenticated DS RRset, then the resolver has no supported
                                //authentication path leading from the parent to the child.  The
                                //resolver should treat this case as it would the case of an
                                //authenticated NSEC RRset proving that no DS RRset exists, as
                                //described above.

                                dsRecords = null;
                            }

                            return true;
                        }

                        //validate if DS records are really missing
                        DnssecProofOfNonExistence proofOfNonExistence = GetValidatedProofOfNonExistence(response.Authority, ownerName, DnsResourceRecordType.DS);
                        switch (proofOfNonExistence)
                        {
                            case DnssecProofOfNonExistence.InsecureDelegation:
                            case DnssecProofOfNonExistence.OptOut:
                                //proved that DS is missing and the zone is unsigned
                                dsRecords = null;
                                return true;

                            case DnssecProofOfNonExistence.NoData:
                                //NO DATA; must be a sub domain
                                dsRecords = Array.Empty<DnsResourceRecord>();
                                return true;
                        }
                    }
                    break;
            }

            //could not find DS records or proof of non-existence
            dsRecords = null;
            return false;
        }

        private static IReadOnlyList<DnsResourceRecord> GetFilterdDSRecords(IReadOnlyList<DnsResourceRecord> records, string ownerName)
        {
            List<DnsResourceRecord> dsRecords = new List<DnsResourceRecord>(2);

            foreach (DnsResourceRecord record in records)
            {
                if ((record.Type == DnsResourceRecordType.DS) && (record.DnssecStatus == DnssecStatus.Secure) && record.Name.Equals(ownerName, StringComparison.OrdinalIgnoreCase))
                    dsRecords.Add(record);
            }

            return dsRecords;
        }

        private static DnssecProofOfNonExistence GetValidatedProofOfNonExistence(IReadOnlyList<DnsResourceRecord> records, string domain, DnsResourceRecordType type, bool wildcardAnswerValidation = false, string wildcardNextCloserName = null)
        {
            foreach (DnsResourceRecord record in records)
            {
                if (record.Type == DnsResourceRecordType.NSEC)
                    return DnsNSECRecord.GetValidatedProofOfNonExistence(records, domain, type, wildcardAnswerValidation);

                if (record.Type == DnsResourceRecordType.NSEC3)
                    return DnsNSEC3Record.GetValidatedProofOfNonExistence(records, domain, type, wildcardAnswerValidation, wildcardNextCloserName);
            }

            return DnssecProofOfNonExistence.NoProof;
        }

        private static void FindSignersNames(DnsDatagram response, List<string> signersNames)
        {
            FindSignersNames(response.Answer, signersNames, false, false);
            FindSignersNames(response.Authority, signersNames, true, false);
            FindSignersNames(response.Additional, signersNames, false, true);
        }

        private static void FindSignersNames(IReadOnlyList<DnsResourceRecord> records, List<string> signersNames, bool isAuthoritySection, bool isAdditionalSection)
        {
            foreach (DnsResourceRecord record in records)
            {
                switch (record.Type)
                {
                    case DnsResourceRecordType.RRSIG:
                    case DnsResourceRecordType.OPT:
                        continue;
                }

                bool isRecordCovered = false;

                foreach (DnsResourceRecord rrsigRecord in records)
                {
                    if ((rrsigRecord.Type == DnsResourceRecordType.RRSIG) && rrsigRecord.Name.Equals(record.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        DnsRRSIGRecord rrsig = rrsigRecord.RDATA as DnsRRSIGRecord;

                        if (rrsig.TypeCovered == record.Type)
                        {
                            string signersName = rrsig.SignersName;

                            if (!signersNames.Contains(signersName))
                                signersNames.Add(signersName);

                            isRecordCovered = true;
                            break;
                        }
                    }
                }

                if (!isRecordCovered)
                {
                    if (isAdditionalSection || (isAuthoritySection && record.Type == DnsResourceRecordType.NS))
                    {
                        //ignore record
                    }
                    else
                    {
                        string signersName = record.Name;

                        if (!signersNames.Contains(signersName))
                            signersNames.Add(signersName);
                    }
                }
            }
        }

        private static bool IsDomainUnsigned(string domain, IReadOnlyList<string> unsignedZones)
        {
            if (unsignedZones is null)
                return false;

            foreach (string unsignedZone in unsignedZones)
            {
                if (domain.Equals(unsignedZone, StringComparison.OrdinalIgnoreCase) || domain.EndsWith("." + unsignedZone, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        private static DnsDatagram SanitizeResponseAnswer(DnsDatagram response, string zoneCut)
        {
            string qName = response.Question[0].Name;

            for (int i = 0; i < response.Answer.Count; i++)
            {
                DnsResourceRecord answer = response.Answer[i];

                if (answer.Name.Equals(qName, StringComparison.OrdinalIgnoreCase))
                {
                    switch (answer.Type)
                    {
                        case DnsResourceRecordType.CNAME:
                            if (i < response.Answer.Count - 1)
                            {
                                string domain = (answer.RDATA as DnsCNAMERecord).Domain;

                                if (domain.Equals(zoneCut, StringComparison.OrdinalIgnoreCase) || domain.EndsWith("." + zoneCut, StringComparison.OrdinalIgnoreCase))
                                {
                                    //CNAME domain is inside zone cut
                                    qName = domain;
                                }
                            }
                            break;
                    }
                }
                else if ((answer.Type == DnsResourceRecordType.DNAME) && qName.EndsWith("." + answer.Name, StringComparison.OrdinalIgnoreCase) && (answer.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase) || answer.Name.EndsWith("." + zoneCut, StringComparison.OrdinalIgnoreCase)))
                {
                    //found DNAME, continue next
                }
                else
                {
                    //name mismatch
                    //truncate answer upto previous RR

                    List<DnsResourceRecord> newAnswers = new List<DnsResourceRecord>(i);

                    for (int j = 0; j < i; j++)
                        newAnswers.Add(response.Answer[j]);

                    return response.Clone(newAnswers);
                }
            }

            return response;
        }

        private static DnsDatagram SanitizeResponseAuthority(DnsDatagram response, string zoneCut)
        {
            if (zoneCut.Length == 0)
            {
                //zone cut is root, do nothing
                return response;
            }

            if (response.Authority.Count > 0)
            {
                bool authorityNotInZoneCutOrDnssecIndeterminate = false;
                string zoneCutEnd = "." + zoneCut;

                foreach (DnsResourceRecord authority in response.Authority)
                {
                    if (!authority.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase) && !authority.Name.EndsWith(zoneCutEnd, StringComparison.OrdinalIgnoreCase))
                    {
                        authorityNotInZoneCutOrDnssecIndeterminate = true;
                        break;
                    }

                    if ((authority.Type != DnsResourceRecordType.NS) && (authority.DnssecStatus == DnssecStatus.Indeterminate))
                    {
                        authorityNotInZoneCutOrDnssecIndeterminate = true;
                        break;
                    }
                }

                if (authorityNotInZoneCutOrDnssecIndeterminate)
                {
                    List<DnsResourceRecord> newAuthority = new List<DnsResourceRecord>(response.Authority.Count);

                    foreach (DnsResourceRecord authority in response.Authority)
                    {
                        if (authority.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase) || authority.Name.EndsWith(zoneCutEnd, StringComparison.OrdinalIgnoreCase))
                        {
                            if ((authority.Type == DnsResourceRecordType.NS) || (authority.DnssecStatus != DnssecStatus.Indeterminate))
                                newAuthority.Add(authority);
                        }
                    }

                    return response.Clone(null, newAuthority);
                }
            }

            return response;
        }

        private static async Task RevalidateNameServers(string zoneCut, IReadOnlyList<NameServerAddress> parentSideNameServers, IDnsCache cache, NetProxy proxy, bool preferIPv6, ushort udpPayloadSize, bool randomizeName, int retries, int timeout)
        {
            //Delegation Revalidation by DNS Resolvers
            //https://datatracker.ietf.org/doc/draft-ietf-dnsop-ns-revalidation/

            //select only name server addresses that have their IPEndPoint resolved to avoid additional recursive resolution
            List<NameServerAddress> nameServers = new List<NameServerAddress>(parentSideNameServers.Count);

            foreach (NameServerAddress nameServer in parentSideNameServers)
            {
                if (nameServer.IsIPEndPointStale)
                    continue;

                nameServers.Add(nameServer);
            }

            if (nameServers.Count == 0)
                return; //no name servers with EPs available

            DnsClient client = new DnsClient(nameServers);
            client._proxy = proxy;
            client._preferIPv6 = preferIPv6;
            client._randomizeName = randomizeName;
            client._retries = retries;
            client._timeout = timeout;
            client._concurrency = 1;

            DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(zoneCut, DnsResourceRecordType.NS, DnsClass.IN) }, null, null, null, udpPayloadSize);
            DnsDatagram response;

            try
            {
                response = await client.InternalResolveAsync(request);
            }
            catch
            {
                //ignore failures in resolution
                return;
            }

            //sanitize response
            response = SanitizeResponseAnswer(response, zoneCut); //sanitize answer section
            response = SanitizeResponseAuthority(response, zoneCut); //sanitize authority section

            //cache authoritative NS records from response
            if (response.Answer.Count > 0)
                cache.CacheResponse(response);
        }

        private static async Task<DnsDatagram> ResolveQueryAsync(DnsQuestionRecord question, Func<DnsQuestionRecord, Task<DnsDatagram>> resolveAsync)
        {
            DnsDatagram response = await resolveAsync(question);

            IReadOnlyList<DnsResourceRecord> authority = null;
            IReadOnlyList<DnsResourceRecord> additional = null;

            if (response.Answer.Count > 0)
            {
                DnsResourceRecord lastAnswer = response.GetLastAnswerRecord();

                if ((lastAnswer.Type != question.Type) && (lastAnswer.Type == DnsResourceRecordType.CNAME) && (question.Type != DnsResourceRecordType.ANY))
                {
                    List<DnsResourceRecord> responseAnswer = new List<DnsResourceRecord>();
                    responseAnswer.AddRange(response.Answer);

                    DnsDatagram lastResponse;
                    int queryCount = 0;

                    do
                    {
                        DnsQuestionRecord cnameQuestion = new DnsQuestionRecord((lastAnswer.RDATA as DnsCNAMERecord).Domain, question.Type, question.Class);

                        lastResponse = await resolveAsync(cnameQuestion);

                        if (lastResponse.Answer.Count == 0)
                            break;

                        responseAnswer.AddRange(lastResponse.Answer);

                        lastAnswer = lastResponse.GetLastAnswerRecord();

                        if (lastAnswer.Type == question.Type)
                            break;

                        if (lastAnswer.Type != DnsResourceRecordType.CNAME)
                            throw new DnsClientException("Invalid response received from DNS server: was expecting CNAME but received " + lastAnswer.Type.ToString());
                    }
                    while (++queryCount < MAX_CNAME_HOPS);

                    if (lastResponse.Authority.Count > 0)
                    {
                        if (lastResponse.IsFirstAuthoritySOA())
                            authority = lastResponse.Authority;
                    }
                    else
                    {
                        switch (question.Type)
                        {
                            case DnsResourceRecordType.NS:
                            case DnsResourceRecordType.MX:
                            case DnsResourceRecordType.SRV:
                                additional = response.Additional;
                                break;
                        }
                    }

                    DnsDatagram compositeResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, lastResponse.RCODE, new DnsQuestionRecord[] { question }, responseAnswer, authority, additional);

                    if (lastResponse.Metadata is not null)
                        compositeResponse.SetMetadata(lastResponse.Metadata.NameServerAddress, lastResponse.Metadata.Protocol, lastResponse.Metadata.RTT);

                    return compositeResponse;
                }
            }

            if (response.Authority.Count > 0)
            {
                if (response.IsFirstAuthoritySOA())
                    authority = response.Authority;
            }
            else
            {
                switch (question.Type)
                {
                    case DnsResourceRecordType.NS:
                    case DnsResourceRecordType.MX:
                    case DnsResourceRecordType.SRV:
                        additional = response.Additional;
                        break;
                }
            }

            DnsDatagram finalResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, response.RCODE, new DnsQuestionRecord[] { question }, response.Answer, authority, additional);

            if (response.Metadata is not null)
                finalResponse.SetMetadata(response.Metadata.NameServerAddress, response.Metadata.Protocol, response.Metadata.RTT);

            return finalResponse;
        }

        private async Task<DnsDatagram> InternalResolveAsync(DnsDatagram request)
        {
            //get servers
            IReadOnlyList<NameServerAddress> servers;
            int concurrency;

            if (_servers.Count > _concurrency)
            {
                List<NameServerAddress> serversCopy = new List<NameServerAddress>(_servers);
                serversCopy.Shuffle();

                if (_preferIPv6)
                    serversCopy.Sort();

                servers = serversCopy;
                concurrency = _concurrency;
            }
            else
            {
                servers = _servers;
                concurrency = _servers.Count;
            }

            //init parameters
            object nextServerLock = new object();
            int nextServerIndex = 0;
            IDnsCache nsResolveCache = null;

            NameServerAddress GetNextServer()
            {
                lock (nextServerLock)
                {
                    if (nextServerIndex < servers.Count)
                    {
                        NameServerAddress server = servers[nextServerIndex++];

                        if ((nsResolveCache is null) && server.IsIPEndPointStale && (_proxy is null))
                        {
                            if (_cache is null)
                                nsResolveCache = new DnsCache();
                            else
                                nsResolveCache = _cache;
                        }

                        return server;
                    }

                    return null; //no next server available; stop thread
                }
            }

            async Task<DnsDatagram> DoResolveAsync(CancellationToken cancellationToken = default)
            {
                DnsDatagram asyncRequest = request.CloneHeadersAndQuestions(); //clone request (headers + question section) so that qname randomization does not pollute request question section and does not cause issue with parallel tasks
                DnsDatagram lastResponse = null;
                Exception lastException = null;

                while (true) //next server loop
                {
                    if (cancellationToken.IsCancellationRequested)
                        return await Task.FromCanceled<DnsDatagram>(cancellationToken); //task cancelled

                    NameServerAddress server = GetNextServer();
                    if (server is null)
                    {
                        if (lastResponse is not null)
                            return lastResponse;

                        if (lastException is not null)
                            ExceptionDispatchInfo.Capture(lastException).Throw();

                        throw new DnsClientException("DnsClient failed to resolve the request: no response from name servers.");
                    }

                    if (server.IsIPEndPointStale && (_proxy is null))
                    {
                        //recursive resolve name server via root servers when proxy is null else let proxy resolve it
                        try
                        {
                            await server.RecursiveResolveIPAddressAsync(nsResolveCache, null, _preferIPv6, _udpPayloadSize, _randomizeName, _retries, _timeout);
                        }
                        catch (Exception ex)
                        {
                            lastException = ex;
                            continue; //failed to resolve name server; try next server
                        }
                    }

                    //upgrade protocol to TCP when UDP is not supported by proxy and server is not bypassed
                    if ((_proxy is not null) && (server.Protocol == DnsTransportProtocol.Udp) && !_proxy.IsBypassed(server.EndPoint) && !await _proxy.IsUdpAvailableAsync())
                        server = server.ChangeProtocol(DnsTransportProtocol.Tcp);

                    asyncRequest.SetRandomIdentifier();

                    bool protocolWasSwitched = false;
                    try
                    {
                        bool retryRequest;
                        do //retry request loop
                        {
                            retryRequest = false;

                            if (server.Protocol == DnsTransportProtocol.Udp)
                            {
                                if ((asyncRequest.Question.Count > 0) && (asyncRequest.Question[0].Type == DnsResourceRecordType.AXFR))
                                {
                                    //use TCP for AXFR
                                    server = server.ChangeProtocol(DnsTransportProtocol.Tcp);
                                }
                                else if (_randomizeName)
                                {
                                    foreach (DnsQuestionRecord question in asyncRequest.Question)
                                        question.RandomizeName();
                                }
                            }

                            //get connection
                            using (DnsClientConnection connection = DnsClientConnection.GetConnection(server, _proxy))
                            {
                                try
                                {
                                    DnsDatagram response = await connection.QueryAsync(asyncRequest, _timeout, _retries, cancellationToken);
                                    if (response.Truncation)
                                    {
                                        if (server.Protocol == DnsTransportProtocol.Udp)
                                        {
                                            server = server.ChangeProtocol(DnsTransportProtocol.Tcp);

                                            if (_randomizeName)
                                            {
                                                foreach (DnsQuestionRecord question in asyncRequest.Question)
                                                    question.NormalizeName();
                                            }

                                            retryRequest = true;
                                            protocolWasSwitched = true;
                                        }
                                    }
                                    else
                                    {
                                        if (response.ParsingException is not null)
                                        {
                                            lastException = response.ParsingException;
                                        }
                                        else
                                        {
                                            switch (response.RCODE)
                                            {
                                                case DnsResponseCode.NoError:
                                                case DnsResponseCode.NxDomain:
                                                    return response;

                                                default:
                                                    lastResponse = response;
                                                    break;
                                            }
                                        }
                                    }
                                }
                                catch (SocketException ex)
                                {
                                    switch (ex.SocketErrorCode)
                                    {
                                        case SocketError.MessageSize:
                                            if (server.Protocol == DnsTransportProtocol.Udp)
                                            {
                                                //unexpected large UDP response was received; switch protocols
                                                server = server.ChangeProtocol(DnsTransportProtocol.Tcp);

                                                if (_randomizeName)
                                                {
                                                    foreach (DnsQuestionRecord question in asyncRequest.Question)
                                                        question.NormalizeName();
                                                }

                                                lastException = ex;
                                                retryRequest = true;
                                                protocolWasSwitched = true;
                                            }
                                            else
                                            {
                                                throw;
                                            }

                                            break;

                                        case SocketError.TimedOut:
                                            if ((server.Protocol == DnsTransportProtocol.Udp) && (asyncRequest.EDNS is not null) && !asyncRequest.EDNS.Flags.HasFlag(EDnsHeaderFlags.DNSSEC_OK))
                                            {
                                                //EDNS udp request timed out; disable EDNS and retry the request

                                                IReadOnlyList<DnsResourceRecord> newAdditional;

                                                if (asyncRequest.Additional.Count == 1)
                                                {
                                                    newAdditional = Array.Empty<DnsResourceRecord>();
                                                }
                                                else
                                                {
                                                    List<DnsResourceRecord> newAdditionalList = new List<DnsResourceRecord>(asyncRequest.Additional.Count - 1);

                                                    foreach (DnsResourceRecord record in asyncRequest.Additional)
                                                    {
                                                        if (record.Type == DnsResourceRecordType.OPT)
                                                            continue;

                                                        newAdditionalList.Add(record);
                                                    }

                                                    newAdditional = newAdditionalList;
                                                }

                                                asyncRequest = asyncRequest.Clone(null, null, newAdditional);

                                                lastException = ex;
                                                retryRequest = true;
                                                protocolWasSwitched = false;
                                            }
                                            else
                                            {
                                                throw;
                                            }

                                            break;

                                        default:
                                            throw;
                                    }
                                }
                                catch (DnsClientResponseValidationException ex)
                                {
                                    if (server.Protocol == DnsTransportProtocol.Udp)
                                    {
                                        //TCP fallback mechanism to use for any response validation failures
                                        server = server.ChangeProtocol(DnsTransportProtocol.Tcp);

                                        if (_randomizeName)
                                        {
                                            foreach (DnsQuestionRecord question in asyncRequest.Question)
                                                question.NormalizeName();
                                        }

                                        lastException = ex;
                                        retryRequest = true;
                                        protocolWasSwitched = true;
                                    }
                                    else
                                    {
                                        throw;
                                    }
                                }
                            }
                        }
                        while (retryRequest); //retry request loop
                    }
                    catch (Exception ex)
                    {
                        if (protocolWasSwitched && (lastException is DnsClientResponseValidationException) && (ex is SocketException))
                        {
                            //keep previous last exception to allow recursive resolver distinguish exception for qname minimization to work
                        }
                        else
                        {
                            lastException = ex;
                        }
                    }
                }
            }

            if (concurrency > 1)
            {
                using (CancellationTokenSource cancellationTokenSource = new CancellationTokenSource())
                {
                    List<Task> tasks = new List<Task>(concurrency);

                    //start worker tasks
                    for (int i = 0; i < concurrency; i++)
                        tasks.Add(Task.Factory.StartNew(delegate () { return DoResolveAsync(cancellationTokenSource.Token); }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current).Unwrap());

                    //add delay task
                    Task delayTask = Task.Delay(_timeout * _retries * (int)Math.Ceiling((double)servers.Count / concurrency), cancellationTokenSource.Token);
                    tasks.Add(delayTask);

                    //wait for first positive response, or for all tasks to fault, or timeout
                    DnsDatagram lastResponse = null;
                    Exception lastException = null;

                    while (true)
                    {
                        Task completedTask = await Task.WhenAny(tasks);

                        if (completedTask == delayTask)
                        {
                            cancellationTokenSource.Cancel(); //to stop resolver tasks

                            if (lastResponse is not null)
                                return lastResponse; //return last response since it was returned by a task that ran to completion

                            if (lastException is not null)
                                ExceptionDispatchInfo.Capture(lastException).Throw();

                            throw new DnsClientException("DnsClient failed to resolve the request: request timed out.");
                        }

                        if (completedTask.Status == TaskStatus.RanToCompletion)
                        {
                            //resolver task complete
                            DnsDatagram response = await (completedTask as Task<DnsDatagram>); //await to get response

                            switch (response.RCODE)
                            {
                                case DnsResponseCode.NoError:
                                case DnsResponseCode.NxDomain:
                                    cancellationTokenSource.Cancel(); //to stop delay and other resolver tasks
                                    return response;

                                default:
                                    //keep response
                                    lastResponse = response;
                                    break;
                            }
                        }

                        if (tasks.Count == 2)
                        {
                            //this is the last resolver task
                            cancellationTokenSource.Cancel(); //to stop delay and other resolver tasks

                            if (lastResponse is not null)
                                return lastResponse; //return last response since it was returned by a task that ran to completion

                            return await (completedTask as Task<DnsDatagram>); //await throw error
                        }

                        tasks.Remove(completedTask);
                        lastException = completedTask.Exception;

                        if (lastException is AggregateException)
                            lastException = lastException.InnerException;
                    }
                }
            }
            else
            {
                return await DoResolveAsync();
            }
        }

        private async Task<DnsDatagram> InternalNoDnssecResolveAsync(DnsDatagram request)
        {
            DnsDatagram response = await InternalResolveAsync(request);

            response.SetDnssecStatusForAllRecords(DnssecStatus.Disabled);

            return response;
        }

        private async Task<DnsDatagram> InternalDnssecResolveAsync(DnsQuestionRecord question)
        {
            IDnsCache cache;

            if (_cache is null)
                cache = new DnsCache();
            else
                cache = _cache;

            DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, true, DnsResponseCode.NoError, new DnsQuestionRecord[] { question }, null, null, null, _udpPayloadSize, EDnsHeaderFlags.DNSSEC_OK);
            DnsDatagram response = await InternalResolveAsync(request);

            await DnssecValidateResponseAsync(response, ROOT_TRUST_ANCHORS, this, cache, _udpPayloadSize);

            return response;
        }

        private async Task<DnsDatagram> InternalCachedResolveQueryAsync(DnsQuestionRecord question)
        {
            return await ResolveQueryAsync(question, async delegate (DnsQuestionRecord q)
            {
                DnsDatagram newRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { q }, null, null, null, _udpPayloadSize);

                DnsDatagram cacheResponse = QueryCache(_cache, newRequest);
                if (cacheResponse is not null)
                    return cacheResponse;

                DnsDatagram newResponse;

                if (_dnssecValidation)
                    newResponse = await InternalDnssecResolveAsync(q);
                else
                    newResponse = await InternalNoDnssecResolveAsync(newRequest);

                _cache.CacheResponse(newResponse);
                return newResponse;
            });
        }

        private static DnsDatagram QueryCache(IDnsCache cache, DnsDatagram request)
        {
            DnsDatagram cacheResponse = cache.Query(request);
            if (cacheResponse is not null)
            {
                if ((cacheResponse.RCODE != DnsResponseCode.NoError) || (cacheResponse.Answer.Count > 0) || (cacheResponse.Authority.Count == 0) || cacheResponse.IsFirstAuthoritySOA())
                    return cacheResponse;
            }

            return null;
        }

        #endregion

        #region public

        public Task<DnsDatagram> ResolveAsync(DnsDatagram request)
        {
            if ((_cache is not null) && (request.Question.Count == 1))
                return InternalCachedResolveQueryAsync(request.Question[0]);

            if (_dnssecValidation)
            {
                if (request.Question.Count != 1)
                    throw new ArgumentException("Request must have exactly one question record.", nameof(request));

                return InternalDnssecResolveAsync(request.Question[0]);
            }

            return InternalNoDnssecResolveAsync(request);
        }

        public async Task<DnsDatagram> ResolveAsync(DnsDatagram request, TsigKey key, ushort fudge = 300)
        {
            request.SetRandomIdentifier();
            DnsDatagram signedRequest = request.SignRequest(key, fudge);

            DnsDatagram signedResponse = await InternalNoDnssecResolveAsync(signedRequest);
            if (!signedResponse.VerifySignedResponse(signedRequest, key, out DnsDatagram unsignedResponse, out bool requestFailed, out DnsResponseCode rCode, out DnsTsigError error))
            {
                if (requestFailed)
                    throw new DnsClientTsigRequestFailedException(rCode, error);
                else
                    throw new DnsClientTsigResponseVerificationException(rCode, error);
            }

            return unsignedResponse;
        }

        public Task<DnsDatagram> ResolveAsync(DnsQuestionRecord question)
        {
            if (_cache is not null)
                return InternalCachedResolveQueryAsync(question);

            if (_dnssecValidation)
                return InternalDnssecResolveAsync(question);

            return InternalNoDnssecResolveAsync(new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { question }, null, null, null, _udpPayloadSize));
        }

        public Task<DnsDatagram> ResolveAsync(DnsQuestionRecord question, TsigKey key, ushort fudge = 300)
        {
            return ResolveAsync(new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { question }, null, null, null, _udpPayloadSize), key, fudge);
        }

        public Task<DnsDatagram> ResolveAsync(string domain, DnsResourceRecordType type)
        {
            if ((type == DnsResourceRecordType.PTR) && IPAddress.TryParse(domain, out IPAddress address))
                return ResolveAsync(new DnsQuestionRecord(address, DnsClass.IN));
            else
                return ResolveAsync(new DnsQuestionRecord(domain, type, DnsClass.IN));
        }

        public Task<DnsDatagram> ResolveAsync(string domain, DnsResourceRecordType type, TsigKey key, ushort fudge = 300)
        {
            if ((type == DnsResourceRecordType.PTR) && IPAddress.TryParse(domain, out IPAddress address))
                return ResolveAsync(new DnsQuestionRecord(address, DnsClass.IN), key, fudge);
            else
                return ResolveAsync(new DnsQuestionRecord(domain, type, DnsClass.IN), key, fudge);
        }

        public Task<IReadOnlyList<string>> ResolveMXAsync(string domain, bool resolveIP = false, bool preferIPv6 = false)
        {
            return ResolveMXAsync(this, domain, resolveIP, preferIPv6);
        }

        public async Task<IReadOnlyList<string>> ResolvePTRAsync(IPAddress ip)
        {
            return ParseResponsePTR(await ResolveAsync(new DnsQuestionRecord(ip, DnsClass.IN)));
        }

        public async Task<IReadOnlyList<string>> ResolveTXTAsync(string domain)
        {
            return ParseResponseTXT(await ResolveAsync(new DnsQuestionRecord(domain, DnsResourceRecordType.TXT, DnsClass.IN)));
        }

        public Task<IReadOnlyList<IPAddress>> ResolveIPAsync(string domain, bool preferIPv6 = false)
        {
            return ResolveIPAsync(this, domain, preferIPv6);
        }

        #endregion

        #region property

        public IReadOnlyList<NameServerAddress> Servers
        { get { return _servers; } }

        public IDnsCache Cache
        {
            get { return _cache; }
            set { _cache = value; }
        }

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

        public ushort UdpPayloadSize
        {
            get { return _udpPayloadSize; }
            set { _udpPayloadSize = value; }
        }

        public bool RandomizeName
        {
            get { return _randomizeName; }
            set { _randomizeName = value; }
        }

        public bool DnssecValidation
        {
            get { return _dnssecValidation; }
            set { _dnssecValidation = value; }
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

        public int Concurrency
        {
            get { return _concurrency; }
            set { _concurrency = value; }
        }

        #endregion

        class ResolverData
        {
            public readonly DnsQuestionRecord Question;
            public readonly string ZoneCut;
            public readonly EDnsHeaderFlags EDnsFlags;
            public readonly IReadOnlyList<DnsResourceRecord> LastDSRecords;
            public readonly IList<NameServerAddress> NameServers;
            public readonly int NameServerIndex;
            public readonly int HopCount;
            public readonly DnsDatagram LastResponse;
            public readonly Exception LastException;

            public ResolverData(DnsQuestionRecord question, string zoneCut, EDnsHeaderFlags ednsFlags, IReadOnlyList<DnsResourceRecord> lastDSRecords, IList<NameServerAddress> nameServers, int nameServerIndex, int hopCount, DnsDatagram lastResponse, Exception lastException)
            {
                Question = question;
                ZoneCut = zoneCut;
                EDnsFlags = ednsFlags;
                LastDSRecords = lastDSRecords;
                NameServers = nameServers;
                NameServerIndex = nameServerIndex;
                HopCount = hopCount;
                LastResponse = lastResponse;
                LastException = lastException;
            }
        }
    }
}
