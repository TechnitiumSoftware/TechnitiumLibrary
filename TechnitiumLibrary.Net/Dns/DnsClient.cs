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
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using TechnitiumLibrary.Net.Dns.ClientConnection;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
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
        HttpsJson = 4, //Google
        Quic = 5, //RFC 9250
        UdpProxy = 253, //PROXY Protocol over UDP
        TcpProxy = 254 //PROXY Protocol over TCP
    }

    public class DnsClient : IDnsClient
    {
        #region variables

        static IReadOnlyList<NameServerAddress> IPv4_ROOT_HINTS;
        static IReadOnlyList<NameServerAddress> IPv6_ROOT_HINTS;

        static IReadOnlyList<DnsResourceRecord> ROOT_TRUST_ANCHORS;

        readonly static IdnMapping _idnMapping = new IdnMapping() { AllowUnassigned = true };

        readonly static PropertyInfo _sslStream_innerStream = typeof(SslStream).GetProperty("InnerStream", BindingFlags.Instance | BindingFlags.NonPublic);

        const int MAX_DELEGATION_HOPS = 16; //max NS referrals to follow
        internal const int MAX_CNAME_HOPS = 16; //max CNAMEs to follow
        const int MAX_NS_TO_QUERY_PER_REFERRAL = 16; //max NS to query per referral response to mitigate NRDelegationAttack and NXNSAttack
        internal const int MAX_NSEC3_ITERATIONS = 100; //max iterations allowed for NSEC3 [RFC 9276]

        //CVE-2023-50387 KeyTrap mitigation
        const int KEY_TRAP_MAX_KEY_TAG_COLLISIONS = 4; //HashTrap mitigation by limiting key collisions
        const int KEY_TRAP_MAX_CRYPTO_FAILURES = 16; //mitigation by limiting cryptographic failures per resolution
        const int KEY_TRAP_MAX_RRSET_VALIDATIONS_PER_SUSPENSION = 8; //task will suspend after max RRSET validations
        const int KEY_TRAP_MAX_SUSPENSIONS_PER_RESPONSE = 16; //task will stop RRSET validation after max suspensions for the response

        //CVE-2023-50868 NSEC3 closest encloser proof DoS mitigation
        internal const int NSEC3_MAX_HASHES_PER_SUSPENSION = 8; //task will suspend after max NSEC3 compute hash calls
        internal const int NSEC3_MAX_SUSPENSIONS_PER_RESPONSE = 16; //task will stop NSEC3 proof validation after max suspensions for the response

        readonly IReadOnlyList<NameServerAddress> _servers;

        IDnsCache _cache;
        NetProxy _proxy;
        bool _preferIPv6;
        ushort _udpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE;
        bool _randomizeName;
        bool _dnssecValidation;
        NetworkAddress _eDnsClientSubnet;
        bool _advancedForwardingClientSubnet; //this feature is used by Advanced Forwarding app to cache response per network group
        string _conditionalForwardingZoneCut;
        int _retries = 2;
        int _timeout = 2000;
        int _concurrency = 2;

        Dictionary<string, IReadOnlyList<DnsResourceRecord>> _trustAnchors;

        #endregion

        #region constructor

        static DnsClient()
        {
            //set default root hints
            IPv4_ROOT_HINTS =
            [
                new NameServerAddress("a.root-servers.net", IPAddress.Parse("198.41.0.4")), //VeriSign, Inc.
                new NameServerAddress("b.root-servers.net", IPAddress.Parse("170.247.170.2")), //University of Southern California (ISI)
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
            ];

            IPv6_ROOT_HINTS =
            [
                new NameServerAddress("a.root-servers.net", IPAddress.Parse("2001:503:ba3e::2:30")), //VeriSign, Inc.
                new NameServerAddress("b.root-servers.net", IPAddress.Parse("2801:1b8:10::b")), //University of Southern California (ISI)
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
            ];

            //set default root trust anchors
            ROOT_TRUST_ANCHORS =
            [
                new DnsResourceRecord("", DnsResourceRecordType.DS, DnsClass.IN, 0, new DnsDSRecordData(20326, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256, Convert.FromHexString("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"))),
                new DnsResourceRecord("", DnsResourceRecordType.DS, DnsClass.IN, 0, new DnsDSRecordData(38696, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256, Convert.FromHexString("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16")))
            ];

            //load root hints file async
            _ = Task.Run(ReloadRootHintsAsync);

            //load root trust anchors file
            try
            {
                ReloadRootTrustAnchors();
            }
            catch
            { }
        }

        private DnsClient()
        { }

        public DnsClient(Uri dohEndPoint)
        {
            _servers = [new NameServerAddress(dohEndPoint)];
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
            : this(addresses.Split(NameServerAddress.Parse, ','))
        { }

        public DnsClient(params string[] addresses)
            : this(addresses.Convert(NameServerAddress.Parse))
        { }

        public DnsClient(string address, DnsTransportProtocol protocol)
            : this(NameServerAddress.Parse(address, protocol))
        { }

        public DnsClient(NameServerAddress server)
        {
            _servers = [server];
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

        public static async Task ReloadRootHintsAsync()
        {
            string rootHintsFile = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "named.root");
            if (!File.Exists(rootHintsFile))
                return;

            List<DnsResourceRecord> rootZoneRecords = await ZoneFile.ReadZoneFileFromAsync(rootHintsFile);

            List<NameServerAddress> ipv4RootHints = new List<NameServerAddress>(13);
            List<NameServerAddress> ipv6RootHints = new List<NameServerAddress>(13);

            foreach (DnsResourceRecord nsRecord in rootZoneRecords)
            {
                if (nsRecord.Type != DnsResourceRecordType.NS)
                    continue;

                if (nsRecord.Name.Length != 0)
                    continue;

                string name = (nsRecord.RDATA as DnsNSRecordData).NameServer.ToLowerInvariant();

                foreach (DnsResourceRecord record in rootZoneRecords)
                {
                    switch (record.Type)
                    {
                        case DnsResourceRecordType.A:
                            if (name.Equals(record.Name, StringComparison.OrdinalIgnoreCase))
                                ipv4RootHints.Add(new NameServerAddress(name, (record.RDATA as DnsARecordData).Address));

                            break;

                        case DnsResourceRecordType.AAAA:
                            if (name.Equals(record.Name, StringComparison.OrdinalIgnoreCase))
                                ipv6RootHints.Add(new NameServerAddress(name, (record.RDATA as DnsAAAARecordData).Address));

                            break;
                    }
                }
            }

            IPv4_ROOT_HINTS = ipv4RootHints;
            IPv6_ROOT_HINTS = ipv6RootHints;
        }

        public static void ReloadRootTrustAnchors()
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
                    switch (childNode.Name.ToLowerInvariant())
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

                rootTrustAnchors.Add(new DnsResourceRecord("", DnsResourceRecordType.DS, DnsClass.IN, 0, new DnsDSRecordData(keyTag, algorithm, digestType, Convert.FromHexString(digest))));
            }

            ROOT_TRUST_ANCHORS = rootTrustAnchors;
        }

        public static async Task<DnsDatagram> RecursiveResolveAsync(DnsQuestionRecord question, IDnsCache cache = null, NetProxy proxy = null, bool preferIPv6 = false, ushort udpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE, bool randomizeName = false, bool qnameMinimization = false, bool asyncNsRevalidation = false, bool dnssecValidation = false, NetworkAddress eDnsClientSubnet = null, int retries = 2, int timeout = 2000, int concurrency = 2, int maxStackCount = 16, bool minimalResponse = false, bool asyncNsResolution = false, List<DnsDatagram> rawResponses = null, CancellationToken cancellationToken = default)
        {
            if ((udpPayloadSize < 512) && (dnssecValidation || (eDnsClientSubnet is not null)))
                throw new ArgumentOutOfRangeException(nameof(udpPayloadSize), "EDNS cannot be disabled by setting UDP payload size to less than 512 when DNSSEC validation or EDNS Client Subnet is enabled.");

            EDnsOption[] eDnsClientSubnetOption = EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(eDnsClientSubnet);

            if (cache is null)
                cache = new DnsCache();

            if (qnameMinimization)
            {
                question = question.Clone(); //clone question so that original object is not affected
                question.ZoneCut = ""; //enable QNAME minimization by setting zone cut to <root>
            }

            List<EDnsExtendedDnsErrorOptionData> extendedDnsErrors = new List<EDnsExtendedDnsErrorOptionData>();

            //ns revalidation
            Dictionary<string, NsRevalidationTask> nsRevalidationChildSideTasks = null;
            Dictionary<string, object> nsRevalidationParentSideTask = null;

            if (asyncNsRevalidation)
            {
                nsRevalidationChildSideTasks = new Dictionary<string, NsRevalidationTask>();
                nsRevalidationParentSideTask = new Dictionary<string, object>();

                asyncNsResolution = false; //since NS revalidation does NS resolution too
            }

            void AddNsRevalidationParentSideTaskIfRequired(IReadOnlyCollection<DnsResourceRecord> nsRecords)
            {
                foreach (DnsResourceRecord nsRecord in nsRecords)
                {
                    if (nsRecord.Type != DnsResourceRecordType.NS)
                        continue;

                    DnsNSRecordData ns = nsRecord.RDATA as DnsNSRecordData;

                    if (ns.IsParentSideTtlSet && (ns.ParentSideTtl == 0))
                        nsRevalidationParentSideTask.TryAdd(nsRecord.Name.ToLowerInvariant(), null); //revalidate NS from parent side

                    break; //check only first NS record
                }
            }

            void TriggerNsRevalidation()
            {
                if (!asyncNsRevalidation || ((nsRevalidationChildSideTasks.Count == 0) && (nsRevalidationParentSideTask.Count == 0)))
                    return;

                _ = Task.Factory.StartNew(delegate ()
                {
                    foreach (KeyValuePair<string, NsRevalidationTask> entry in nsRevalidationChildSideTasks)
                        _ = RevalidateNameServersFromChildSideAsync(entry.Key, entry.Value.LastDSRecords, entry.Value.NameServers, cache, proxy, preferIPv6, udpPayloadSize, randomizeName, qnameMinimization, dnssecValidation, retries, timeout, concurrency, maxStackCount);

                    foreach (KeyValuePair<string, object> entry in nsRevalidationParentSideTask)
                        _ = RevalidateNameServersFromParentSideAsync(entry.Key, cache, proxy, preferIPv6, udpPayloadSize, randomizeName, qnameMinimization, dnssecValidation, retries, timeout, concurrency, maxStackCount);
                }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current);
            }

            //async resolve all name servers
            Dictionary<string, object> asyncNsResolutionTasks = null;

            if (asyncNsResolution)
                asyncNsResolutionTasks = new Dictionary<string, object>();

            void TriggerNsResolution()
            {
                if (!asyncNsResolution || (asyncNsResolutionTasks.Count == 0))
                    return;

                _ = Task.Factory.StartNew(delegate ()
                {
                    foreach (KeyValuePair<string, object> entry in asyncNsResolutionTasks)
                    {
                        if (preferIPv6)
                            _ = RecursiveResolveAsync(new DnsQuestionRecord(entry.Key, DnsResourceRecordType.AAAA, DnsClass.IN), cache, proxy, preferIPv6, udpPayloadSize, randomizeName, qnameMinimization, false, dnssecValidation, null, retries, timeout, concurrency, maxStackCount, false, false, null, cancellationToken);

                        _ = RecursiveResolveAsync(new DnsQuestionRecord(entry.Key, DnsResourceRecordType.A, DnsClass.IN), cache, proxy, preferIPv6, udpPayloadSize, randomizeName, qnameMinimization, false, dnssecValidation, null, retries, timeout, concurrency, maxStackCount, false, false, null, cancellationToken);
                    }
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

            List<NameServerAddress> ResolveNameServerAddressesFromCache(List<NameServerAddress> nameServers)
            {
                List<NameServerAddress> newNameServers = new List<NameServerAddress>(preferIPv6 ? nameServers.Count * 2 : nameServers.Count);

                foreach (NameServerAddress nameServer in nameServers)
                {
                    if (nameServer.IPEndPoint is not null)
                    {
                        newNameServers.Add(nameServer);
                        continue;
                    }

                    bool resolved = false;

                    if (preferIPv6)
                    {
                        DnsDatagram cacheRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(nameServer.DomainEndPoint.Address, DnsResourceRecordType.AAAA, DnsClass.IN)]);
                        DnsDatagram cacheResponse = cache.Query(cacheRequest);
                        if ((cacheResponse is not null) && (cacheResponse.Answer.Count > 0) && (cacheResponse.Answer[0].Type == DnsResourceRecordType.AAAA))
                        {
                            resolved = true;
                            newNameServers.Add(nameServer.UpdateAddress((cacheResponse.Answer[0].RDATA as DnsAAAARecordData).Address));
                        }
                    }

                    {
                        DnsDatagram cacheRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(nameServer.DomainEndPoint.Address, DnsResourceRecordType.A, DnsClass.IN)]);
                        DnsDatagram cacheResponse = cache.Query(cacheRequest);
                        if ((cacheResponse is not null) && (cacheResponse.Answer.Count > 0) && (cacheResponse.Answer[0].Type == DnsResourceRecordType.A))
                        {
                            resolved = true;
                            newNameServers.Add(nameServer.UpdateAddress((cacheResponse.Answer[0].RDATA as DnsARecordData).Address));
                        }
                    }

                    if (!resolved)
                        newNameServers.Add(nameServer);
                }

                return newNameServers;
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
                    DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { question });

                    if (extendedDnsErrors.Count > 0)
                        failureResponse.AddDnsClientExtendedError(extendedDnsErrors);

                    failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.Other, "Recursion stack limit reached for " + question.ToString());

                    if (eDnsClientSubnet is not null)
                        failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(eDnsClientSubnet.PrefixLength, eDnsClientSubnet.PrefixLength, eDnsClientSubnet.Address));

                    cache.CacheResponse(failureResponse);

                    throw new DnsClientException("DnsClient recursive resolution exceeded the maximum stack count for domain: " + question.Name.ToLowerInvariant());
                }

                //query cache
                {
                    //query cache without CD flag to not get response from "bad cache" and DO flag, if validation is enabled, to get DNSSEC records for correctly reading DS from response
                    DnsDatagram cacheRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { question }, null, null, null, udpPayloadSize, ednsFlags, resolverStack.Count == 0 ? eDnsClientSubnetOption : null);
                    DnsDatagram cacheResponse = cache.Query(cacheRequest, findClosestNameServers: true);
                    if (cacheResponse is not null)
                    {
                        extendedDnsErrors.AddRange(cacheResponse.DnsClientExtendedErrors);

                        switch (cacheResponse.RCODE)
                        {
                            case DnsResponseCode.NoError:
                                {
                                    if (cacheResponse.Answer.Count > 0)
                                    {
                                        if (resolverStack.Count == 0)
                                        {
                                            TriggerNsRevalidation();
                                            TriggerNsResolution();
                                            return cacheResponse;
                                        }
                                        else
                                        {
                                            bool found = false;

                                            for (int i = 0; i < cacheResponse.Answer.Count; i++)
                                            {
                                                DnsResourceRecord answer = cacheResponse.Answer[i];
                                                switch (answer.Type)
                                                {
                                                    case DnsResourceRecordType.AAAA:
                                                        found = true;
                                                        PopStack();
                                                        nameServers[nameServerIndex] = nameServers[nameServerIndex].UpdateAddress((answer.RDATA as DnsAAAARecordData).Address);

                                                        for (int j = i + 1; j < cacheResponse.Answer.Count; j++)
                                                        {
                                                            answer = cacheResponse.Answer[j];
                                                            if (answer.Type == DnsResourceRecordType.AAAA)
                                                                nameServers.Insert(nameServerIndex + (j - i), nameServers[nameServerIndex].UpdateAddress((answer.RDATA as DnsAAAARecordData).Address));
                                                        }

                                                        break;

                                                    case DnsResourceRecordType.A:
                                                        found = true;
                                                        PopStack();
                                                        nameServers[nameServerIndex] = nameServers[nameServerIndex].UpdateAddress((answer.RDATA as DnsARecordData).Address);

                                                        for (int j = i + 1; j < cacheResponse.Answer.Count; j++)
                                                        {
                                                            answer = cacheResponse.Answer[j];
                                                            if (answer.Type == DnsResourceRecordType.A)
                                                                nameServers.Insert(nameServerIndex + (j - i), nameServers[nameServerIndex].UpdateAddress((answer.RDATA as DnsARecordData).Address));
                                                        }

                                                        break;

                                                    case DnsResourceRecordType.DS:
                                                        found = true;

                                                        Tuple<bool, IReadOnlyList<DnsResourceRecord>> tupleCacheDSRecords = await TryGetDSFromResponseAsync(cacheResponse, cacheResponse.Question[0].Name);
                                                        if (!tupleCacheDSRecords.Item1)
                                                            throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due to unable to find DS records for owner name: " + cacheResponse.Question[0].Name.ToLowerInvariant(), cacheResponse);

                                                        IReadOnlyList<DnsResourceRecord> cacheDSRecords = tupleCacheDSRecords.Item2;

                                                        extendedDnsErrors.AddRange(cacheResponse.DnsClientExtendedErrors);

                                                        PopStack();

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
                                                }

                                                if (found)
                                                    break;
                                            }

                                            //proceed to resolver loop
                                        }
                                    }
                                    else if (cacheResponse.Authority.Count > 0)
                                    {
                                        DnsResourceRecord firstAuthority = cacheResponse.FindFirstAuthorityRecord();

                                        if (firstAuthority.Type == DnsResourceRecordType.SOA)
                                        {
                                            if (resolverStack.Count == 0)
                                            {
                                                TriggerNsRevalidation();
                                                TriggerNsResolution();
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

                                            nextNameServers = NameServerAddress.GetNameServersFromResponse(cacheResponse, preferIPv6, false);
                                            InspectCacheNameServersForLoops(nextNameServers);

                                            if (nextNameServers.Count > 0)
                                            {
                                                //found name servers from response
                                                nextZoneCut = firstAuthority.Name;

                                                if (ednsFlags.HasFlag(EDnsHeaderFlags.DNSSEC_OK))
                                                {
                                                    Tuple<bool, IReadOnlyList<DnsResourceRecord>> tupleCacheDsRecords = await TryGetDSFromResponseAsync(cacheResponse, nextZoneCut);
                                                    if (tupleCacheDsRecords.Item1)
                                                    {
                                                        IReadOnlyList<DnsResourceRecord> cacheDsRecords = tupleCacheDsRecords.Item2;

                                                        extendedDnsErrors.AddRange(cacheResponse.DnsClientExtendedErrors);

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

                                                if (asyncNsRevalidation)
                                                    AddNsRevalidationParentSideTaskIfRequired(cacheResponse.Authority);
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
                                                    DnsDatagram cachedNsResponse = cache.Query(new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(currentDomain, DnsResourceRecordType.NS, DnsClass.IN) }), findClosestNameServers: true);
                                                    if (cachedNsResponse is null)
                                                        continue;

                                                    nextNameServers = NameServerAddress.GetNameServersFromResponse(cachedNsResponse, preferIPv6, false);
                                                    InspectCacheNameServersForLoops(nextNameServers);

                                                    if (nextNameServers.Count > 0)
                                                    {
                                                        //found NS for parent from cache
                                                        nextZoneCut = currentDomain;

                                                        if (asyncNsRevalidation)
                                                            AddNsRevalidationParentSideTaskIfRequired(cachedNsResponse.Answer);

                                                        break;
                                                    }
                                                }
                                            }

                                            if (nextNameServers.Count > 0)
                                            {
                                                //found NS and/or DS (or proof of no DS)
                                                bool prioritizeOnesWithIPAddress = asyncNsRevalidation || asyncNsResolution || (resolverStack.Count > 0);

                                                if (question.ZoneCut is not null)
                                                    question.ZoneCut = nextZoneCut;

                                                zoneCut = nextZoneCut;
                                                ednsFlags = nextEdnsFlags;
                                                lastDSRecords = nextDSRecords;
                                                nameServers = GetOrderedNameServersToPreferPerformance(nextNameServers, prioritizeOnesWithIPAddress, preferIPv6);
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
                                            TriggerNsResolution();
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
                                                    throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due to unable to find DS records for owner name: " + cacheResponse.Question[0].Name.ToLowerInvariant(), cacheResponse);
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
                                        TriggerNsResolution();
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
                                        TriggerNsResolution();
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
                                                throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due to unable to find DS records for owner name: " + cacheResponse.Question[0].Name.ToLowerInvariant(), cacheResponse);
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
                    zoneCut = "";
                    nameServers = await GetRootServersUsingRootHintsAsync(cache, proxy, preferIPv6, udpPayloadSize, dnssecValidation, retries, timeout, cancellationToken);
                    nameServerIndex = 0;
                    lastResponse = null;
                }

                while (true) //resolver loop
                {
                    if ((lastDSRecords is not null) && !lastDSRecords[0].Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase))
                    {
                        //find the DS for current zone cut recursively in next stack
                        PushStack(zoneCut, DnsResourceRecordType.DS);
                        goto stackLoop;
                    }

                    //query name servers one by one upto referral limit
                    int referralLimit = Math.Min(nameServers.Count, MAX_NS_TO_QUERY_PER_REFERRAL);

                    for (; nameServerIndex < referralLimit; nameServerIndex++) //try next server loop
                    {
                        int currentNameServerIndex = nameServerIndex;

                        //attempt to find name servers that are resolved for concurrent querying
                        List<NameServerAddress> resolvedNameServers = new List<NameServerAddress>(referralLimit - nameServerIndex);

                        for (int i = nameServerIndex; i < referralLimit; i++)
                        {
                            if (nameServers[i].IPEndPoint is null)
                                break;

                            resolvedNameServers.Add(nameServers[i]);
                        }

                        DnsClient dnsClient;

                        if (resolvedNameServers.Count > 0)
                        {
                            //attempt to do concurrent requests to resolved name servers
                            nameServerIndex += resolvedNameServers.Count - 1; //set index to avoid querying these selected name servers again

                            dnsClient = new DnsClient(resolvedNameServers);
                            dnsClient._concurrency = concurrency;
                        }
                        else
                        {
                            //do sequential request to current name server after resolving it
                            NameServerAddress nameServer = nameServers[nameServerIndex];

                            if (preferIPv6)
                            {
                                bool wasIPv6Attempted = false;

                                for (int i = 0; i < nameServerIndex; i++)
                                {
                                    NameServerAddress ns = nameServers[i];

                                    if (ns.Host.Equals(nameServer.Host, StringComparison.OrdinalIgnoreCase))
                                    {
                                        wasIPv6Attempted = true;
                                        break;
                                    }
                                }

                                if (wasIPv6Attempted)
                                {
                                    PushStack(nameServer.Host, DnsResourceRecordType.A);
                                }
                                else
                                {
                                    nameServers.Add(nameServer); //add to allow future IPv4 address resolution if needed

                                    PushStack(nameServer.Host, DnsResourceRecordType.AAAA);
                                }
                            }
                            else
                            {
                                PushStack(nameServer.Host, DnsResourceRecordType.A);
                            }

                            goto stackLoop;
                        }

                        dnsClient._proxy = proxy;
                        dnsClient._randomizeName = randomizeName;
                        dnsClient._retries = retries;
                        dnsClient._timeout = timeout;

                        DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [question], null, null, null, udpPayloadSize, ednsFlags, (resolverStack.Count == 0) && zoneCut.Contains('.') ? eDnsClientSubnetOption : null);
                        DnsDatagram response;

                        try
                        {
                            response = await dnsClient.InternalResolveAsync(request, async delegate (DnsDatagram response, CancellationToken cancellationToken1)
                            {
                                cancellationToken1.ThrowIfCancellationRequested();

                                rawResponses?.Add(response);

                                //sanitize response
                                response = SanitizeResponseAnswerForQName(response);
                                response = SanitizeResponseAnswerForZoneCut(response, zoneCut); //sanitize answer section
                                response = SanitizeResponseAuthorityForZoneCut(response, zoneCut); //sanitize authority section
                                response = SanitizeResponseAdditionalForZoneCut(response, zoneCut); //sanitize additional section

                                if (ednsFlags.HasFlag(EDnsHeaderFlags.DNSSEC_OK))
                                {
                                    //dnssec validate response
                                    await DnssecValidateResponseAsync(response, lastDSRecords, dnsClient, cache, udpPayloadSize, cancellationToken1);

                                    //sanitize response after DNSSEC validation
                                    response = SanitizeResponseAfterDnssecValidation(response);
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

                                return response;
                            }, true, cancellationToken);
                        }
                        catch (DnsClientResponseDnssecValidationException ex)
                        {
                            if (question.ZoneCut is not null)
                            {
                                //QNAME minimization can encounter NO DATA response with unsupported NSEC3 iterations value
                                bool unsupportedNSEC3IterationsValue = false;

                                if (ex.Response is not null)
                                {
                                    foreach (EDnsExtendedDnsErrorOptionData eDnsOption in ex.Response.DnsClientExtendedErrors)
                                    {
                                        if (eDnsOption.InfoCode == EDnsExtendedDnsErrorCode.UnsupportedNSEC3IterationsValue)
                                        {
                                            unsupportedNSEC3IterationsValue = true;
                                            break;
                                        }
                                    }
                                }

                                if (unsupportedNSEC3IterationsValue)
                                {
                                    if (question.Name.Equals(question.MinimizedName, StringComparison.OrdinalIgnoreCase))
                                    {
                                        if (question.Type == question.MinimizedType)
                                        {
                                            //domain wont resolve
                                        }
                                        else
                                        {
                                            //disable QNAME minimization and query again to current server to get correct type response
                                            question.ZoneCut = null;
                                            nameServerIndex = currentNameServerIndex - 1;
                                            continue;
                                        }
                                    }
                                    else
                                    {
                                        //use minimized name as zone cut and query again to current server to move to next label
                                        question.ZoneCut = question.MinimizedName;
                                        nameServerIndex = currentNameServerIndex - 1;
                                        continue;
                                    }
                                }
                            }

                            //continue for loop to next name server since current name server may be out of sync
                            lastException = ex;
                            continue; //try next name server
                        }
                        catch (DnsClientResponseValidationException ex)
                        {
                            if (question.ZoneCut is not null)
                            {
                                if (question.Name.Equals(question.MinimizedName, StringComparison.OrdinalIgnoreCase))
                                {
                                    if (question.Type == question.MinimizedType)
                                    {
                                        //domain wont resolve
                                    }
                                    else
                                    {
                                        //disable QNAME minimization and query again to current server to get correct type response
                                        question.ZoneCut = null;
                                        nameServerIndex = currentNameServerIndex - 1;
                                        continue;
                                    }
                                }
                                else
                                {
                                    //use minimized name as zone cut and query again to current server to move to next label
                                    question.ZoneCut = question.MinimizedName;
                                    nameServerIndex = currentNameServerIndex - 1;
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

                        //add any previous extended dns errors for caching
                        if ((response.RCODE != DnsResponseCode.NoError) && (extendedDnsErrors.Count > 0))
                            response.AddDnsClientExtendedError(extendedDnsErrors);

                        //cache response
                        cache.CacheResponse(response, false, zoneCut);

                        //set as last response
                        lastResponse = response;

                        extendedDnsErrors.AddRange(response.DnsClientExtendedErrors);

                        switch (response.RCODE)
                        {
                            case DnsResponseCode.NoError:
                                {
                                    if (response.Answer.Count > 0)
                                    {
                                        bool qnameMatches = response.Answer[0].Name.Equals(question.Name, StringComparison.OrdinalIgnoreCase);
                                        bool foundDNAME = false;

                                        if (!qnameMatches)
                                        {
                                            foreach (DnsResourceRecord answer in response.Answer)
                                            {
                                                if ((answer.Type == DnsResourceRecordType.DNAME) && question.Name.EndsWith("." + answer.Name, StringComparison.OrdinalIgnoreCase))
                                                {
                                                    foundDNAME = true;
                                                    break;
                                                }
                                            }
                                        }

                                        if (qnameMatches || foundDNAME) //checking for DNAME too
                                        {
                                            if (question.Type == question.MinimizedType)
                                            {
                                                //found answer as QNAME minimization uses A, AAAA, or DS type queries
                                            }
                                            else if (question.ZoneCut is not null)
                                            {
                                                //disable QNAME minimization and query again to current server to get correct type response
                                                question.ZoneCut = null;
                                                nameServerIndex = currentNameServerIndex - 1;
                                                continue;
                                            }
                                        }
                                        else if (question.ZoneCut is not null)
                                        {
                                            //disable QNAME minimization and query again to current server
                                            question.ZoneCut = null;
                                            nameServerIndex = currentNameServerIndex - 1;
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
                                            TriggerNsResolution();

                                            if (extendedDnsErrors.Count > 0)
                                                response.AddDnsClientExtendedError(extendedDnsErrors);

                                            if (minimalResponse)
                                                return GetMinimalResponseWithoutNSAndGlue(response);

                                            return response;
                                        }
                                        else
                                        {
                                            for (int i = 0; i < response.Answer.Count; i++)
                                            {
                                                DnsResourceRecord answer = response.Answer[i];
                                                switch (answer.Type)
                                                {
                                                    case DnsResourceRecordType.AAAA:
                                                        PopStack();
                                                        nameServers[nameServerIndex] = nameServers[nameServerIndex].UpdateAddress((answer.RDATA as DnsAAAARecordData).Address);

                                                        for (int j = i + 1; j < response.Answer.Count; j++)
                                                        {
                                                            answer = response.Answer[j];
                                                            if (answer.Type == DnsResourceRecordType.AAAA)
                                                                nameServers.Insert(nameServerIndex + (j - i), nameServers[nameServerIndex].UpdateAddress((answer.RDATA as DnsAAAARecordData).Address));
                                                        }

                                                        goto resolverLoop;

                                                    case DnsResourceRecordType.A:
                                                        PopStack();
                                                        nameServers[nameServerIndex] = nameServers[nameServerIndex].UpdateAddress((answer.RDATA as DnsARecordData).Address);

                                                        for (int j = i + 1; j < response.Answer.Count; j++)
                                                        {
                                                            answer = response.Answer[j];
                                                            if (answer.Type == DnsResourceRecordType.A)
                                                                nameServers.Insert(nameServerIndex + (j - i), nameServers[nameServerIndex].UpdateAddress((answer.RDATA as DnsARecordData).Address));
                                                        }

                                                        goto resolverLoop;

                                                    case DnsResourceRecordType.DS:
                                                        Tuple<bool, IReadOnlyList<DnsResourceRecord>> tupleDsRecords = await TryGetDSFromResponseAsync(response, request.Question[0].Name);
                                                        if (!tupleDsRecords.Item1)
                                                            throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due to unable to find DS records for owner name: " + request.Question[0].Name.ToLowerInvariant(), response);

                                                        IReadOnlyList<DnsResourceRecord> dsRecords = tupleDsRecords.Item2;

                                                        extendedDnsErrors.AddRange(response.DnsClientExtendedErrors);

                                                        PopStack();

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

                                                        goto resolverLoop;
                                                }
                                            }

                                            //didnt find IP/DS for current name server
                                            continue; //try next name server
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
                                                    if (question.Type == question.MinimizedType)
                                                    {
                                                        //record does not exists
                                                    }
                                                    else
                                                    {
                                                        //disable QNAME minimization and query again to current server to get correct type response
                                                        question.ZoneCut = null;
                                                        nameServerIndex = currentNameServerIndex - 1;
                                                        continue;
                                                    }
                                                }
                                                else
                                                {
                                                    //use minimized name as zone cut and query again to current server to move to next label
                                                    question.ZoneCut = question.MinimizedName;
                                                    nameServerIndex = currentNameServerIndex - 1;
                                                    continue;
                                                }
                                            }

                                            //NO DATA - no entry for given type
                                            if (resolverStack.Count == 0)
                                            {
                                                TriggerNsRevalidation();
                                                TriggerNsResolution();

                                                if (extendedDnsErrors.Count > 0)
                                                    response.AddDnsClientExtendedError(extendedDnsErrors);

                                                if (minimalResponse)
                                                    return GetMinimalResponseWithoutNSAndGlue(response);

                                                return response;
                                            }
                                            else
                                            {
                                                if (question.Type == DnsResourceRecordType.AAAA)
                                                {
                                                    question = new DnsQuestionRecord(question.Name, DnsResourceRecordType.A, question.Class);

                                                    //try same server again with AAAA query
                                                    nameServerIndex = currentNameServerIndex - 1;
                                                    continue;
                                                }
                                                else
                                                {
                                                    //NO DATA - domain does not resolve 
                                                    PopStack();

                                                    switch (request.Question[0].Type)
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
                                            bool continueNextNameServer = false;

                                            foreach (DnsResourceRecord authorityRecord in response.Authority)
                                            {
                                                if ((authorityRecord.Type == DnsResourceRecordType.NS) && authorityRecord.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase))
                                                {
                                                    //empty response with authority name servers that match the zone cut
                                                    if (resolverStack.Count == 0)
                                                    {
                                                        //continue for loop to next name server since current name server may be misconfigured
                                                        continueNextNameServer = true;
                                                        break;
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

                                            if (continueNextNameServer)
                                                break; //continue for loop to next name server since current name server may be misconfigured

                                            //check for hop limit
                                            if (hopCount >= MAX_DELEGATION_HOPS)
                                            {
                                                //max hop count reached
                                                if (resolverStack.Count == 0)
                                                {
                                                    //cannot proceed forever; return what we have and stop
                                                    TriggerNsRevalidation();
                                                    TriggerNsResolution();

                                                    if (extendedDnsErrors.Count > 0)
                                                        response.AddDnsClientExtendedError(extendedDnsErrors);

                                                    if (minimalResponse)
                                                        return GetMinimalResponseWithoutNSAndGlue(response);

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

                                            //get next hop name servers with loopback filter to prevent loops in resolution
                                            List<NameServerAddress> nextNameServers = NameServerAddress.GetNameServersFromResponse(response, preferIPv6, true);

                                            if (nextNameServers.Count > 0)
                                            {
                                                string nextZoneCut = firstAuthority.Name;

                                                EDnsHeaderFlags nextEdnsFlags = ednsFlags;
                                                IReadOnlyList<DnsResourceRecord> nextDSRecords = lastDSRecords;

                                                if (ednsFlags.HasFlag(EDnsHeaderFlags.DNSSEC_OK))
                                                {
                                                    Tuple<bool, IReadOnlyList<DnsResourceRecord>> tupleDsRecords = await TryGetDSFromResponseAsync(response, nextZoneCut);
                                                    if (tupleDsRecords.Item1)
                                                    {
                                                        IReadOnlyList<DnsResourceRecord> dsRecords = tupleDsRecords.Item2;

                                                        extendedDnsErrors.AddRange(response.DnsClientExtendedErrors);

                                                        //get DS records from response
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
                                                }

                                                nextNameServers = ResolveNameServerAddressesFromCache(nextNameServers);
                                                nextNameServers.Shuffle(); //do initial shuffle to avoid querying the same first NS everytime

                                                bool prioritizeOnesWithIPAddress = asyncNsRevalidation || asyncNsResolution || (resolverStack.Count > 0);

                                                if (question.ZoneCut is not null)
                                                    question.ZoneCut = nextZoneCut;

                                                zoneCut = nextZoneCut;
                                                ednsFlags = nextEdnsFlags;
                                                lastDSRecords = nextDSRecords;
                                                nameServers = GetOrderedNameServersToPreferPerformance(nextNameServers, prioritizeOnesWithIPAddress, preferIPv6);
                                                nameServerIndex = 0;
                                                hopCount++;
                                                lastResponse = null; //reset last response for current zone cut

                                                //add to NS revalidation task list
                                                if (asyncNsRevalidation)
                                                    nsRevalidationChildSideTasks.TryAdd(zoneCut.ToLowerInvariant(), new NsRevalidationTask(lastDSRecords, nextNameServers));

                                                //add to async NS resolution task list
                                                if (asyncNsResolution)
                                                {
                                                    int maxNsResolutions = Math.Min(nextNameServers.Count, MAX_NS_TO_QUERY_PER_REFERRAL);

                                                    foreach (NameServerAddress nextNameServer in nextNameServers)
                                                    {
                                                        if (nextNameServer.IPEndPoint is null)
                                                        {
                                                            if (asyncNsResolutionTasks.TryAdd(nextNameServer.DomainEndPoint.Address, null))
                                                            {
                                                                maxNsResolutions--;

                                                                if (maxNsResolutions < 1)
                                                                    break;
                                                            }
                                                        }
                                                    }
                                                }

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
                                                if (question.Type == question.MinimizedType)
                                                {
                                                    //record does not exists
                                                }
                                                else
                                                {
                                                    //disable QNAME minimization and query again to current server to get correct type response
                                                    question.ZoneCut = null;
                                                    nameServerIndex = currentNameServerIndex - 1;
                                                    continue;
                                                }
                                            }
                                            else
                                            {
                                                //use minimized name as zone cut and query again to current server to move to next label
                                                question.ZoneCut = question.MinimizedName;
                                                nameServerIndex = currentNameServerIndex - 1;
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
                                        if (question.Name.Equals(question.MinimizedName, StringComparison.OrdinalIgnoreCase) && (question.Type == question.MinimizedType))
                                        {
                                            //domain does not exists
                                        }
                                        else
                                        {
                                            //disable QNAME minimization and query again to current server to confirm full name response
                                            question.ZoneCut = null;
                                            nameServerIndex = currentNameServerIndex - 1;
                                            continue;
                                        }
                                    }

                                    if (resolverStack.Count == 0)
                                    {
                                        TriggerNsRevalidation();
                                        TriggerNsResolution();

                                        if (extendedDnsErrors.Count > 0)
                                            response.AddDnsClientExtendedError(extendedDnsErrors);

                                        if (minimalResponse)
                                            return GetMinimalResponseWithoutNSAndGlue(response);

                                        return response;
                                    }
                                    else
                                    {
                                        //domain does not exists
                                        PopStack();

                                        switch (request.Question[0].Type)
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
                                            if (question.Type == question.MinimizedType)
                                            {
                                                //domain wont resolve
                                            }
                                            else
                                            {
                                                //disable QNAME minimization and query again to current server to get correct type response
                                                question.ZoneCut = null;
                                                nameServerIndex = currentNameServerIndex - 1;
                                                continue;
                                            }
                                        }
                                        else
                                        {
                                            //use minimized name as zone cut and query again to current server to move to next label
                                            question.ZoneCut = question.MinimizedName;
                                            nameServerIndex = currentNameServerIndex - 1;
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
                        TriggerNsResolution();

                        if (lastResponse is not null)
                        {
                            if ((lastResponse.Question.Count > 0) && lastResponse.Question[0].Equals(question))
                            {
                                if (extendedDnsErrors.Count > 0)
                                    lastResponse.AddDnsClientExtendedError(extendedDnsErrors);

                                if (minimalResponse)
                                    return GetMinimalResponseWithoutNSAndGlue(lastResponse);

                                return lastResponse;
                            }
                        }

                        if (lastException is null)
                        {
                            //cache as failure
                            DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { question });

                            if (extendedDnsErrors.Count > 0)
                                failureResponse.AddDnsClientExtendedError(extendedDnsErrors);

                            failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NoReachableAuthority, "No response from name servers for " + question.ToString());

                            if (eDnsClientSubnet is not null)
                                failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(eDnsClientSubnet.PrefixLength, eDnsClientSubnet.PrefixLength, eDnsClientSubnet.Address));

                            cache.CacheResponse(failureResponse);
                        }
                        else if (lastException is DnsClientResponseDnssecValidationException ex)
                        {
                            if ((ex.Response.Question.Count > 0) && ex.Response.Question[0].Equals(question))
                            {
                                //was already cached as bad cache
                            }
                            else
                            {
                                //response is not for current question; cache its extended errors as failure response
                                DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { question });

                                if (extendedDnsErrors.Count > 0)
                                    failureResponse.AddDnsClientExtendedError(extendedDnsErrors);

                                failureResponse.AddDnsClientExtendedErrorFrom(ex.Response);

                                if (eDnsClientSubnet is not null)
                                    failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(eDnsClientSubnet.PrefixLength, eDnsClientSubnet.PrefixLength, eDnsClientSubnet.Address));

                                //cache as failure
                                cache.CacheResponse(failureResponse);
                            }

                            ExceptionDispatchInfo.Throw(lastException);
                        }
                        else if (lastException is DnsClientNoResponseException)
                        {
                            //cache as failure
                            DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { question });

                            if (extendedDnsErrors.Count > 0)
                                failureResponse.AddDnsClientExtendedError(extendedDnsErrors);

                            failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NoReachableAuthority, "No response from name servers for " + question.ToString());

                            if (eDnsClientSubnet is not null)
                                failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(eDnsClientSubnet.PrefixLength, eDnsClientSubnet.PrefixLength, eDnsClientSubnet.Address));

                            cache.CacheResponse(failureResponse);
                        }
                        else if (lastException is SocketException ex2)
                        {
                            //cache as failure
                            DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { question });

                            if (extendedDnsErrors.Count > 0)
                                failureResponse.AddDnsClientExtendedError(extendedDnsErrors);

                            if (ex2.SocketErrorCode == SocketError.TimedOut)
                                failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NoReachableAuthority, "Request timed out for " + question.ToString());
                            else
                                failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NetworkError, "Socket error for " + question.ToString() + ": " + ex2.SocketErrorCode.ToString());

                            if (eDnsClientSubnet is not null)
                                failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(eDnsClientSubnet.PrefixLength, eDnsClientSubnet.PrefixLength, eDnsClientSubnet.Address));

                            cache.CacheResponse(failureResponse);
                        }
                        else if (lastException is IOException ex3)
                        {
                            //cache as failure
                            DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { question });

                            if (extendedDnsErrors.Count > 0)
                                failureResponse.AddDnsClientExtendedError(extendedDnsErrors);

                            if (ex3.InnerException is SocketException ex3a)
                            {
                                if (ex3a.SocketErrorCode == SocketError.TimedOut)
                                    failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NoReachableAuthority, "Request timed out for " + question.ToString());
                                else
                                    failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NetworkError, "Socket error for " + question.ToString() + ": " + ex3a.SocketErrorCode.ToString());
                            }
                            else
                            {
                                failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NetworkError, "IO error for " + question.ToString() + ": " + ex3.Message);
                            }

                            if (eDnsClientSubnet is not null)
                                failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(eDnsClientSubnet.PrefixLength, eDnsClientSubnet.PrefixLength, eDnsClientSubnet.Address));

                            cache.CacheResponse(failureResponse);
                        }
                        else
                        {
                            //cache as failure
                            DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { question });

                            if (extendedDnsErrors.Count > 0)
                                failureResponse.AddDnsClientExtendedError(extendedDnsErrors);

                            if (lastException is not null)
                                failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.Other, "Resolver exception for " + question.ToString() + ": " + lastException.Message);

                            if (eDnsClientSubnet is not null)
                                failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(eDnsClientSubnet.PrefixLength, eDnsClientSubnet.PrefixLength, eDnsClientSubnet.Address));

                            cache.CacheResponse(failureResponse);
                        }

                        throw new DnsClientNoResponseException("DnsClient failed to recursively resolve the request '" + question.ToString() + "': no response from name servers [" + nameServers.Join() + "].", lastException);
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
                                DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { question });

                                if (extendedDnsErrors.Count > 0)
                                    failureResponse.AddDnsClientExtendedError(extendedDnsErrors);

                                failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.DnssecIndeterminate, "Unable to resolve DS for " + lastQuestion.Name.ToLowerInvariant());

                                if (eDnsClientSubnet is not null)
                                    failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(eDnsClientSubnet.PrefixLength, eDnsClientSubnet.PrefixLength, eDnsClientSubnet.Address));

                                cache.CacheResponse(failureResponse);

                                throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due to unable to find DS records for owner name: " + lastQuestion.Name.ToLowerInvariant(), lastResponse is null ? failureResponse : lastResponse);
                        }

                        //proceed to resolver loop
                    }

                    resolverLoop:;
                }

                stackLoop:;
            }
        }

        public static Task<DnsDatagram> RecursiveResolveQueryAsync(DnsQuestionRecord question, IDnsCache cache = null, NetProxy proxy = null, bool preferIPv6 = false, ushort udpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE, bool randomizeName = false, bool qnameMinimization = false, bool dnssecValidation = false, NetworkAddress eDnsClientSubnet = null, int retries = 2, int timeout = 2000, int concurrency = 2, int maxStackCount = 16, CancellationToken cancellationToken = default)
        {
            if (cache is null)
                cache = new DnsCache();

            return ResolveQueryAsync(question, delegate (DnsQuestionRecord q)
            {
                return RecursiveResolveAsync(q, cache, proxy, preferIPv6, udpPayloadSize, randomizeName, qnameMinimization, false, dnssecValidation, eDnsClientSubnet, retries, timeout, concurrency, maxStackCount, true, false, null, cancellationToken);
            });
        }

        public static async Task<IReadOnlyList<IPAddress>> RecursiveResolveIPAsync(string domain, IDnsCache cache = null, NetProxy proxy = null, bool preferIPv6 = false, ushort udpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE, bool randomizeName = false, bool qnameMinimization = false, bool dnssecValidation = false, NetworkAddress eDnsClientSubnet = null, int retries = 2, int timeout = 2000, int concurrency = 2, int maxStackCount = 16, CancellationToken cancellationToken = default)
        {
            if (cache is null)
                cache = new DnsCache();

            if (preferIPv6)
            {
                IReadOnlyList<IPAddress> addresses = ParseResponseAAAA(await RecursiveResolveQueryAsync(new DnsQuestionRecord(domain, DnsResourceRecordType.AAAA, DnsClass.IN), cache, proxy, preferIPv6, udpPayloadSize, randomizeName, qnameMinimization, dnssecValidation, eDnsClientSubnet, retries, timeout, concurrency, maxStackCount, cancellationToken));
                if (addresses.Count > 0)
                    return addresses;
            }

            return ParseResponseA(await RecursiveResolveQueryAsync(new DnsQuestionRecord(domain, DnsResourceRecordType.A, DnsClass.IN), cache, proxy, preferIPv6, udpPayloadSize, randomizeName, qnameMinimization, dnssecValidation, eDnsClientSubnet, retries, timeout, concurrency, maxStackCount, cancellationToken));
        }

        public static async Task<IReadOnlyList<IPAddress>> ResolveIPAsync(IDnsClient dnsClient, string domain, bool preferIPv6 = false, CancellationToken cancellationToken = default)
        {
            if (preferIPv6)
            {
                IReadOnlyList<IPAddress> addresses = ParseResponseAAAA(await dnsClient.ResolveAsync(new DnsQuestionRecord(domain, DnsResourceRecordType.AAAA, DnsClass.IN), cancellationToken));
                if (addresses.Count > 0)
                    return addresses;
            }

            return ParseResponseA(await dnsClient.ResolveAsync(new DnsQuestionRecord(domain, DnsResourceRecordType.A, DnsClass.IN), cancellationToken));
        }

        public static async Task<IReadOnlyList<string>> ResolveMXAsync(IDnsClient dnsClient, string domain, bool resolveIP = false, bool preferIPv6 = false, CancellationToken cancellationToken = default)
        {
            if (IPAddress.TryParse(domain, out _))
            {
                //host is valid ip address
                return new string[] { domain };
            }

            DnsDatagram response = await dnsClient.ResolveAsync(new DnsQuestionRecord(domain, DnsResourceRecordType.MX, DnsClass.IN), cancellationToken);
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
                    switch (record.DnssecStatus)
                    {
                        case DnssecStatus.Disabled:
                        case DnssecStatus.Secure:
                        case DnssecStatus.Insecure:
                            break;

                        default:
                            continue;
                    }

                    if (record.Name.Equals(mxEntry, StringComparison.OrdinalIgnoreCase))
                    {
                        switch (record.Type)
                        {
                            case DnsResourceRecordType.A:
                                if (!preferIPv6)
                                {
                                    mxAddresses.Add((record.RDATA as DnsARecordData).Address.ToString());
                                    glueRecordFound = true;
                                }
                                break;

                            case DnsResourceRecordType.AAAA:
                                if (preferIPv6)
                                {
                                    mxAddresses.Add((record.RDATA as DnsAAAARecordData).Address.ToString());
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
                        IReadOnlyList<IPAddress> ipList = await ResolveIPAsync(dnsClient, mxEntry, preferIPv6, cancellationToken);

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
                                    ipAddresses.Add((record.RDATA as DnsARecordData).Address);
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = (record.RDATA as DnsCNAMERecordData).Domain;
                                    break;
                            }
                        }
                    }

                    return ipAddresses;

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + (response.Metadata is null ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientNoResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + (response.Metadata is null ? "" : " from Name server: " + response.Metadata.NameServer.ToString()));
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
                                    ipAddresses.Add((record.RDATA as DnsAAAARecordData).Address);
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = (record.RDATA as DnsCNAMERecordData).Domain;
                                    break;
                            }
                        }
                    }

                    return ipAddresses;

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + (response.Metadata is null ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientNoResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + (response.Metadata is null ? "" : " from Name server: " + response.Metadata.NameServer.ToString()));
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
                                    txtRecords.Add((record.RDATA as DnsTXTRecordData).GetText());
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = (record.RDATA as DnsCNAMERecordData).Domain;
                                    break;
                            }
                        }
                    }

                    return txtRecords;

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + (response.Metadata is null ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientNoResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + (response.Metadata is null ? "" : " from Name server: " + response.Metadata.NameServer.ToString()));
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
                                    values.Add((record.RDATA as DnsPTRRecordData).Domain);
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = (record.RDATA as DnsCNAMERecordData).Domain;
                                    break;
                            }
                        }
                    }

                    return values;

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + (response.Metadata is null ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientNoResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + (response.Metadata is null ? "" : " from Name server: " + response.Metadata.NameServer.ToString()));
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

                    List<DnsMXRecordData> mxRecords = new List<DnsMXRecordData>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.MX:
                                    mxRecords.Add(record.RDATA as DnsMXRecordData);
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = (record.RDATA as DnsCNAMERecordData).Domain;
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
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + (response.Metadata is null ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientNoResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + (response.Metadata is null ? "" : " from Name server: " + response.Metadata.NameServer.ToString()));
            }
        }

        public static IReadOnlyList<DnsDSRecordData> ParseResponseDS(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return Array.Empty<DnsDSRecordData>();

                    List<DnsDSRecordData> dsRecords = new List<DnsDSRecordData>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.DS:
                                    dsRecords.Add(record.RDATA as DnsDSRecordData);
                                    break;
                            }
                        }
                    }

                    return dsRecords;

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + (response.Metadata is null ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientNoResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + (response.Metadata is null ? "" : " from Name server: " + response.Metadata.NameServer.ToString()));
            }
        }

        public static IReadOnlyList<DnsTLSARecordData> ParseResponseTLSA(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return Array.Empty<DnsTLSARecordData>();

                    List<DnsTLSARecordData> tlsaRecords = new List<DnsTLSARecordData>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.DnssecStatus != DnssecStatus.Secure)
                            continue;

                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.TLSA:
                                    DnsTLSARecordData tlsa = record.RDATA as DnsTLSARecordData;

                                    switch (tlsa.CertificateUsage)
                                    {
                                        case DnsTLSACertificateUsage.PKIX_TA:
                                        case DnsTLSACertificateUsage.PKIX_EE:
                                        case DnsTLSACertificateUsage.DANE_TA:
                                        case DnsTLSACertificateUsage.DANE_EE:
                                            break;

                                        default:
                                            continue; //unusable
                                    }

                                    switch (tlsa.Selector)
                                    {
                                        case DnsTLSASelector.Cert:
                                        case DnsTLSASelector.SPKI:
                                            break;

                                        default:
                                            continue; //unusable
                                    }

                                    switch (tlsa.MatchingType)
                                    {
                                        case DnsTLSAMatchingType.Full:
                                        case DnsTLSAMatchingType.SHA2_256:
                                        case DnsTLSAMatchingType.SHA2_512:
                                            break;

                                        default:
                                            continue; //unusable
                                    }

                                    if (tlsa.CertificateAssociationData.Length == 0)
                                        continue; //unusable

                                    tlsaRecords.Add(tlsa);
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = (record.RDATA as DnsCNAMERecordData).Domain;
                                    break;
                            }
                        }
                    }

                    return tlsaRecords;

                case DnsResponseCode.NxDomain:
                    return null;

                default:
                    throw new DnsClientNoResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + (response.Metadata is null ? "" : " from Name server: " + response.Metadata.NameServer.ToString()));
            }
        }

        public static IReadOnlyList<DnsZONEMDRecordData> ParseResponseZONEMD(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return [];

                    List<DnsZONEMDRecordData> zonemdRecords = new List<DnsZONEMDRecordData>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.ZONEMD:
                                    zonemdRecords.Add(record.RDATA as DnsZONEMDRecordData);
                                    break;
                            }
                        }
                    }

                    return zonemdRecords;

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + (response.Metadata is null ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientNoResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + (response.Metadata is null ? "" : " from Name server: " + response.Metadata.NameServer.ToString()));
            }
        }

        public static DnsSOARecordData ParseResponseSOA(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return null;

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.SOA:
                                    return record.RDATA as DnsSOARecordData;
                            }
                        }
                    }

                    return null;

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + (response.Metadata is null ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientNoResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + (response.Metadata is null ? "" : " from Name server: " + response.Metadata.NameServer.ToString()));
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

                        if (labelChar == 47) //[/]
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

        public static bool IsDomainNameUnicode(string domain)
        {
            foreach (char c in domain)
            {
                if (!char.IsAscii(c))
                    return true;
            }

            return false;
        }

        public static string ConvertDomainNameToAscii(string domain)
        {
            return _idnMapping.GetAscii(domain);
        }

        public static string ConvertDomainNameToUnicode(string domain)
        {
            return _idnMapping.GetUnicode(domain);
        }

        public static bool TryConvertDomainNameToUnicode(string domain, out string idn)
        {
            if (domain.Contains("xn--", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    idn = _idnMapping.GetUnicode(domain);
                    return true;
                }
                catch
                { }
            }

            idn = null;
            return false;
        }

        #endregion

        #region private

        private static int CompareNameServersToPreferOnesWithIPAddress(NameServerAddress x, NameServerAddress y)
        {
            if (x.IPEndPoint is null)
            {
                if (y.IPEndPoint is null)
                    return 0;
                else
                    return 1;
            }
            else
            {
                if (y.IPEndPoint is null)
                    return -1;
                else
                    return 0;
            }
        }

        private static int CompareNameServersToPreferIPv6(NameServerAddress x, NameServerAddress y)
        {
            if ((x.IPEndPoint is null) || (y.IPEndPoint is null))
                return 0;

            if ((x.IPEndPoint.AddressFamily == AddressFamily.InterNetwork) && (y.IPEndPoint.AddressFamily == AddressFamily.InterNetworkV6))
                return 1;

            if ((x.IPEndPoint.AddressFamily == AddressFamily.InterNetworkV6) && (y.IPEndPoint.AddressFamily == AddressFamily.InterNetwork))
                return -1;

            return 0;
        }

        private static int CompareNameServersToPreferPerformance(NameServerAddress x, NameServerAddress y)
        {
            double v1 = x.Metadata.GetNetRTT();
            double v2 = y.Metadata.GetNetRTT();

            return v1.CompareTo(v2);
        }

        private static List<NameServerAddress> GetOrderedNameServersToPreferPerformance(IReadOnlyCollection<NameServerAddress> nameServers, bool prioritizeOnesWithIPAddress, bool preferIPv6)
        {
            //create copy of root name servers array so that the values in original array are not messed due to shuffling/sorting feature
            List<NameServerAddress> nameServersList = new List<NameServerAddress>(nameServers);

            //Using Epsilon-Greedy Algorithm
            const int EPSILON = 5;
            int p = RandomNumberGenerator.GetInt32(100);

            if (p < EPSILON)
                nameServersList.Shuffle(); //exploration
            else
                nameServersList.Sort(CompareNameServersToPreferPerformance); //exploitation

            if (prioritizeOnesWithIPAddress)
                nameServersList.Sort(CompareNameServersToPreferOnesWithIPAddress); //sort name servers to prioritize ones with IP address

            if (preferIPv6)
                nameServersList.Sort(CompareNameServersToPreferIPv6); //sort name servers to prefer IPv6

            return nameServersList;
        }

        private static async Task<List<NameServerAddress>> GetRootServersUsingRootHintsAsync(IDnsCache cache, NetProxy proxy, bool preferIPv6, ushort udpPayloadSize, bool dnssecValidation, int retries, int timeout, CancellationToken cancellationToken = default)
        {
            //create copy of root name servers array so that the values in original array are not messed due to shuffling feature
            List<NameServerAddress> rootHints;

            if (preferIPv6)
            {
                List<NameServerAddress> nameServersList = new List<NameServerAddress>(IPv6_ROOT_HINTS.Count + IPv4_ROOT_HINTS.Count);

                nameServersList.AddRange(IPv6_ROOT_HINTS);
                nameServersList.AddRange(IPv4_ROOT_HINTS);
                nameServersList.Shuffle();
                nameServersList.Sort(CompareNameServersToPreferIPv6);

                rootHints = nameServersList;
            }
            else
            {
                List<NameServerAddress> nameServersList = new List<NameServerAddress>(IPv4_ROOT_HINTS);
                nameServersList.Shuffle();

                rootHints = nameServersList;
            }

            //get root servers by priming query
            DnsClient dnsClient = new DnsClient(rootHints);

            dnsClient._cache = cache;
            dnsClient._proxy = proxy;
            dnsClient._preferIPv6 = preferIPv6;
            dnsClient._udpPayloadSize = udpPayloadSize;
            dnsClient._dnssecValidation = dnssecValidation;
            dnsClient._retries = retries;
            dnsClient._timeout = timeout;

            DnsQuestionRecord question = new DnsQuestionRecord("", DnsResourceRecordType.NS, DnsClass.IN);
            DnsDatagram response;

            if (dnssecValidation)
                response = await dnsClient.InternalDnssecResolveAsync(question, cancellationToken);
            else
                response = await dnsClient.InternalNoDnssecResolveAsync(new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, dnssecValidation, DnsResponseCode.NoError, [question], null, null, null, udpPayloadSize, dnssecValidation ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, null), cancellationToken);

            //validate priming query response
            if (response.RCODE != DnsResponseCode.NoError)
                throw new DnsClientNoResponseException("DnsClient failed to resolve the request '" + question.ToString() + "'. Received a response with RCODE: " + response.RCODE + (response.Metadata is null ? "" : " from Name server: " + response.Metadata.NameServer.ToString()));

            if (!response.AuthoritativeAnswer)
                throw new DnsClientNoResponseException("DnsClient failed to resolve the request '" + question.ToString() + "'. Received a response without AuthoritativeAnswer flag set from Name server: " + response.Metadata.NameServer.ToString());

            if ((response.Answer.Count == 0) || (response.Authority.Count > 0) || (response.Additional.Count == 0))
                throw new DnsClientNoResponseException("DnsClient failed to resolve the request '" + question.ToString() + "'. Received a response without any answer from Name server: " + response.Metadata.NameServer.ToString());

            cache.CacheResponse(response);

            List<NameServerAddress> rootServers = NameServerAddress.GetNameServersFromResponse(response, preferIPv6, true);
            rootServers.Shuffle();

            return rootServers;
        }

        private static async Task DnssecValidateResponseAsync(DnsDatagram response, IReadOnlyList<DnsResourceRecord> lastDSRecords, DnsClient dnsClient, IDnsCache cache, ushort udpPayloadSize, CancellationToken cancellationToken = default)
        {
            //find current DNSKEY
            IReadOnlyList<DnsResourceRecord> currentDnsKeyRecords = await GetDnsKeyForAsync(lastDSRecords, dnsClient, cache, udpPayloadSize, cancellationToken);

            string lastDSOwnerName = lastDSRecords[0].Name;
            DnsClass @class = response.Question[0].Class;
            List<DnsResourceRecord> allDnsKeyRecords = new List<DnsResourceRecord>(4);
            List<string> unsignedZones = null;

            //add current dns key
            allDnsKeyRecords.AddRange(currentDnsKeyRecords);

            //find signer's names for verification
            IReadOnlyCollection<string> signersNames = FindSignersNames(response);

            //find DNSKEYs for all signers that are sub domain names for last DS record owner name
            foreach (string signersName in signersNames)
            {
                if (signersName.Equals(lastDSOwnerName, StringComparison.OrdinalIgnoreCase))
                    continue; //already found DNSKEYs for last DS record owner name

                IReadOnlyList<DnsResourceRecord> dnsKeyRecords;

                if (signersName.EndsWith("." + lastDSOwnerName, StringComparison.OrdinalIgnoreCase) || (lastDSOwnerName.Length == 0))
                {
                    //signer's name is a subdomain for last DS record owner name
                    //find signer's DNSKEYs
                    dnsKeyRecords = await FindDnsKeyForAsync(signersName, @class, currentDnsKeyRecords, dnsClient, cache, udpPayloadSize, response, cancellationToken);
                }
                else
                {
                    //signer's name is not related to last DS record
                    //get root's DNSKEYs
                    IReadOnlyList<DnsResourceRecord> rootDnsKeyRecords = await GetDnsKeyForAsync(ROOT_TRUST_ANCHORS, dnsClient, cache, udpPayloadSize, cancellationToken);

                    //find signer's DNSKEYs
                    if (signersName.Length == 0)
                        dnsKeyRecords = rootDnsKeyRecords;
                    else
                        dnsKeyRecords = await FindDnsKeyForAsync(signersName, @class, rootDnsKeyRecords, dnsClient, cache, udpPayloadSize, response, cancellationToken);
                }

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

            try
            {
                //verify signature for all records in response
                await DnssecValidateSignatureAsync(response, allDnsKeyRecords, unsignedZones);

                //validate proofs for response
                switch (response.RCODE)
                {
                    case DnsResponseCode.NoError:
                        if (response.Answer.Count > 0)
                        {
                            foreach (DnsResourceRecord rrsigRecord in response.Answer)
                            {
                                if (rrsigRecord.Type != DnsResourceRecordType.RRSIG)
                                    continue;

                                if (DnsRRSIGRecordData.IsWildcard(rrsigRecord, out string nextCloserName))
                                {
                                    //For every wildcard expansion, we need to prove that the expansion was allowed.

                                    //validate wildcard
                                    DnsResourceRecordType typeCovered = (rrsigRecord.RDATA as DnsRRSIGRecordData).TypeCovered;
                                    DnssecProofOfNonExistence proofOfNonExistence = await GetValidatedProofOfNonExistenceAsync(response, rrsigRecord.Name, typeCovered, true, nextCloserName);
                                    switch (proofOfNonExistence)
                                    {
                                        case DnssecProofOfNonExistence.OptOut:
                                        case DnssecProofOfNonExistence.NxDomain:
                                        case DnssecProofOfNonExistence.UnsupportedNSEC3IterationsValue:
                                            //record does not exists so wildcard is valid
                                            break;

                                        default:
                                            response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NSECMissing, "Missing non-existence proof (Wildcard) for " + rrsigRecord.Name + " " + typeCovered.ToString() + " " + rrsigRecord.Class.ToString());
                                            throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed as the response was unable to prove non-existence (Wildcard) for owner name: " + rrsigRecord.Name + "/" + typeCovered.ToString(), response);
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

                                        DnssecProofOfNonExistence proofOfNonExistence = await GetValidatedProofOfNonExistenceAsync(response, question.Name, question.Type);
                                        switch (proofOfNonExistence)
                                        {
                                            case DnssecProofOfNonExistence.OptOut:
                                            case DnssecProofOfNonExistence.NoData:
                                            case DnssecProofOfNonExistence.InsecureDelegation: //proves no DS record exists
                                            case DnssecProofOfNonExistence.UnsupportedNSEC3IterationsValue:
                                                //no data for the type was found
                                                break;

                                            default:
                                                response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NSECMissing, "Missing non-existence proof (No Data) for " + question.ToString());
                                                throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed as the response was unable to prove non-existence (No Data) for owner name: " + question.Name.ToLowerInvariant() + "/" + question.Type.ToString(), response);
                                        }
                                    }
                                    break;

                                case DnsResourceRecordType.NS:
                                    {
                                        //validate if DS records are really missing
                                        DnssecProofOfNonExistence proofOfNonExistence = await GetValidatedProofOfNonExistenceAsync(response, question.Name, DnsResourceRecordType.DS);
                                        switch (proofOfNonExistence)
                                        {
                                            case DnssecProofOfNonExistence.InsecureDelegation:
                                            case DnssecProofOfNonExistence.OptOut:
                                            case DnssecProofOfNonExistence.NoData:
                                            case DnssecProofOfNonExistence.UnsupportedNSEC3IterationsValue:
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
                                    response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NSECMissing, "Missing non-existence proof (No Data) for " + question.ToString());
                                    throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed as the response was unable to prove non-existence (No Data) for owner name: " + question.Name.ToLowerInvariant() + "/" + question.Type.ToString(), response);
                            }
                        }
                        else
                        {
                            //empty answer and authority section
                            DnsQuestionRecord question = response.Question[0];

                            if (IsDomainUnsigned(question.Name, unsignedZones))
                                break;

                            response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NSECMissing, "Missing non-existence proof (No Data) for " + question.ToString());
                            throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed as the response was unable to prove non-existence (No Data) for owner name: " + question.Name.ToLowerInvariant() + "/" + question.Type.ToString(), response);
                        }

                        break;

                    case DnsResponseCode.NxDomain:
                        {
                            DnsQuestionRecord question = response.Question[0];

                            if (IsDomainUnsigned(question.Name, unsignedZones))
                                break;

                            DnssecProofOfNonExistence proofOfNonExistence = await GetValidatedProofOfNonExistenceAsync(response, question.Name, question.Type);
                            switch (proofOfNonExistence)
                            {
                                case DnssecProofOfNonExistence.OptOut:
                                case DnssecProofOfNonExistence.NxDomain:
                                case DnssecProofOfNonExistence.UnsupportedNSEC3IterationsValue:
                                    //domain does not exists or could not prove it exists due to opt-opt
                                    break;

                                default:
                                    response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NSECMissing, "Missing non-existence proof (NX Domain) for " + question.Name.ToLowerInvariant());
                                    throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed as the response was unable to prove non-existence (NX Domain) for owner name: " + question.Name.ToLowerInvariant(), response);
                            }
                        }
                        break;
                }
            }
            catch (DnsClientResponseDnssecValidationException ex)
            {
                cache.CacheResponse(ex.Response, true);
                throw;
            }
        }

        private static async Task DnssecValidateSignatureAsync(DnsDatagram response, IReadOnlyList<DnsResourceRecord> dnsKeyRecords, IReadOnlyList<string> unsignedZones)
        {
            //check if any DNSKEY with a supported algorithm is available
            if (!DnsDNSKEYRecordData.IsAnyDnssecAlgorithmSupported(dnsKeyRecords))
            {
                //no DNSKEY available with a supported algorithm; mark response as Insecure
                response.SetDnssecStatusForAllRecords(DnssecStatus.Insecure);
                return;
            }

            //check if DNSKEYs are marked as insecure
            foreach (DnsResourceRecord dnsKeyRecord in dnsKeyRecords)
            {
                if (dnsKeyRecord.Type != DnsResourceRecordType.DNSKEY)
                    continue;

                if (dnsKeyRecord.DnssecStatus == DnssecStatus.Insecure)
                {
                    //DNSKEY with insecure status found; mark response as Insecure
                    response.SetDnssecStatusForAllRecords(DnssecStatus.Insecure);
                    return;
                }
            }

            //verify signature for all records in response
            DnssecValidateSignatureParameters parameters = new DnssecValidateSignatureParameters();

            if (response.Answer.Count > 0)
            {
                await DnssecValidateSignatureAsync(response, response.Answer, dnsKeyRecords, unsignedZones, parameters, false, false);

                if (response.Question[0].Type == DnsResourceRecordType.DNSKEY)
                    dnsKeyRecords = response.Answer; //use all DNSKEYs for validating authority & additional sections
            }

            if (response.Authority.Count > 0)
                await DnssecValidateSignatureAsync(response, response.Authority, dnsKeyRecords, unsignedZones, parameters, true, false);

            if (response.Additional.Count > 1) //OPT record always exists
                await DnssecValidateSignatureAsync(response, response.Additional, dnsKeyRecords, unsignedZones, parameters, false, true);

            //update all record status
            response.SetDnssecStatusForAllRecords(DnssecStatus.Indeterminate);
        }

        private static async Task DnssecValidateSignatureAsync(DnsDatagram response, IReadOnlyList<DnsResourceRecord> records, IReadOnlyList<DnsResourceRecord> dnsKeyRecords, IReadOnlyList<string> unsignedZones, DnssecValidateSignatureParameters parameters, bool isAuthoritySection, bool isAdditionalSection)
        {
            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedRecords = DnsResourceRecord.GroupRecords(records, true);

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

                    if (parameters.MaxSuspensions < 1)
                    {
                        foreach (DnsResourceRecord record in rrset.Value)
                            record.SetDnssecStatus(DnssecStatus.Indeterminate);

                        response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.TooManyCryptoValidations, "Too many crypto validations for " + ownerName + " " + rrsetType + " " + rrsetClass.ToString());
                        continue;
                    }

                    bool foundValidSignature = false;
                    EDnsExtendedDnsErrorCode lastExtendedDnsErrorCode = EDnsExtendedDnsErrorCode.RRSIGsMissing;

                    //find RRSIG for current RRSET
                    foreach (DnsResourceRecord rrsigRecord in records)
                    {
                        if (rrsigRecord.Type != DnsResourceRecordType.RRSIG)
                            continue;

                        //The RRSIG RR and the RRset MUST have the same owner name and the same class.
                        if (rrsigRecord.Name.Equals(ownerName, StringComparison.OrdinalIgnoreCase) && (rrsigRecord.Class == rrsetClass))
                        {
                            DnsRRSIGRecordData rrsig = rrsigRecord.RDATA as DnsRRSIGRecordData;

                            //The RRSIG RR's Signer's Name field MUST be the name of the zone that contains the RRset.
                            if ((rrsig.SignersName.Length > 0) && !ownerName.Equals(rrsig.SignersName, StringComparison.OrdinalIgnoreCase) && !ownerName.EndsWith("." + rrsig.SignersName, StringComparison.OrdinalIgnoreCase))
                                continue;

                            //The RRSIG RR's Type Covered field MUST equal the RRset's type.
                            if (rrsig.TypeCovered != rrsetType)
                                continue;

                            //validate records
                            if (rrsig.IsSignatureValid(rrset.Value, dnsKeyRecords, ref parameters.MaxCryptoFailures, out EDnsExtendedDnsErrorCode extendedDnsErrorCode))
                            {
                                foundValidSignature = true;

                                rrsigRecord.SetDnssecStatus(DnssecStatus.Secure);

                                parameters.MaxCryptoValidations--;

                                if (parameters.MaxCryptoValidations < 1)
                                {
                                    parameters.MaxSuspensions--;

                                    if (parameters.MaxSuspensions < 1)
                                        break;

                                    //suspend current task by yielding
                                    await Task.Yield();

                                    parameters.MaxCryptoValidations = KEY_TRAP_MAX_RRSET_VALIDATIONS_PER_SUSPENSION;
                                }
                            }
                            else
                            {
                                lastExtendedDnsErrorCode = extendedDnsErrorCode;

                                switch (extendedDnsErrorCode)
                                {
                                    case EDnsExtendedDnsErrorCode.DnssecBogus:
                                    case EDnsExtendedDnsErrorCode.SignatureExpired:
                                    case EDnsExtendedDnsErrorCode.SignatureNotYetValid:
                                    case EDnsExtendedDnsErrorCode.RRSIGsMissing: //the RRSIG RR did not pass the necessary validation checks and MUST NOT be used to authenticate this RRset.
                                    case EDnsExtendedDnsErrorCode.NoZoneKeyBitSet:
                                    case EDnsExtendedDnsErrorCode.DNSKEYMissing:
                                        rrsigRecord.SetDnssecStatus(DnssecStatus.Bogus);
                                        break;

                                    case EDnsExtendedDnsErrorCode.UnsupportedDnsKeyAlgorithm:
                                        rrsigRecord.SetDnssecStatus(DnssecStatus.Insecure);
                                        break;

                                    default:
                                        rrsigRecord.SetDnssecStatus(DnssecStatus.Indeterminate);
                                        break;
                                }
                            }
                        }
                    }

                    if (foundValidSignature)
                    {
                        foreach (DnsResourceRecord record in rrset.Value)
                            record.SetDnssecStatus(DnssecStatus.Secure);
                    }
                    else if (isAuthoritySection && (rrsetType == DnsResourceRecordType.NS) && (lastExtendedDnsErrorCode == EDnsExtendedDnsErrorCode.RRSIGsMissing))
                    {
                        //non referrer response with NS records in authority section and missing RRSIG
                        foreach (DnsResourceRecord record in rrset.Value)
                            record.SetDnssecStatus(DnssecStatus.Indeterminate);
                    }
                    else
                    {
                        switch (lastExtendedDnsErrorCode)
                        {
                            case EDnsExtendedDnsErrorCode.DnssecBogus:
                            case EDnsExtendedDnsErrorCode.SignatureExpired:
                            case EDnsExtendedDnsErrorCode.SignatureNotYetValid:
                                //RRSIG with invalid signature
                                foreach (DnsResourceRecord record in rrset.Value)
                                    record.SetDnssecStatus(DnssecStatus.Bogus);

                                response.AddDnsClientExtendedError(lastExtendedDnsErrorCode, ownerName + " " + rrsetType + " " + rrsetClass.ToString());

                                if (!isAdditionalSection)
                                    throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due to invalid signature [" + lastExtendedDnsErrorCode.ToString() + "] for owner name: " + ownerName + "/" + rrsetType, response);

                                break;

                            case EDnsExtendedDnsErrorCode.UnsupportedDnsKeyAlgorithm:
                                //Missing RRSIG with a supported algorithm
                                foreach (DnsResourceRecord record in rrset.Value)
                                    record.SetDnssecStatus(DnssecStatus.Bogus);

                                response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.RRSIGsMissing, "Missing RRSIG with a supported algorithm for " + ownerName + " " + rrsetType + " " + rrsetClass.ToString());

                                if (!isAdditionalSection)
                                    throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due missing RRSIG with a supported algorithm for owner name: " + ownerName + "/" + rrsetType, response);

                                break;

                            case EDnsExtendedDnsErrorCode.RRSIGsMissing:
                                //missing RRSIG for the RRSet

                                if (rrsetType == DnsResourceRecordType.CNAME)
                                {
                                    //check if CNAME was synthesized from DNAME
                                    bool foundDNAME = false;
                                    DnsResourceRecord cnameRecord = rrset.Value[0];

                                    foreach (DnsResourceRecord dnameRecord in records)
                                    {
                                        if (dnameRecord.Type != DnsResourceRecordType.DNAME)
                                            continue;

                                        if (cnameRecord.Name.EndsWith("." + dnameRecord.Name, StringComparison.OrdinalIgnoreCase))
                                        {
                                            string synthesizedCNAME = (dnameRecord.RDATA as DnsDNAMERecordData).Substitute(cnameRecord.Name, dnameRecord.Name);
                                            string CNAME = (cnameRecord.RDATA as DnsCNAMERecordData).Domain;

                                            if (synthesizedCNAME.Equals(CNAME, StringComparison.OrdinalIgnoreCase))
                                            {
                                                //found CNAME synthesized from DNAME
                                                cnameRecord.SetDnssecStatus(DnssecStatus.Secure);

                                                foundDNAME = true;
                                                break;
                                            }
                                        }
                                    }

                                    if (foundDNAME)
                                        continue; //continue to next rrset
                                }

                                if (isAdditionalSection)
                                {
                                    foreach (DnsResourceRecord record in rrset.Value)
                                        record.SetDnssecStatus(DnssecStatus.Indeterminate);
                                }
                                else
                                {
                                    foreach (DnsResourceRecord record in rrset.Value)
                                        record.SetDnssecStatus(DnssecStatus.Bogus);

                                    response.AddDnsClientExtendedError(lastExtendedDnsErrorCode, ownerName + "/" + rrsetType);

                                    throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due to missing RRSIG for owner name: " + ownerName + "/" + rrsetType, response);
                                }

                                break;

                            default:
                                foreach (DnsResourceRecord record in rrset.Value)
                                    record.SetDnssecStatus(DnssecStatus.Bogus);

                                response.AddDnsClientExtendedError(lastExtendedDnsErrorCode, ownerName + "/" + rrsetType);

                                if (!isAdditionalSection)
                                    throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due to reason: " + lastExtendedDnsErrorCode.ToString() + ", for owner name: " + ownerName + "/" + rrsetType, response);

                                break;
                        }
                    }
                }
            }
        }

        private static async Task<IReadOnlyList<DnsResourceRecord>> FindDnsKeyForAsync(string ownerName, DnsClass @class, IReadOnlyList<DnsResourceRecord> currentDnsKeyRecords, DnsClient dnsClient, IDnsCache cache, ushort udpPayloadSize, DnsDatagram originalResponse, CancellationToken cancellationToken)
        {
            string dnsKeyOwnerName = currentDnsKeyRecords[0].Name;

            if (ownerName.Equals(dnsKeyOwnerName, StringComparison.OrdinalIgnoreCase) || ((dnsKeyOwnerName.Length > 0) && !ownerName.EndsWith("." + dnsKeyOwnerName, StringComparison.OrdinalIgnoreCase)))
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
                IReadOnlyList<DnsResourceRecord> nextDSRecords = await GetDSForAsync(nextDomain, @class, currentDnsKeyRecords, dnsClient, cache, udpPayloadSize, originalResponse, cancellationToken);

                if (nextDSRecords is null)
                {
                    //zone is validated to be unsigned
                    return null;
                }
                else if (nextDSRecords.Count > 0)
                {
                    //get next DNSKEY
                    currentDnsKeyRecords = await GetDnsKeyForAsync(nextDSRecords, dnsClient, cache, udpPayloadSize, cancellationToken);
                }
                else
                {
                    //NO DATA; must be a subdomain so next DNSKEY remains same
                }
            }

            return currentDnsKeyRecords;
        }

        private static async Task<IReadOnlyList<DnsResourceRecord>> GetDnsKeyForAsync(IReadOnlyList<DnsResourceRecord> lastDSRecords, DnsClient dnsClient, IDnsCache cache, ushort udpPayloadSize, CancellationToken cancellationToken)
        {
            DnsResourceRecord lastDSRecord = lastDSRecords[0];
            DnsQuestionRecord dnsKeyQuestion = new DnsQuestionRecord(lastDSRecord.Name, DnsResourceRecordType.DNSKEY, lastDSRecord.Class);

            //query cache without CD & DO flags
            DnsDatagram cacheDnsKeyRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [dnsKeyQuestion], null, null, null, udpPayloadSize, EDnsHeaderFlags.None);
            DnsDatagram cacheDnsKeyResponse = QueryCache(cache, cacheDnsKeyRequest);
            if (cacheDnsKeyResponse is not null)
            {
                //cache response is trusted due to no CD & DO flags in request
                if (cacheDnsKeyResponse.Answer.Count > 0)
                    return cacheDnsKeyResponse.Answer; //found in cache

                //bad cache response; continue to resolve DNSKEY
            }

            //query name server
            DnsDatagram dnsKeyRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, true, DnsResponseCode.NoError, [dnsKeyQuestion], null, null, null, udpPayloadSize, EDnsHeaderFlags.DNSSEC_OK);
            DnsDatagram dnsKeyResponse = await dnsClient.InternalResolveAsync(dnsKeyRequest, async delegate (DnsDatagram dnsKeyResponse, CancellationToken cancellationToken1)
            {
                if (dnsKeyResponse.Answer.Count == 0)
                {
                    switch (dnsKeyResponse.RCODE)
                    {
                        case DnsResponseCode.NoError:
                            dnsKeyResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.DNSKEYMissing, (dnsKeyResponse.Metadata is null ? "name server" : dnsKeyResponse.Metadata.NameServer.ToString()) + " returned no DNSKEYs for " + dnsKeyQuestion.Name.ToLowerInvariant());
                            cache.CacheResponse(dnsKeyResponse, true);
                            throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due to missing DNSKEY records for owner name: " + dnsKeyQuestion.Name.ToLowerInvariant(), dnsKeyResponse);

                        default:
                            dnsKeyResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.DNSKEYMissing, (dnsKeyResponse.Metadata is null ? "name server" : dnsKeyResponse.Metadata.NameServer.ToString()) + " returned RCODE=" + dnsKeyResponse.RCODE.ToString() + " for " + dnsKeyQuestion.ToString());
                            cache.CacheResponse(dnsKeyResponse, true);
                            throw new DnsClientResponseDnssecValidationException("Failed to resolve the request '" + dnsKeyResponse.Question[0].ToString() + "'. Received a response with RCODE: " + dnsKeyResponse.RCODE + (dnsKeyResponse.Metadata is null ? "" : " from Name server: " + dnsKeyResponse.Metadata.NameServer.ToString()), dnsKeyResponse);
                    }
                }

                //find valid DNSKEY using DS digest
                if (lastDSRecords.Count > 1)
                {
                    //reverse sort DS by digest type
                    List<DnsResourceRecord> sortedLastDSRecords = new List<DnsResourceRecord>(lastDSRecords);
                    sortedLastDSRecords.Sort(delegate (DnsResourceRecord x, DnsResourceRecord y)
                    {
                        return (x.RDATA as DnsDSRecordData).DigestType.CompareTo((y.RDATA as DnsDSRecordData).DigestType) * -1;
                    });

                    lastDSRecords = sortedLastDSRecords;
                }

                List<DnsResourceRecord> sepDnsKeyRecords = new List<DnsResourceRecord>(2);

                foreach (DnsResourceRecord dnsKeyRecord in dnsKeyResponse.Answer)
                {
                    if (dnsKeyRecord.Type != DnsResourceRecordType.DNSKEY)
                        continue;

                    DnsDNSKEYRecordData dnsKey = dnsKeyRecord.RDATA as DnsDNSKEYRecordData;

                    if (dnsKey.Flags.HasFlag(DnsDnsKeyFlag.Revoke))
                        continue; //cannot use revoked DNSKEY to validate the DNSKEY response

                    int maxKeyTagCollisions = KEY_TRAP_MAX_KEY_TAG_COLLISIONS;

                    foreach (DnsResourceRecord dsRecord in lastDSRecords)
                    {
                        if (!dsRecord.Name.Equals(dnsKeyQuestion.Name, StringComparison.OrdinalIgnoreCase))
                            continue;

                        DnsDSRecordData ds = dsRecord.RDATA as DnsDSRecordData;

                        if ((ds.KeyTag == dnsKey.ComputedKeyTag) && (ds.Algorithm == dnsKey.Algorithm) && DnsDSRecordData.IsDigestTypeSupported(ds.DigestType))
                        {
                            //found DS
                            if (dnsKey.IsDnsKeyValid(dnsKeyRecord.Name, ds))
                            {
                                //found match
                                sepDnsKeyRecords.Add(dnsKeyRecord);
                                break;
                            }

                            maxKeyTagCollisions--;

                            if (maxKeyTagCollisions < 1)
                                break; //too many key tag collisions
                        }
                    }
                }

                if (sepDnsKeyRecords.Count == 0)
                {
                    dnsKeyResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.DNSKEYMissing, "No SEP matching the DS found for " + dnsKeyQuestion.Name.ToLowerInvariant());
                    cache.CacheResponse(dnsKeyResponse, true);
                    throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due to unable to find a SEP DNSKEY matching the DS for owner name: " + dnsKeyQuestion.Name.ToLowerInvariant(), dnsKeyResponse);
                }

                //validate signature for DNSKEY response
                try
                {
                    await DnssecValidateSignatureAsync(dnsKeyResponse, sepDnsKeyRecords, null);
                }
                catch (DnsClientResponseDnssecValidationException ex)
                {
                    cache.CacheResponse(ex.Response, true);
                    throw;
                }

                return dnsKeyResponse;
            }, false, cancellationToken);

            cache.CacheResponse(dnsKeyResponse);

            return dnsKeyResponse.Answer;
        }

        private static async Task<IReadOnlyList<DnsResourceRecord>> GetDSForAsync(string ownerName, DnsClass @class, IReadOnlyList<DnsResourceRecord> currentDnsKeyRecords, DnsClient dnsClient, IDnsCache cache, ushort udpPayloadSize, DnsDatagram originalResponse, CancellationToken cancellationToken)
        {
            string dnsKeyOwnerName = currentDnsKeyRecords[0].Name;

            if (ownerName.Equals(dnsKeyOwnerName, StringComparison.OrdinalIgnoreCase) || ((dnsKeyOwnerName.Length > 0) && !ownerName.EndsWith("." + dnsKeyOwnerName, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException();

            DnsQuestionRecord dsQuestion = new DnsQuestionRecord(ownerName, DnsResourceRecordType.DS, @class);

            //query cache with no CD flag to not get response from "bad cache" and DO flag to get DNSSEC records for correctly reading DS from response
            DnsDatagram cacheDSRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [dsQuestion], null, null, null, udpPayloadSize, EDnsHeaderFlags.DNSSEC_OK);
            DnsDatagram cacheDSResponse = QueryCache(cache, cacheDSRequest);
            if (cacheDSResponse is not null)
            {
                Tuple<bool, IReadOnlyList<DnsResourceRecord>> tupleCacheDSRecords = await TryGetDSFromResponseAsync(cacheDSResponse, ownerName);
                if (tupleCacheDSRecords.Item1)
                {
                    IReadOnlyList<DnsResourceRecord> cacheDSRecords = tupleCacheDSRecords.Item2;

                    if (cacheDSRecords is null)
                        originalResponse.AddDnsClientExtendedErrorFrom(cacheDSResponse);

                    return cacheDSRecords;
                }

                //bad cache response; continue to resolve DS
            }

            //query dns server
            DnsDatagram dsRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, true, DnsResponseCode.NoError, [dsQuestion], null, null, null, udpPayloadSize, EDnsHeaderFlags.DNSSEC_OK);
            IReadOnlyList<DnsResourceRecord> dsRecords = []; //default NO DATA response so that DNSKEY remains same

            try
            {
                _ = await dnsClient.InternalResolveAsync(dsRequest, async delegate (DnsDatagram dsResponse, CancellationToken cancellationToken1)
                {
                    //validate signature for DS response
                    await DnssecValidateSignatureAsync(dsResponse, currentDnsKeyRecords, null);

                    Tuple<bool, IReadOnlyList<DnsResourceRecord>> tupleDsRecords = await TryGetDSFromResponseAsync(dsResponse, ownerName);
                    if (tupleDsRecords.Item1)
                    {
                        dsRecords = tupleDsRecords.Item2;

                        if (dsRecords is null)
                            originalResponse.AddDnsClientExtendedErrorFrom(dsResponse);

                        cache.CacheResponse(dsResponse);
                        return dsResponse;
                    }

                    switch (dsResponse.RCODE)
                    {
                        case DnsResponseCode.NoError:
                        case DnsResponseCode.NxDomain:
                            dsResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.DnssecIndeterminate, (dsResponse.Metadata is null ? "name server" : dsResponse.Metadata.NameServer.ToString()) + " returned no DS for " + ownerName);
                            cache.CacheResponse(dsResponse, true);
                            throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due to missing DS records for owner name: " + ownerName, dsResponse);

                        default:
                            dsResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.DnssecIndeterminate, (dsResponse.Metadata is null ? "name server" : dsResponse.Metadata.NameServer.ToString()) + " returned RCODE=" + dsResponse.RCODE.ToString() + " for " + dsQuestion.ToString());
                            cache.CacheResponse(dsResponse, true);
                            throw new DnsClientResponseDnssecValidationException("Failed to resolve the request '" + dsResponse.Question[0].ToString() + "'. Received a response with RCODE: " + dsResponse.RCODE + (dsResponse.Metadata is null ? "" : " from Name server: " + dsResponse.Metadata.NameServer.ToString()), dsResponse);
                    }
                }, false, cancellationToken);
            }
            catch (DnsClientResponseDnssecValidationException ex)
            {
                //check if owner name is a CNAME
                foreach (DnsResourceRecord record in ex.Response.Answer)
                {
                    if ((record.Type == DnsResourceRecordType.CNAME) && record.Name.Equals(ownerName, StringComparison.OrdinalIgnoreCase))
                    {
                        if (record.DnssecStatus == DnssecStatus.Secure)
                            return []; //NO DATA case since a secure CNAME was found instead of DS

                        //CNAME found but is not secure
                        break;
                    }
                }

                cache.CacheResponse(ex.Response, true);
                throw;
            }

            return dsRecords;
        }

        private static async Task<Tuple<bool, IReadOnlyList<DnsResourceRecord>>> TryGetDSFromResponseAsync(DnsDatagram response, string ownerName)
        {
            IReadOnlyList<DnsResourceRecord> dsRecords;

            switch (response.RCODE)
            {
                case DnsResponseCode.NxDomain:
                    //NX Domain was already validated thus DS does not exists
                    dsRecords = null;
                    return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);

                case DnsResponseCode.NoError:
                    if ((response.Question[0].Type == DnsResourceRecordType.DS) && response.Question[0].Name.Equals(ownerName, StringComparison.OrdinalIgnoreCase))
                    {
                        //DS query response
                        if (response.Answer.Count > 0)
                        {
                            dsRecords = GetFilterdDSRecords(response.Answer, ownerName);
                            if (dsRecords.Count > 0)
                            {
                                //If the validator does not support any of the algorithms listed in an
                                //authenticated DS RRset, then the resolver has no supported
                                //authentication path leading from the parent to the child.  The
                                //resolver should treat this case as it would the case of an
                                //authenticated NSEC RRset proving that no DS RRset exists, as
                                //described above.

                                if (!DnsDSRecordData.IsAnyDigestTypeSupported(dsRecords))
                                {
                                    response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.UnsupportedDsDigestType, ownerName);
                                    dsRecords = null;
                                    return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                                }

                                if (!DnsDSRecordData.IsAnyDnssecAlgorithmSupported(dsRecords))
                                {
                                    response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.UnsupportedDnsKeyAlgorithm, ownerName);
                                    dsRecords = null;
                                    return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                                }

                                foreach (DnsResourceRecord dsRecord in dsRecords)
                                {
                                    if (dsRecord.DnssecStatus == DnssecStatus.Insecure)
                                    {
                                        //found DS marked as insecure so the zone is considered as insecure
                                        dsRecords = null;
                                        return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                                    }
                                }

                                return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                            }

                            //check if owner name is a CNAME
                            foreach (DnsResourceRecord record in response.Answer)
                            {
                                if ((record.Type == DnsResourceRecordType.CNAME) && record.Name.Equals(ownerName, StringComparison.OrdinalIgnoreCase))
                                {
                                    if (record.DnssecStatus == DnssecStatus.Secure)
                                        return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords); //NO DATA case since a secure CNAME was found instead of DS

                                    //CNAME found but is not secure
                                    break;
                                }
                            }
                        }
                        else if (response.Authority.Count > 0)
                        {
                            //validate if DS records are really missing
                            DnssecProofOfNonExistence proofOfNonExistence = await GetValidatedProofOfNonExistenceAsync(response, ownerName, DnsResourceRecordType.DS);
                            switch (proofOfNonExistence)
                            {
                                case DnssecProofOfNonExistence.InsecureDelegation:
                                case DnssecProofOfNonExistence.OptOut:
                                case DnssecProofOfNonExistence.UnsupportedNSEC3IterationsValue:
                                    //proved that DS is missing and the zone is unsigned
                                    dsRecords = null;
                                    return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);

                                case DnssecProofOfNonExistence.NoData:
                                    //NO DATA; must be a sub domain
                                    dsRecords = Array.Empty<DnsResourceRecord>();
                                    return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                            }

                            //check if response is from dnssec validated unsigned zone
                            DnsResourceRecord firstAuthority = response.FindFirstAuthorityRecord();
                            if ((firstAuthority.Type == DnsResourceRecordType.SOA) && (firstAuthority.DnssecStatus == DnssecStatus.Insecure))
                            {
                                //NO DATA; zone is unsigned
                                dsRecords = null;
                                return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
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
                            return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                        }

                        dsRecords = GetFilterdDSRecords(response.Authority, ownerName);
                        if (dsRecords.Count > 0)
                        {
                            //If the validator does not support any of the algorithms listed in an
                            //authenticated DS RRset, then the resolver has no supported
                            //authentication path leading from the parent to the child.  The
                            //resolver should treat this case as it would the case of an
                            //authenticated NSEC RRset proving that no DS RRset exists, as
                            //described above.

                            if (!DnsDSRecordData.IsAnyDigestTypeSupported(dsRecords))
                            {
                                response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.UnsupportedDsDigestType, ownerName);
                                dsRecords = null;
                                return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                            }

                            if (!DnsDSRecordData.IsAnyDnssecAlgorithmSupported(dsRecords))
                            {
                                response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.UnsupportedDnsKeyAlgorithm, ownerName);
                                dsRecords = null;
                                return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                            }

                            foreach (DnsResourceRecord dsRecord in dsRecords)
                            {
                                if (dsRecord.DnssecStatus == DnssecStatus.Insecure)
                                {
                                    //found DS marked as insecure so the zone is considered as insecure
                                    dsRecords = null;
                                    return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                                }
                            }

                            return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                        }

                        //validate if DS records are really missing
                        DnssecProofOfNonExistence proofOfNonExistence = await GetValidatedProofOfNonExistenceAsync(response, ownerName, DnsResourceRecordType.DS);
                        switch (proofOfNonExistence)
                        {
                            case DnssecProofOfNonExistence.InsecureDelegation:
                            case DnssecProofOfNonExistence.OptOut:
                            case DnssecProofOfNonExistence.UnsupportedNSEC3IterationsValue:
                                //proved that DS is missing and the zone is unsigned
                                dsRecords = null;
                                return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);

                            case DnssecProofOfNonExistence.NoData:
                                //NO DATA; must be a sub domain
                                dsRecords = Array.Empty<DnsResourceRecord>();
                                return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                        }
                    }
                    break;
            }

            //could not find DS records or proof of non-existence
            dsRecords = null;
            return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(false, dsRecords);
        }

        private static List<DnsResourceRecord> GetFilterdDSRecords(IReadOnlyList<DnsResourceRecord> records, string ownerName)
        {
            List<DnsResourceRecord> dsRecords = new List<DnsResourceRecord>(2);

            foreach (DnsResourceRecord record in records)
            {
                if ((record.Type == DnsResourceRecordType.DS) && record.Name.Equals(ownerName, StringComparison.OrdinalIgnoreCase))
                    dsRecords.Add(record);
            }

            return dsRecords;
        }

        private static async Task<DnssecProofOfNonExistence> GetValidatedProofOfNonExistenceAsync(DnsDatagram response, string domain, DnsResourceRecordType type, bool wildcardAnswerValidation = false, string wildcardNextCloserName = null)
        {
            foreach (DnsResourceRecord record in response.Authority)
            {
                if (record.Type == DnsResourceRecordType.NSEC)
                    return DnsNSECRecordData.GetValidatedProofOfNonExistence(response.Authority, domain, type, wildcardAnswerValidation);

                if (record.Type == DnsResourceRecordType.NSEC3)
                {
                    DnssecProofOfNonExistence proof = await DnsNSEC3RecordData.GetValidatedProofOfNonExistenceAsync(response.Authority, domain, type, wildcardAnswerValidation, wildcardNextCloserName);
                    if (proof == DnssecProofOfNonExistence.UnsupportedNSEC3IterationsValue)
                    {
                        foreach (DnsResourceRecord authority in response.Authority)
                        {
                            if ((authority.Type == DnsResourceRecordType.SOA) || (authority.Type == DnsResourceRecordType.NS))
                            {
                                response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.UnsupportedNSEC3IterationsValue, "NSEC3 iterations > " + MAX_NSEC3_ITERATIONS + " not supported for " + authority.Name.ToLowerInvariant() + ".");
                                break;
                            }
                        }
                    }

                    return proof;
                }
            }

            return DnssecProofOfNonExistence.NoProof;
        }

        private static IReadOnlyCollection<string> FindSignersNames(DnsDatagram response)
        {
            if ((response.Answer.Count == 0) && (response.Authority.Count == 0))
            {
                switch (response.RCODE)
                {
                    case DnsResponseCode.NoError:
                    case DnsResponseCode.NxDomain:
                        if (response.Question.Count > 0)
                            return new string[] { response.Question[0].Name }; //return qname to allow validating insecure domains

                        return Array.Empty<string>();

                    default:
                        return Array.Empty<string>();
                }
            }
            else
            {
                List<string> signersNames = new List<string>();

                FindSignersNames(response.Answer, signersNames, false);
                FindSignersNames(response.Authority, signersNames, true);

                return signersNames;
            }
        }

        private static void FindSignersNames(IReadOnlyList<DnsResourceRecord> records, List<string> signersNames, bool isAuthoritySection)
        {
            foreach (DnsResourceRecord record in records)
            {
                switch (record.Type)
                {
                    case DnsResourceRecordType.RRSIG:
                    case DnsResourceRecordType.OPT:
                        continue;
                }

                if (record.Name.Length == 0)
                    continue; //skip root zone

                bool isRecordCovered = false;

                foreach (DnsResourceRecord rrsigRecord in records)
                {
                    if (rrsigRecord.Type != DnsResourceRecordType.RRSIG)
                        continue;

                    if (rrsigRecord.Name.Equals(record.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        DnsRRSIGRecordData rrsig = rrsigRecord.RDATA as DnsRRSIGRecordData;

                        if (rrsig.TypeCovered == record.Type)
                        {
                            string signersName = rrsig.SignersName;

                            if (!signersNames.Contains(signersName))
                                signersNames.Add(signersName);

                            isRecordCovered = true;
                            break;
                        }
                    }
                    else if ((record.Type == DnsResourceRecordType.CNAME) && record.Name.EndsWith("." + rrsigRecord.Name, StringComparison.OrdinalIgnoreCase) && ((rrsigRecord.RDATA as DnsRRSIGRecordData).TypeCovered == DnsResourceRecordType.DNAME))
                    {
                        isRecordCovered = true;
                        break;
                    }
                }

                if (!isRecordCovered)
                {
                    if (isAuthoritySection && (record.Type == DnsResourceRecordType.NS))
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

        private static DnsDatagram SanitizeResponseAnswerForQName(DnsDatagram response)
        {
            bool fixAnswer = false;

            foreach (DnsQuestionRecord question in response.Question)
            {
                switch (question.Type)
                {
                    case DnsResourceRecordType.AXFR:
                    case DnsResourceRecordType.IXFR:
                        continue;
                }

                string qName = question.Name;

                foreach (DnsResourceRecord answer in response.Answer)
                {
                    if (qName.Equals(answer.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        switch (answer.Type)
                        {
                            case DnsResourceRecordType.CNAME:
                                qName = (answer.RDATA as DnsCNAMERecordData).Domain;
                                continue;

                            case DnsResourceRecordType.RRSIG:
                                continue;

                            default:
                                if ((question.Type == answer.Type) || (question.Type == DnsResourceRecordType.ANY))
                                    continue;

                                break;
                        }
                    }
                    else
                    {
                        switch (answer.Type)
                        {
                            case DnsResourceRecordType.RRSIG:
                                continue;

                            case DnsResourceRecordType.DNAME:
                                if (qName.EndsWith("." + answer.Name, StringComparison.OrdinalIgnoreCase))
                                    continue; //found DNAME, continue next

                                break;
                        }
                    }

                    fixAnswer = true;
                    break;
                }

                if (fixAnswer)
                    break;
            }

            if (!fixAnswer)
                return response;

            //fix answer
            List<DnsResourceRecord> newAnswers = new List<DnsResourceRecord>(response.Answer.Count);

            foreach (DnsQuestionRecord question in response.Question)
            {
                string qName = question.Name;

                do
                {
                    string nextQName = null;

                    foreach (DnsResourceRecord answer in response.Answer)
                    {
                        if (qName.Equals(answer.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (answer.Type)
                            {
                                case DnsResourceRecordType.CNAME:
                                    newAnswers.Add(answer);

                                    nextQName = (answer.RDATA as DnsCNAMERecordData).Domain;
                                    break;

                                case DnsResourceRecordType.RRSIG:
                                    newAnswers.Add(answer);
                                    break;

                                default:
                                    if ((question.Type == answer.Type) || (question.Type == DnsResourceRecordType.ANY))
                                        newAnswers.Add(answer);

                                    break;
                            }
                        }
                        else if ((answer.Type == DnsResourceRecordType.DNAME) && qName.EndsWith("." + answer.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            //found DNAME
                            newAnswers.Add(answer);
                        }
                    }

                    qName = nextQName;
                }
                while (qName is not null);
            }

            return response.Clone(newAnswers);
        }

        private static DnsDatagram SanitizeResponseAnswerForZoneCut(DnsDatagram response, string zoneCut)
        {
            if (response.Question.Count < 1)
                return response;

            string qName = response.Question[0].Name;
            string zoneCutEnd = zoneCut.Length > 0 ? "." + zoneCut : zoneCut;

            for (int i = 0; i < response.Answer.Count; i++)
            {
                DnsResourceRecord answer = response.Answer[i];

                if ((answer.Type == DnsResourceRecordType.DNAME) && qName.EndsWith("." + answer.Name, StringComparison.OrdinalIgnoreCase))
                    continue; //found DNAME, continue next

                if (answer.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase) || answer.Name.EndsWith(zoneCutEnd, StringComparison.OrdinalIgnoreCase))
                {
                    if (answer.Name.Equals(qName, StringComparison.OrdinalIgnoreCase))
                    {
                        switch (answer.Type)
                        {
                            case DnsResourceRecordType.CNAME:
                                if (i < response.Answer.Count - 1)
                                    qName = (answer.RDATA as DnsCNAMERecordData).Domain;

                                break;
                        }

                        continue;
                    }

                    switch (answer.Type)
                    {
                        case DnsResourceRecordType.RRSIG:
                            continue;

                        case DnsResourceRecordType.DNAME:
                            if (qName.EndsWith("." + answer.Name, StringComparison.OrdinalIgnoreCase))
                                continue; //found DNAME, continue next

                            break;
                    }
                }

                //name mismatch or not in zone cut
                //truncate answer upto previous RR

                List<DnsResourceRecord> newAnswers = new List<DnsResourceRecord>(i);

                for (int j = 0; j < i; j++)
                    newAnswers.Add(response.Answer[j]);

                return response.Clone(newAnswers);
            }

            return response;
        }

        private static DnsDatagram SanitizeResponseAuthorityForZoneCut(DnsDatagram response, string zoneCut)
        {
            if (zoneCut.Length == 0)
            {
                //zone cut is root, do nothing
                return response;
            }

            //remove records from authority section that are not in the zone cut

            if (response.Authority.Count > 0)
            {
                bool authorityNotInZoneCut = false;
                string zoneCutEnd = "." + zoneCut;

                foreach (DnsResourceRecord authority in response.Authority)
                {
                    if (!authority.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase) && !authority.Name.EndsWith(zoneCutEnd, StringComparison.OrdinalIgnoreCase))
                    {
                        authorityNotInZoneCut = true;
                        break;
                    }
                }

                if (authorityNotInZoneCut)
                {
                    List<DnsResourceRecord> newAuthority = new List<DnsResourceRecord>();

                    foreach (DnsResourceRecord authority in response.Authority)
                    {
                        if (!authority.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase) && !authority.Name.EndsWith(zoneCutEnd, StringComparison.OrdinalIgnoreCase))
                            continue;

                        newAuthority.Add(authority);
                    }

                    return response.Clone(null, newAuthority);
                }
            }

            return response;
        }

        private static DnsDatagram SanitizeResponseAdditionalForZoneCut(DnsDatagram response, string zoneCut)
        {
            if (zoneCut.Length == 0)
            {
                //zone cut is root, do nothing
                return response;
            }

            //remove records from additional section that are not in the zone cut

            if (response.Additional.Count > 0)
            {
                bool additionalNotInZoneCut = false;
                string zoneCutEnd = "." + zoneCut;

                foreach (DnsResourceRecord additional in response.Additional)
                {
                    if (additional.Type == DnsResourceRecordType.OPT)
                        continue;

                    if (!additional.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase) && !additional.Name.EndsWith(zoneCutEnd, StringComparison.OrdinalIgnoreCase))
                    {
                        additionalNotInZoneCut = true;
                        break;
                    }
                }

                if (additionalNotInZoneCut)
                {
                    List<DnsResourceRecord> newAdditional = new List<DnsResourceRecord>();

                    foreach (DnsResourceRecord additional in response.Additional)
                    {
                        if (additional.Type == DnsResourceRecordType.OPT)
                        {
                            newAdditional.Add(additional);
                            continue;
                        }

                        if (!additional.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase) && !additional.Name.EndsWith(zoneCutEnd, StringComparison.OrdinalIgnoreCase))
                            continue;

                        newAdditional.Add(additional);
                    }

                    return response.Clone(null, null, newAdditional);
                }
            }

            return response;
        }

        private static DnsDatagram SanitizeResponseAfterDnssecValidation(DnsDatagram response)
        {
            List<DnsResourceRecord> newAnswer = null;
            List<DnsResourceRecord> newAuthority = null;

            foreach (DnsResourceRecord record in response.Answer)
            {
                if (record.DnssecStatus != DnssecStatus.Indeterminate)
                    continue;

                //remove indeterminate records from answer
                newAnswer = new List<DnsResourceRecord>(response.Answer.Count);

                foreach (DnsResourceRecord record2 in response.Answer)
                {
                    if (record2.DnssecStatus == DnssecStatus.Indeterminate)
                        continue;

                    newAnswer.Add(record2);
                }

                break;
            }

            foreach (DnsResourceRecord record in response.Authority)
            {
                if (record.DnssecStatus != DnssecStatus.Indeterminate)
                    continue;

                if (record.Type == DnsResourceRecordType.NS)
                    continue;

                //remove indeterminate records from authority except for NS
                newAuthority = new List<DnsResourceRecord>(response.Authority.Count);

                foreach (DnsResourceRecord record2 in response.Authority)
                {
                    if (record2.DnssecStatus == DnssecStatus.Indeterminate)
                    {
                        if (record2.Type != DnsResourceRecordType.NS)
                            continue;
                    }

                    newAuthority.Add(record2);
                }

                break;
            }

            if ((newAnswer is null) && (newAuthority is null))
                return response;

            return response.Clone(newAnswer, newAuthority);
        }

        private static DnsDatagram GetMinimalResponseWithoutNSAndGlue(DnsDatagram response)
        {
            bool foundNS = false;

            foreach (DnsResourceRecord record in response.Authority)
            {
                if (record.Type == DnsResourceRecordType.NS)
                {
                    foundNS = true;
                    break;
                }
            }

            IReadOnlyList<DnsResourceRecord> authority;

            if (foundNS)
            {
                //remove NS from authority
                List<DnsResourceRecord> newAuthority = new List<DnsResourceRecord>();

                foreach (DnsResourceRecord record in response.Authority)
                {
                    switch (record.Type)
                    {
                        case DnsResourceRecordType.NS:
                        case DnsResourceRecordType.DS:
                            break;

                        case DnsResourceRecordType.RRSIG:
                            switch ((record.RDATA as DnsRRSIGRecordData).TypeCovered)
                            {
                                case DnsResourceRecordType.NS:
                                case DnsResourceRecordType.DS:
                                    break;

                                default:
                                    newAuthority.Add(record);
                                    break;
                            }
                            break;

                        default:
                            newAuthority.Add(record);
                            break;
                    }
                }

                authority = newAuthority;
            }
            else
            {
                authority = response.Authority;
            }

            bool foundIndeterminate = false;

            if (!foundNS)
            {
                foreach (DnsResourceRecord additionalRecord in response.Additional)
                {
                    switch (additionalRecord.DnssecStatus)
                    {
                        case DnssecStatus.Disabled:
                        case DnssecStatus.Secure:
                        case DnssecStatus.Insecure:
                            continue;
                    }

                    foundIndeterminate = true;
                    break;
                }
            }

            //remove glue and Indeterminate records from additional
            if (foundNS || foundIndeterminate)
            {
                IReadOnlyList<DnsResourceRecord> additional;

                if ((response.Additional.Count == 0) || ((response.Additional.Count == 1) && (response.Additional[0].Type == DnsResourceRecordType.OPT)))
                {
                    additional = response.Additional;
                }
                else
                {
                    List<DnsResourceRecord> newAdditional = new List<DnsResourceRecord>();

                    foreach (DnsResourceRecord additionalRecord in response.Additional)
                    {
                        switch (additionalRecord.DnssecStatus)
                        {
                            case DnssecStatus.Disabled:
                            case DnssecStatus.Secure:
                            case DnssecStatus.Insecure:
                                break;

                            default:
                                if (additionalRecord.Type == DnsResourceRecordType.OPT)
                                    break;

                                continue; //skip record
                        }

                        switch (additionalRecord.Type)
                        {
                            case DnsResourceRecordType.A:
                            case DnsResourceRecordType.AAAA:
                            case DnsResourceRecordType.RRSIG:
                                if (foundNS)
                                {
                                    bool foundGlue = false;

                                    foreach (DnsResourceRecord nsRecord in response.Authority)
                                    {
                                        if ((nsRecord.Type == DnsResourceRecordType.NS) && additionalRecord.Name.Equals((nsRecord.RDATA as DnsNSRecordData).NameServer, StringComparison.OrdinalIgnoreCase))
                                        {
                                            foundGlue = true;
                                            break;
                                        }
                                    }

                                    if (!foundGlue)
                                        newAdditional.Add(additionalRecord);
                                }
                                else
                                {
                                    newAdditional.Add(additionalRecord);
                                }
                                break;

                            default:
                                newAdditional.Add(additionalRecord);
                                break;
                        }
                    }

                    additional = newAdditional;
                }

                return response.Clone(null, authority, additional);
            }

            return response;
        }

        private static async Task RevalidateNameServersFromChildSideAsync(string zoneCut, IReadOnlyList<DnsResourceRecord> lastDSRecords, IReadOnlyList<NameServerAddress> parentSideNameServers, IDnsCache cache, NetProxy proxy, bool preferIPv6, ushort udpPayloadSize, bool randomizeName, bool qnameMinimization, bool dnssecValidation, int retries, int timeout, int concurrency, int maxStackCount)
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

            DnsClient dnsClient = new DnsClient(nameServers);
            dnsClient._proxy = proxy;
            dnsClient._preferIPv6 = preferIPv6;
            dnsClient._randomizeName = randomizeName;
            dnsClient._retries = retries;
            dnsClient._timeout = timeout;
            dnsClient._concurrency = 1;

            DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, dnssecValidation, DnsResponseCode.NoError, [new DnsQuestionRecord(zoneCut, DnsResourceRecordType.NS, DnsClass.IN)], null, null, null, udpPayloadSize, dnssecValidation ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None);
            DnsDatagram response;

            try
            {
                response = await dnsClient.InternalResolveAsync(request, async delegate (DnsDatagram response, CancellationToken cancellationToken1)
                {
                    //sanitize response
                    response = SanitizeResponseAnswerForQName(response);
                    response = SanitizeResponseAnswerForZoneCut(response, zoneCut); //sanitize answer section
                    response = SanitizeResponseAuthorityForZoneCut(response, zoneCut); //sanitize authority section
                    response = SanitizeResponseAdditionalForZoneCut(response, zoneCut); //sanitize additional section

                    if (dnssecValidation)
                    {
                        if (lastDSRecords is null)
                        {
                            response.SetDnssecStatusForAllRecords(DnssecStatus.Insecure);
                        }
                        else
                        {
                            await DnssecValidateResponseAsync(response, lastDSRecords, dnsClient, cache, udpPayloadSize, cancellationToken1);

                            //sanitize response after DNSSEC validation
                            response = SanitizeResponseAfterDnssecValidation(response);
                        }
                    }
                    else
                    {
                        response.SetDnssecStatusForAllRecords(DnssecStatus.Disabled);
                    }

                    return response;
                });
            }
            catch
            {
                //ignore failures in resolution
                return;
            }

            //cache authoritative NS records from response
            if (response.Answer.Count > 0)
            {
                //resolve all name server addresses
                List<NameServerAddress> revalidatedNameServers = NameServerAddress.GetNameServersFromResponse(response, preferIPv6, true);
                List<Task> tasks = new List<Task>(revalidatedNameServers.Count);

                foreach (NameServerAddress revalidatedNameServer in revalidatedNameServers)
                {
                    if (revalidatedNameServer.IPEndPoint is null)
                    {
                        if (preferIPv6)
                            tasks.Add(RecursiveResolveAsync(new DnsQuestionRecord(revalidatedNameServer.DomainEndPoint.Address, DnsResourceRecordType.AAAA, DnsClass.IN), cache, proxy, preferIPv6, udpPayloadSize, randomizeName, qnameMinimization, false, dnssecValidation, null, retries, timeout, concurrency, maxStackCount, false, false));

                        tasks.Add(RecursiveResolveAsync(new DnsQuestionRecord(revalidatedNameServer.DomainEndPoint.Address, DnsResourceRecordType.A, DnsClass.IN), cache, proxy, preferIPv6, udpPayloadSize, randomizeName, qnameMinimization, false, dnssecValidation, null, retries, timeout, concurrency, maxStackCount, false, false));
                    }
                }

                await Task.WhenAll(tasks);

                //cache revalidated NS after resolving their addresses to avoid overwriting existing NS with glue
                cache.CacheResponse(response);
            }
        }

        private static Task<DnsDatagram> RevalidateNameServersFromParentSideAsync(string zoneCut, IDnsCache cache, NetProxy proxy, bool preferIPv6, ushort udpPayloadSize, bool randomizeName, bool qnameMinimization, bool dnssecValidation, int retries, int timeout, int concurrency, int maxStackCount)
        {
            DnsQuestionRecord question = new DnsQuestionRecord(zoneCut, DnsResourceRecordType.NS, DnsClass.IN);
            ResolverNsRevalidationDnsCache revalidationDnsCache = new ResolverNsRevalidationDnsCache(cache, question);

            return RecursiveResolveAsync(question, revalidationDnsCache, proxy, preferIPv6, udpPayloadSize, randomizeName, qnameMinimization, true, dnssecValidation, null, retries, timeout, concurrency, maxStackCount);
        }

        private static async Task<DnsDatagram> ResolveQueryAsync(DnsQuestionRecord question, Func<DnsQuestionRecord, Task<DnsDatagram>> resolveAsync)
        {
            DnsDatagram response = await resolveAsync(question);
            if (response is null)
                return new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, DnsResponseCode.Refused, new DnsQuestionRecord[] { question });

            if (response.Answer.Count > 0)
            {
                DnsResourceRecord lastRR = response.GetLastAnswerRecord();

                if ((lastRR.Type != question.Type) && (lastRR.Type == DnsResourceRecordType.CNAME) && (question.Type != DnsResourceRecordType.ANY))
                {
                    List<DnsResourceRecord> newAnswer = new List<DnsResourceRecord>(response.Answer.Count + 4);
                    newAnswer.AddRange(response.Answer);

                    //copying NSEC/NSEC3 for for wildcard answers
                    List<DnsResourceRecord> newAuthority = new List<DnsResourceRecord>(2);

                    foreach (DnsResourceRecord record in response.Authority)
                    {
                        switch (record.Type)
                        {
                            case DnsResourceRecordType.NSEC:
                            case DnsResourceRecordType.NSEC3:
                                newAuthority.Add(record);
                                break;

                            case DnsResourceRecordType.RRSIG:
                                switch ((record.RDATA as DnsRRSIGRecordData).TypeCovered)
                                {
                                    case DnsResourceRecordType.NSEC:
                                    case DnsResourceRecordType.NSEC3:
                                        newAuthority.Add(record);
                                        break;
                                }
                                break;
                        }
                    }

                    DnsDatagram lastResponse = null;
                    int queryCount = 0;

                    do
                    {
                        string cnameDomain = (lastRR.RDATA as DnsCNAMERecordData).Domain;
                        if (lastRR.Name.Equals(cnameDomain, StringComparison.OrdinalIgnoreCase))
                            break; //loop detected

                        lastResponse = await resolveAsync(new DnsQuestionRecord(cnameDomain, question.Type, question.Class));
                        if (lastResponse is null)
                        {
                            lastResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { question });
                            break;
                        }

                        if (lastResponse.Answer.Count == 0)
                            break;

                        lastRR = lastResponse.GetLastAnswerRecord();
                        if (lastRR.Type != DnsResourceRecordType.CNAME)
                        {
                            newAnswer.AddRange(lastResponse.Answer);
                            break; //cname was resolved
                        }

                        bool foundRepeat = false;

                        foreach (DnsResourceRecord answerRecord in newAnswer)
                        {
                            if (answerRecord.Type != DnsResourceRecordType.CNAME)
                                continue;

                            if (answerRecord.RDATA.Equals(lastRR.RDATA))
                            {
                                foundRepeat = true;
                                break;
                            }
                        }

                        if (foundRepeat)
                            break; //loop detected

                        newAnswer.AddRange(lastResponse.Answer);
                    }
                    while (++queryCount < MAX_CNAME_HOPS);

                    if (lastResponse is null)
                        return response;

                    IReadOnlyList<DnsResourceRecord> authority;

                    if (newAuthority.Count == 0)
                    {
                        authority = lastResponse.Authority;
                    }
                    else
                    {
                        newAuthority.AddRange(lastResponse.Authority);
                        authority = newAuthority;
                    }

                    DnsDatagram compositeResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, lastResponse.RCODE, new DnsQuestionRecord[] { question }, newAnswer, authority, lastResponse.Additional);

                    if (lastResponse.Metadata is not null)
                        compositeResponse.SetMetadata(lastResponse.Metadata.NameServer, lastResponse.Metadata.RoundTripTime);

                    return compositeResponse;
                }
            }

            return response;
        }

        protected virtual async Task<DnsDatagram> InternalResolveAsync(DnsDatagram request, Func<DnsDatagram, CancellationToken, Task<DnsDatagram>> getValidatedResponseAsync = null, bool doNotReorderNameServers = false, CancellationToken cancellationToken = default)
        {
            //get servers
            IReadOnlyList<NameServerAddress> servers;
            int concurrency;

            if (_servers.Count > _concurrency)
            {
                if (doNotReorderNameServers)
                    servers = _servers;
                else
                    servers = GetOrderedNameServersToPreferPerformance(_servers, false, _preferIPv6);

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
                        return servers[nextServerIndex++];

                    return null; //no next server available; stop thread
                }
            }

            async Task<DnsDatagram> DoResolveAsync(CancellationToken cancellationToken)
            {
                DnsDatagram asyncRequest = request.CloneHeadersAndQuestions(); //clone request (headers + question section) so that qname randomization does not pollute request question section and does not cause issue with parallel tasks
                DnsDatagram lastResponse = null;
                Exception lastException = null;

                while (true) //next server loop
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    NameServerAddress server = GetNextServer();
                    if (server is null)
                    {
                        if (lastResponse is not null)
                            return lastResponse;

                        if (lastException is not null)
                            ExceptionDispatchInfo.Throw(lastException);

                        throw new DnsClientNoResponseException("DnsClient failed to resolve the request" + (asyncRequest.Question.Count > 0 ? " '" + asyncRequest.Question[0].ToString() + "'" : "") + ": no response from name servers [" + servers.Join() + "].");
                    }

                    NetProxy proxy = _proxy;

                    if ((proxy is not null) && proxy.IsBypassed(server.EndPoint))
                        proxy = null;

                    if (server.IsIPEndPointStale)
                    {
                        if (nsResolveCache is null)
                            nsResolveCache = _cache is null ? new DnsCache() : _cache;

                        //recursive resolve name server via root servers
                        try
                        {
                            await server.RecursiveResolveIPAddressAsync(nsResolveCache, proxy, _preferIPv6, _udpPayloadSize, _randomizeName, _retries, _timeout, concurrency, cancellationToken: cancellationToken);
                        }
                        catch (OperationCanceledException)
                        {
                            throw;
                        }
                        catch (Exception ex)
                        {
                            lastException = ex;
                            continue; //failed to resolve name server; try next server
                        }
                    }

                    if (proxy is not null)
                    {
                        //upgrade protocol to TCP when UDP is not supported by proxy and server is not bypassed
                        if ((server.Protocol == DnsTransportProtocol.Udp) && !await proxy.IsUdpAvailableAsync(cancellationToken))
                            server = server.ChangeProtocol(DnsTransportProtocol.Tcp);
                    }

                    switch (server.Protocol)
                    {
                        case DnsTransportProtocol.Https:
                        case DnsTransportProtocol.Quic:
                            asyncRequest.SetIdentifier(0);
                            break;

                        default:
                            asyncRequest.SetRandomIdentifier();
                            break;
                    }

                    DateTime startTime = DateTime.UtcNow;

                    bool protocolWasSwitched = false;
                    try
                    {
                        bool retryRequest;
                        do //retry request loop
                        {
                            cancellationToken.ThrowIfCancellationRequested();

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
                            await using (DnsClientConnection connection = DnsClientConnection.GetConnection(server, proxy))
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

                                            if (response.Metadata is not null)
                                                server.Metadata.UpdateSuccess(response.Metadata.RoundTripTime);

                                            retryRequest = true;
                                            protocolWasSwitched = true;
                                        }
                                        else
                                        {
                                            //unexpected truncated response for the transport protocol
                                            server.Metadata.UpdateFailure(_timeout * _retries);
                                            lastException = new DnsClientResponseValidationException("Invalid response was received: truncated response over " + server.Protocol.ToString().ToUpper() + " transport.");
                                        }
                                    }
                                    else
                                    {
                                        if (response.ParsingException is not null)
                                        {
                                            server.Metadata.UpdateFailure(_timeout * _retries);
                                            lastException = response.ParsingException;
                                        }
                                        else
                                        {
                                            EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption();
                                            if (requestECS is not null)
                                            {
                                                EDnsClientSubnetOptionData responseECS = response.GetEDnsClientSubnetOption();
                                                if (responseECS is null)
                                                {
                                                    // If no ECS option is contained in the response, the Intermediate
                                                    // Nameserver SHOULD treat this as being equivalent to having received a
                                                    // SCOPE PREFIX-LENGTH of 0, which is an answer suitable for all client
                                                    // addresses.
                                                    response.SetShadowEDnsClientSubnetOption(requestECS);
                                                }
                                            }

                                            if (getValidatedResponseAsync is not null)
                                                response = await getValidatedResponseAsync(response, cancellationToken);

                                            switch (response.RCODE)
                                            {
                                                case DnsResponseCode.NoError:
                                                case DnsResponseCode.YXDomain:
                                                    if (response.Metadata is not null)
                                                        server.Metadata.UpdateSuccess(response.Metadata.RoundTripTime);

                                                    response.SetIdentifier(request.Identifier);
                                                    return response;

                                                case DnsResponseCode.NxDomain:
                                                    if (response.Metadata is not null)
                                                        server.Metadata.UpdateSuccess(response.Metadata.RoundTripTime);

                                                    response.SetIdentifier(request.Identifier);

                                                    //check for quad9 blocking signal
                                                    if (request.RecursionDesired && !response.RecursionAvailable && !response.AuthoritativeAnswer)
                                                        response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.Blocked, response.Question[0].Name.ToLowerInvariant() + " was blocked by " + (response.Metadata is null ? "upstream server" : response.Metadata.NameServer.ToString()));

                                                    return response;

                                                case DnsResponseCode.FormatError:
                                                    if ((asyncRequest.EDNS is not null) && !asyncRequest.EDNS.Flags.HasFlag(EDnsHeaderFlags.DNSSEC_OK))
                                                    {
                                                        //response does not contain EDNS which indicates that the server does not support EDNS
                                                        //disable EDNS and retry the request
                                                        asyncRequest = asyncRequest.CloneWithoutEDns();

                                                        server.Metadata.UpdateFailure(_timeout);
                                                        retryRequest = true;
                                                        protocolWasSwitched = false;
                                                    }
                                                    else
                                                    {
                                                        server.Metadata.UpdateFailure(_timeout * _retries);
                                                        response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NetworkError, (response.Metadata is null ? "name server" : response.Metadata.NameServer.ToString()) + " returned RCODE=" + response.RCODE.ToString() + " for " + request.Question[0].ToString());

                                                        if (lastResponse is not null)
                                                            response.AddDnsClientExtendedErrorFrom(lastResponse);

                                                        lastResponse = response;
                                                    }
                                                    break;

                                                case DnsResponseCode.Refused:
                                                    EDnsClientSubnetOptionData asyncRequestECS = asyncRequest.GetEDnsClientSubnetOption(true);
                                                    if (asyncRequestECS is not null)
                                                    {
                                                        //If a REFUSED response is received from an Authoritative Nameserver,
                                                        //an ECS-aware resolver MUST retry the query without ECS to distinguish
                                                        //the response from one where the Authoritative Nameserver is not
                                                        //responsible for the name, which is a common convention for the
                                                        //REFUSED status. Similarly, a client of a Recursive Resolver SHOULD
                                                        //retry after receiving a REFUSED response because it is not
                                                        //sufficiently clear whether the REFUSED response was because of the
                                                        //ECS option or some other reason.
                                                        asyncRequest = asyncRequest.CloneWithoutEDnsClientSubnet();

                                                        server.Metadata.UpdateFailure(_timeout);
                                                        retryRequest = true;
                                                        protocolWasSwitched = false;
                                                    }
                                                    else
                                                    {
                                                        server.Metadata.UpdateFailure(_timeout * _retries);
                                                        response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NetworkError, (response.Metadata is null ? "name server" : response.Metadata.NameServer.ToString()) + " returned RCODE=" + response.RCODE.ToString() + " for " + request.Question[0].ToString());

                                                        if (lastResponse is not null)
                                                            response.AddDnsClientExtendedErrorFrom(lastResponse);

                                                        lastResponse = response;
                                                    }
                                                    break;

                                                default:
                                                    server.Metadata.UpdateFailure(_timeout * _retries);
                                                    response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NetworkError, (response.Metadata is null ? "name server" : response.Metadata.NameServer.ToString()) + " returned RCODE=" + response.RCODE.ToString() + " for " + request.Question[0].ToString());

                                                    if (lastResponse is not null)
                                                        response.AddDnsClientExtendedErrorFrom(lastResponse);

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

                                                server.Metadata.UpdateFailure(_timeout);
                                                lastException = ex;
                                                retryRequest = true;
                                                protocolWasSwitched = true;
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
                                catch (DnsClientNoResponseException ex)
                                {
                                    //request timed out
                                    if ((server.Protocol == DnsTransportProtocol.Udp) && (asyncRequest.EDNS is not null) && !asyncRequest.EDNS.Flags.HasFlag(EDnsHeaderFlags.DNSSEC_OK))
                                    {
                                        //EDNS udp request timed out; disable EDNS and retry the request
                                        asyncRequest = asyncRequest.CloneWithoutEDns();

                                        server.Metadata.UpdateFailure(_timeout);
                                        lastException = ex;
                                        retryRequest = true;
                                        protocolWasSwitched = false;
                                    }
                                    else
                                    {
                                        throw;
                                    }
                                }
                                catch (DnsClientResponseDnssecValidationException)
                                {
                                    throw;
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

                                        server.Metadata.UpdateFailure(_timeout);
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
                    catch (OperationCanceledException)
                    {
                        //task was canceled
                        double timeTaken = (DateTime.UtcNow - startTime).TotalMilliseconds;
                        double average = ((_timeout * _retries) - timeTaken) / 2;
                        server.Metadata.UpdateFailure(average);
                        throw;
                    }
                    catch (DnsClientNoResponseException ex)
                    {
                        //request timed out
                        server.Metadata.UpdateFailure(_timeout * _retries);
                        lastException = ex;
                    }
                    catch (DnsClientResponseValidationException ex)
                    {
                        //response validation failed or DNSSEC validation failed
                        server.Metadata.UpdateFailure(_timeout * _retries);
                        lastException = ex;
                    }
                    catch (Exception ex)
                    {
                        server.Metadata.UpdateFailure(_timeout * _retries);

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
                    await using (CancellationTokenRegistration ctr = cancellationToken.Register(cancellationTokenSource.Cancel))
                    {
                        CancellationToken currentCancellationToken = cancellationTokenSource.Token;
                        List<Task> tasks = new List<Task>(concurrency + 1);

                        //start worker tasks
                        for (int i = 0; i < concurrency; i++)
                            tasks.Add(Task.Factory.StartNew(delegate () { return DoResolveAsync(currentCancellationToken); }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current).Unwrap());

                        //add delay task
                        Task delayTask = Task.Delay(_timeout * _retries * (int)Math.Ceiling((double)servers.Count / concurrency), currentCancellationToken);
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
                                    ExceptionDispatchInfo.Throw(lastException);

                                throw new DnsClientNoResponseException("DnsClient failed to resolve the request" + (request.Question.Count > 0 ? " '" + request.Question[0].ToString() + "'" : "") + ": request timed out for name servers [" + servers.Join() + "].");
                            }

                            if (completedTask.Status == TaskStatus.RanToCompletion)
                            {
                                //resolver task complete
                                DnsDatagram response = await (completedTask as Task<DnsDatagram>); //await to get response

                                switch (response.RCODE)
                                {
                                    case DnsResponseCode.NoError:
                                    case DnsResponseCode.NxDomain:
                                    case DnsResponseCode.YXDomain:
                                        cancellationTokenSource.Cancel(); //to stop delay and other resolver tasks
                                        return response;

                                    default:
                                        //copy EDE from last response
                                        if (lastResponse is not null)
                                            response.AddDnsClientExtendedErrorFrom(lastResponse);

                                        //keep response
                                        lastResponse = response;
                                        break;
                                }
                            }

                            if (tasks.Count == 2)
                            {
                                //this is the last resolver task
                                cancellationTokenSource.Cancel(); //to stop delay task

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
            }
            else
            {
                return await DoResolveAsync(cancellationToken);
            }
        }

        private async Task<DnsDatagram> InternalNoDnssecResolveAsync(DnsDatagram request, CancellationToken cancellationToken = default)
        {
            if ((_conditionalForwardingZoneCut is not null) && (request.Question.Count == 1))
            {
                DnsQuestionRecord question = request.Question[0];

                if (!question.Name.Equals(_conditionalForwardingZoneCut, StringComparison.OrdinalIgnoreCase) && !question.Name.EndsWith("." + _conditionalForwardingZoneCut, StringComparison.OrdinalIgnoreCase))
                    return new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, DnsResponseCode.Refused, new DnsQuestionRecord[] { question });
            }

            DnsDatagram response = await InternalResolveAsync(request, cancellationToken: cancellationToken);

            //sanitize response
            response = SanitizeResponseAnswerForQName(response);

            if (_conditionalForwardingZoneCut is not null)
            {
                response = SanitizeResponseAnswerForZoneCut(response, _conditionalForwardingZoneCut); //keep answers that match qname and within given zone cut
                response = SanitizeResponseAdditionalForZoneCut(response, _conditionalForwardingZoneCut); //keep additional section within zone cut
            }

            //dnssec validation is disabled
            response.SetDnssecStatusForAllRecords(DnssecStatus.Disabled);

            return response;
        }

        private async Task<DnsDatagram> InternalDnssecResolveAsync(DnsQuestionRecord question, CancellationToken cancellationToken = default)
        {
            if ((_conditionalForwardingZoneCut is not null) && !question.Name.Equals(_conditionalForwardingZoneCut, StringComparison.OrdinalIgnoreCase) && !question.Name.EndsWith("." + _conditionalForwardingZoneCut, StringComparison.OrdinalIgnoreCase))
                return new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, DnsResponseCode.Refused, [question]);

            IDnsCache cache;

            if (_cache is null)
                cache = new DnsCache();
            else
                cache = _cache;

            DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, true, DnsResponseCode.NoError, [question], null, null, null, _udpPayloadSize, EDnsHeaderFlags.DNSSEC_OK, _advancedForwardingClientSubnet ? null : EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(_eDnsClientSubnet));
            if (_advancedForwardingClientSubnet)
                request.SetShadowEDnsClientSubnetOption(_eDnsClientSubnet, true);

            bool dnssecRRSigMissingRetry = false; //retry mechanism for RRSIG missing case

            while (true)
            {
                try
                {
                    return await InternalResolveAsync(request, async delegate (DnsDatagram response, CancellationToken cancellationToken1)
                    {
                        //sanitize response
                        response = SanitizeResponseAnswerForQName(response);

                        if (_conditionalForwardingZoneCut is not null)
                        {
                            response = SanitizeResponseAnswerForZoneCut(response, _conditionalForwardingZoneCut); //keep answers that match qname and within given zone cut
                            response = SanitizeResponseAdditionalForZoneCut(response, _conditionalForwardingZoneCut); //keep additional section within zone cut
                        }

                        //dnssec validate response
                        await DnssecValidateResponseAsync(response, GetTrustAnchorsFor(response), this, cache, _udpPayloadSize, cancellationToken1);

                        //sanitize response after DNSSEC validation
                        response = SanitizeResponseAfterDnssecValidation(response);

                        return response;
                    }, false, cancellationToken);
                }
                catch (DnsClientResponseDnssecValidationException ex)
                {
                    if (!dnssecRRSigMissingRetry)
                    {
                        if (ex.Response is not null)
                        {
                            foreach (EDnsExtendedDnsErrorOptionData eDnsError in ex.Response.DnsClientExtendedErrors)
                            {
                                if (eDnsError.InfoCode == EDnsExtendedDnsErrorCode.RRSIGsMissing)
                                {
                                    dnssecRRSigMissingRetry = true;
                                    break;
                                }
                            }

                            if (dnssecRRSigMissingRetry)
                                continue; //retry once
                        }
                    }

                    throw;
                }
            }
        }

        private IReadOnlyList<DnsResourceRecord> GetTrustAnchorsFor(DnsDatagram response)
        {
            if (_trustAnchors is null)
                return ROOT_TRUST_ANCHORS;

            IReadOnlyCollection<string> signersNames = FindSignersNames(response);
            List<DnsResourceRecord> selectedTrustAnchors = new List<DnsResourceRecord>();

            foreach (string signersName in signersNames)
            {
                string domain = signersName;

                while (domain is not null)
                {
                    if (_trustAnchors.TryGetValue(domain, out IReadOnlyList<DnsResourceRecord> dsRecords))
                    {
                        foreach (DnsResourceRecord dsRecord in dsRecords)
                        {
                            if (!selectedTrustAnchors.Contains(dsRecord))
                                selectedTrustAnchors.Add(dsRecord);
                        }
                        break;
                    }

                    domain = DnsCache.GetParentZone(domain);
                }
            }

            if (selectedTrustAnchors.Count > 0)
                return selectedTrustAnchors;

            return ROOT_TRUST_ANCHORS;
        }

        private async Task<DnsDatagram> InternalCachedResolveQueryAsync(DnsQuestionRecord question, CancellationToken cancellationToken)
        {
            return await ResolveQueryAsync(question, async delegate (DnsQuestionRecord q)
            {
                if ((_conditionalForwardingZoneCut is not null) && !q.Name.Equals(_conditionalForwardingZoneCut, StringComparison.OrdinalIgnoreCase) && !q.Name.EndsWith("." + _conditionalForwardingZoneCut, StringComparison.OrdinalIgnoreCase))
                    return null;

                DnsDatagram newRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, _dnssecValidation, DnsResponseCode.NoError, new DnsQuestionRecord[] { q }, null, null, null, _udpPayloadSize, _dnssecValidation ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, _advancedForwardingClientSubnet ? null : EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(_eDnsClientSubnet));
                if (_advancedForwardingClientSubnet)
                    newRequest.SetShadowEDnsClientSubnetOption(_eDnsClientSubnet, true);

                DnsDatagram cacheResponse = QueryCache(_cache, newRequest);
                if (cacheResponse is not null)
                    return cacheResponse;

                try
                {
                    DnsDatagram newResponse;

                    if (_dnssecValidation)
                        newResponse = await InternalDnssecResolveAsync(q, cancellationToken);
                    else
                        newResponse = await InternalNoDnssecResolveAsync(newRequest, cancellationToken);

                    //removing NS records from authority section and glue records to prevent them from being cached as referrer when answer section is empty
                    newResponse = GetMinimalResponseWithoutNSAndGlue(newResponse);

                    _cache.CacheResponse(newResponse);

                    return newResponse;
                }
                catch (TaskCanceledException)
                {
                    //catch to prevent caching failure record
                    throw;
                }
                catch (Exception ex)
                {
                    if (ex is DnsClientResponseDnssecValidationException ex2)
                    {
                        if ((ex2.Response.Question.Count > 0) && ex2.Response.Question[0].Equals(q))
                        {
                            //was already cached as bad cache
                        }
                        else
                        {
                            //response is not for current question; cache its extended errors as failure response
                            DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { q });
                            failureResponse.AddDnsClientExtendedErrorFrom(ex2.Response);

                            if (_eDnsClientSubnet is not null)
                                failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(_eDnsClientSubnet.PrefixLength, _eDnsClientSubnet.PrefixLength, _eDnsClientSubnet.Address));

                            //cache as failure
                            _cache.CacheResponse(failureResponse);
                        }
                    }
                    else if (ex is DnsClientNoResponseException)
                    {
                        //cache as failure
                        DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { q });

                        if (ex.InnerException is SocketException ex3)
                        {
                            if (ex3.SocketErrorCode == SocketError.TimedOut)
                                failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NoReachableAuthority, "Request timed out for " + q.ToString());
                            else
                                failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NetworkError, "Socket error for " + q.ToString() + ": " + ex3.SocketErrorCode.ToString());
                        }
                        else
                        {
                            failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NoReachableAuthority, "No response from name servers for " + q.ToString());
                        }

                        if (_eDnsClientSubnet is not null)
                            failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(_eDnsClientSubnet.PrefixLength, _eDnsClientSubnet.PrefixLength, _eDnsClientSubnet.Address));

                        _cache.CacheResponse(failureResponse);
                    }
                    else if (ex is SocketException ex4)
                    {
                        //cache as failure
                        DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { q });

                        if (ex4.SocketErrorCode == SocketError.TimedOut)
                            failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NoReachableAuthority, "Request timed out for " + q.ToString());
                        else
                            failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NetworkError, "Socket error for " + q.ToString() + ": " + ex4.SocketErrorCode.ToString());

                        if (_eDnsClientSubnet is not null)
                            failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(_eDnsClientSubnet.PrefixLength, _eDnsClientSubnet.PrefixLength, _eDnsClientSubnet.Address));

                        _cache.CacheResponse(failureResponse);
                    }
                    else if (ex is IOException ex5)
                    {
                        //cache as failure
                        DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { q });

                        if (ex5.InnerException is SocketException ex4a)
                        {
                            if (ex4a.SocketErrorCode == SocketError.TimedOut)
                                failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NoReachableAuthority, "Request timed out for " + q.ToString());
                            else
                                failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NetworkError, "Socket error for " + q.ToString() + ": " + ex4a.SocketErrorCode.ToString());
                        }
                        else
                        {
                            failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NetworkError, "IO error for " + q.ToString() + ": " + ex5.Message);
                        }

                        if (_eDnsClientSubnet is not null)
                            failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(_eDnsClientSubnet.PrefixLength, _eDnsClientSubnet.PrefixLength, _eDnsClientSubnet.Address));

                        _cache.CacheResponse(failureResponse);
                    }
                    else
                    {
                        //cache as failure
                        DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { q });
                        failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.Other, "Resolver exception for " + q.ToString() + ": " + ex.Message);

                        if (_eDnsClientSubnet is not null)
                            failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(_eDnsClientSubnet.PrefixLength, _eDnsClientSubnet.PrefixLength, _eDnsClientSubnet.Address));

                        _cache.CacheResponse(failureResponse);
                    }

                    throw;
                }
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

        public Task<DnsDatagram> RawResolveAsync(DnsDatagram request, CancellationToken cancellationToken = default)
        {
            return InternalResolveAsync(request, cancellationToken: cancellationToken);
        }

        public async Task<DnsDatagram> TsigResolveAsync(DnsDatagram request, TsigKey key, ushort fudge = 300, CancellationToken cancellationToken = default)
        {
            if (request.Identifier == 0)
                request.SetRandomIdentifier();

            DnsDatagram signedRequest = request.SignRequest(key, fudge);

            return await InternalResolveAsync(signedRequest, delegate (DnsDatagram signedResponse, CancellationToken cancellationToken1)
            {
                if (!signedResponse.VerifySignedResponse(signedRequest, key, out DnsDatagram unsignedResponse, out bool requestFailed, out DnsResponseCode rCode, out DnsTsigError error))
                {
                    if (requestFailed)
                        throw new DnsClientTsigRequestFailedException(rCode, error);
                    else
                        throw new DnsClientTsigResponseVerificationException(rCode, error);
                }

                return Task.FromResult(unsignedResponse);
            }, false, cancellationToken);
        }

        public Task<DnsDatagram> TsigResolveAsync(DnsQuestionRecord question, TsigKey key, ushort fudge = 300, CancellationToken cancellationToken = default)
        {
            DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { question }, null, null, null, _udpPayloadSize, EDnsHeaderFlags.None, _advancedForwardingClientSubnet ? null : EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(_eDnsClientSubnet));
            if (_advancedForwardingClientSubnet)
                request.SetShadowEDnsClientSubnetOption(_eDnsClientSubnet, true);

            return TsigResolveAsync(request, key, fudge, cancellationToken);
        }

        public Task<DnsDatagram> TsigResolveAsync(string domain, DnsResourceRecordType type, TsigKey key, ushort fudge = 300, CancellationToken cancellationToken = default)
        {
            if ((type == DnsResourceRecordType.PTR) && IPAddress.TryParse(domain, out IPAddress address))
                return TsigResolveAsync(new DnsQuestionRecord(address, DnsClass.IN), key, fudge, cancellationToken);
            else
                return TsigResolveAsync(new DnsQuestionRecord(domain, type, DnsClass.IN), key, fudge, cancellationToken);
        }

        public Task<DnsDatagram> ResolveAsync(DnsQuestionRecord question, CancellationToken cancellationToken = default)
        {
            if (_cache is not null)
                return InternalCachedResolveQueryAsync(question, cancellationToken);

            if (_dnssecValidation)
                return InternalDnssecResolveAsync(question, cancellationToken);

            DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { question }, null, null, null, _udpPayloadSize, EDnsHeaderFlags.None, _advancedForwardingClientSubnet ? null : EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(_eDnsClientSubnet));
            if (_advancedForwardingClientSubnet)
                request.SetShadowEDnsClientSubnetOption(_eDnsClientSubnet, true);

            return InternalNoDnssecResolveAsync(request, cancellationToken);
        }

        public Task<DnsDatagram> ResolveAsync(string domain, DnsResourceRecordType type, CancellationToken cancellationToken = default)
        {
            if ((type == DnsResourceRecordType.PTR) && IPAddress.TryParse(domain, out IPAddress address))
                return ResolveAsync(new DnsQuestionRecord(address, DnsClass.IN), cancellationToken);
            else
                return ResolveAsync(new DnsQuestionRecord(domain, type, DnsClass.IN), cancellationToken);
        }

        public Task<IReadOnlyList<string>> ResolveMXAsync(string domain, bool resolveIP = false, bool preferIPv6 = false, CancellationToken cancellationToken = default)
        {
            return ResolveMXAsync(this, domain, resolveIP, preferIPv6, cancellationToken);
        }

        public async Task<IReadOnlyList<string>> ResolvePTRAsync(IPAddress ip, CancellationToken cancellationToken = default)
        {
            return ParseResponsePTR(await ResolveAsync(new DnsQuestionRecord(ip, DnsClass.IN), cancellationToken));
        }

        public async Task<IReadOnlyList<string>> ResolveTXTAsync(string domain, CancellationToken cancellationToken = default)
        {
            return ParseResponseTXT(await ResolveAsync(new DnsQuestionRecord(domain, DnsResourceRecordType.TXT, DnsClass.IN), cancellationToken));
        }

        public Task<IReadOnlyList<IPAddress>> ResolveIPAsync(string domain, bool preferIPv6 = false, CancellationToken cancellationToken = default)
        {
            return ResolveIPAsync(this, domain, preferIPv6, cancellationToken);
        }

        public void AddTrustAnchor(string domain, DnsDSRecordData dsRecord)
        {
            AddTrustAnchor(domain, dsRecord.KeyTag, dsRecord.Algorithm, dsRecord.DigestType, dsRecord.Digest);
        }

        public void AddTrustAnchor(string domain, ushort keyTag, DnssecAlgorithm algorithm, DnssecDigestType digestType, string digest)
        {
            AddTrustAnchor(domain, keyTag, algorithm, digestType, Convert.FromHexString(digest));
        }

        public void AddTrustAnchor(string domain, ushort keyTag, DnssecAlgorithm algorithm, DnssecDigestType digestType, byte[] digest)
        {
            if (_trustAnchors is null)
                _trustAnchors = new Dictionary<string, IReadOnlyList<DnsResourceRecord>>();

            DnsResourceRecord dsRecord = new DnsResourceRecord(domain, DnsResourceRecordType.DS, DnsClass.IN, 0, new DnsDSRecordData(keyTag, algorithm, digestType, digest));

            if (_trustAnchors.TryGetValue(domain, out IReadOnlyList<DnsResourceRecord> existingRecords))
            {
                List<DnsResourceRecord> newRecords = new List<DnsResourceRecord>(existingRecords.Count + 1);

                newRecords.AddRange(existingRecords);
                newRecords.Add(dsRecord);

                _trustAnchors[domain] = newRecords;
            }
            else
            {
                _trustAnchors.Add(domain, new DnsResourceRecord[] { dsRecord });
            }
        }

        public async Task ValidateDaneAsync(SslStream sslStream, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors, CancellationToken cancellationToken = default)
        {
            if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
                throw new AuthenticationException("The remote certificate is invalid according to the validation procedure: " + sslPolicyErrors.ToString());

            NetworkStream networkStream = _sslStream_innerStream.GetValue(sslStream) as NetworkStream;
            IReadOnlyList<DnsTLSARecordData> tlsaRecords = ParseResponseTLSA(await ResolveAsync("_" + networkStream.Socket.RemoteEndPoint.GetPort() + "._tcp." + sslStream.TargetHostName, DnsResourceRecordType.TLSA, cancellationToken));

            if ((tlsaRecords is null) || (tlsaRecords.Count == 0))
            {
                //no TLSA records available; process as usual
                if (sslPolicyErrors == SslPolicyErrors.None)
                    return;

                throw new AuthenticationException("The remote certificate is invalid according to the validation procedure: " + sslPolicyErrors.ToString());
            }

            foreach (DnsTLSARecordData tlsa in tlsaRecords)
            {
                switch (tlsa.CertificateUsage)
                {
                    case DnsTLSACertificateUsage.PKIX_TA:
                        {
                            if (sslPolicyErrors == SslPolicyErrors.None)
                            {
                                //PKIX is validating; validate TLSA
                                for (int i = 1; i < chain.ChainElements.Count; i++)
                                {
                                    X509ChainElement chainElement = chain.ChainElements[i];
                                    byte[] certificateAssociatedData = DnsTLSARecordData.GetCertificateAssociatedData(tlsa.Selector, tlsa.MatchingType, chainElement.Certificate);

                                    if (BinaryNumber.Equals(certificateAssociatedData, tlsa.CertificateAssociationData))
                                        return; //TLSA is validating
                                }
                            }
                        }
                        break;

                    case DnsTLSACertificateUsage.PKIX_EE:
                        {
                            if (sslPolicyErrors == SslPolicyErrors.None)
                            {
                                //PKIX is validating; validate TLSA
                                byte[] certificateAssociatedData = DnsTLSARecordData.GetCertificateAssociatedData(tlsa.Selector, tlsa.MatchingType, certificate);

                                if (BinaryNumber.Equals(certificateAssociatedData, tlsa.CertificateAssociationData))
                                    return; //TLSA is validating
                            }
                        }
                        break;

                    case DnsTLSACertificateUsage.DANE_TA:
                        {
                            bool pkixFailed = false;

                            for (int i = 0; i < chain.ChainElements.Count; i++)
                            {
                                X509ChainElement chainElement = chain.ChainElements[i];

                                if (i == 0)
                                {
                                    //validate PKIX
                                    if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch) || (chainElement.ChainElementStatus.Length > 0))
                                    {
                                        //cert has validation issues
                                        pkixFailed = true;
                                        break;
                                    }

                                    //first i.e. end entity certificate only requires cert validation
                                    continue;
                                }

                                //validate TLSA
                                byte[] certificateAssociatedData = DnsTLSARecordData.GetCertificateAssociatedData(tlsa.Selector, tlsa.MatchingType, chainElement.Certificate);
                                bool tlsaVerified = BinaryNumber.Equals(certificateAssociatedData, tlsa.CertificateAssociationData);

                                //validate PKIX
                                foreach (X509ChainStatus chainStatus in chainElement.ChainElementStatus)
                                {
                                    switch (chainStatus.Status)
                                    {
                                        case X509ChainStatusFlags.PartialChain:
                                        case X509ChainStatusFlags.UntrustedRoot:
                                            if (tlsaVerified)
                                                continue; //ignored issues since cert is TA

                                            //cert has validation issues
                                            break;
                                    }

                                    //cert has validation issues
                                    pkixFailed = true;
                                    break;
                                }

                                if (pkixFailed)
                                    break; //cert has validation issues; DANE-TA failed to validate

                                if (tlsaVerified)
                                    return; //TLSA is validating; DANE-TA was validated successfully
                            }

                            if (!pkixFailed && (tlsa.MatchingType == DnsTLSAMatchingType.Full))
                            {
                                switch (tlsa.Selector)
                                {
                                    case DnsTLSASelector.Cert:
                                        {
                                            //validate TA cert from TLSA record
                                            X509Certificate2 taCert = new X509Certificate2(tlsa.CertificateAssociationData);
                                            X509Certificate2 lastCert = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;

                                            using (X509Chain taChain = new X509Chain())
                                            {
                                                taChain.ChainPolicy.CustomTrustStore.Add(taCert);

                                                if (taChain.Build(lastCert))
                                                    return; //TA cert chain is validating
                                            }
                                        }
                                        break;

                                    case DnsTLSASelector.SPKI:
                                        //validation using only public key is not supported
                                        break;
                                }
                            }
                        }
                        break;

                    case DnsTLSACertificateUsage.DANE_EE:
                        {
                            //validate PKIX
                            bool pkixFailed = false;

                            foreach (X509ChainStatus chainStatus in chain.ChainElements[0].ChainElementStatus)
                            {
                                switch (chainStatus.Status)
                                {
                                    case X509ChainStatusFlags.PartialChain:
                                    case X509ChainStatusFlags.UntrustedRoot:
                                    case X509ChainStatusFlags.HasExcludedNameConstraint:
                                    case X509ChainStatusFlags.HasNotDefinedNameConstraint:
                                    case X509ChainStatusFlags.HasNotPermittedNameConstraint:
                                    case X509ChainStatusFlags.HasNotSupportedNameConstraint:
                                    case X509ChainStatusFlags.InvalidNameConstraints:
                                    case X509ChainStatusFlags.NotTimeValid:
                                        //ignored issues
                                        continue;
                                }

                                //cert has validation issues
                                pkixFailed = true;
                                break;
                            }

                            if (pkixFailed)
                                break; //cert has validation issues

                            //PKIX is validating; validate TLSA
                            byte[] certificateAssociatedData = DnsTLSARecordData.GetCertificateAssociatedData(tlsa.Selector, tlsa.MatchingType, certificate);

                            if (BinaryNumber.Equals(certificateAssociatedData, tlsa.CertificateAssociationData))
                                return; //TLSA is validating
                        }
                        break;
                }
            }

            throw new AuthenticationException("The SSL connection could not be established since the TLS certificate failed DANE validation: no matching TLSA record was found, or the certificate had one or more issues.");
        }

        #endregion

        #region property

        internal static IReadOnlyList<NameServerAddress> IPv4RootHints
        { get { return IPv4_ROOT_HINTS; } }

        internal static IReadOnlyList<NameServerAddress> IPv6RootHints
        { get { return IPv6_ROOT_HINTS; } }

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

        public NetworkAddress EDnsClientSubnet
        {
            get { return _eDnsClientSubnet; }
            set { _eDnsClientSubnet = value; }
        }

        public bool AdvancedForwardingClientSubnet
        {
            get { return _advancedForwardingClientSubnet; }
            set { _advancedForwardingClientSubnet = value; }
        }

        public string ConditionalForwardingZoneCut
        {
            get { return _conditionalForwardingZoneCut; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    _conditionalForwardingZoneCut = null;
                else
                    _conditionalForwardingZoneCut = value;
            }
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

        public IDictionary<string, IReadOnlyList<DnsResourceRecord>> TrustAnchors
        {
            get
            {
                if (_trustAnchors is null)
                    _trustAnchors = new Dictionary<string, IReadOnlyList<DnsResourceRecord>>();

                return _trustAnchors;
            }
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

        class NsRevalidationTask
        {
            public readonly IReadOnlyList<DnsResourceRecord> LastDSRecords;
            public readonly IReadOnlyList<NameServerAddress> NameServers;

            public NsRevalidationTask(IReadOnlyList<DnsResourceRecord> lastDSRecords, IReadOnlyList<NameServerAddress> nameServers)
            {
                LastDSRecords = lastDSRecords;
                NameServers = nameServers;
            }
        }

        class DnssecValidateSignatureParameters
        {
            public int MaxCryptoFailures = KEY_TRAP_MAX_CRYPTO_FAILURES;
            public int MaxCryptoValidations = KEY_TRAP_MAX_RRSET_VALIDATIONS_PER_SUSPENSION;
            public int MaxSuspensions = KEY_TRAP_MAX_SUSPENSIONS_PER_RESPONSE;
        }
    }
}
