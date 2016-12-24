/*
Technitium Library
Copyright (C) 2016  Shreyas Zare (shreyas@technitium.com)

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
using System.Net.Sockets;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;

namespace TechnitiumLibrary.Net
{
    public enum DnsRecordType : ushort
    {
        A = 1,
        NS = 2,
        MD = 3,
        MF = 4,
        CNAME = 5,
        SOA = 6,
        MB = 7,
        MG = 8,
        MR = 9,
        NULL = 10,
        WKS = 11,
        PTR = 12,
        HINFO = 13,
        MINFO = 14,
        MX = 15,
        TXT = 16,
        RP = 17,
        AFSDB = 18,
        X25 = 19,
        ISDN = 20,
        RT = 21,
        NSAP = 22,
        NSAP_PTR = 23,
        SIG = 24,
        KEY = 25,
        PX = 26,
        GPOS = 27,
        AAAA = 28,
        LOC = 29,
        NXT = 30,
        EID = 31,
        NIMLOC = 32,
        SRV = 33,
        ATMA = 34,
        NAPTR = 35,
        KX = 36,
        CERT = 37,
        A6 = 38,
        DNAME = 39,
        SINK = 40,
        APL = 42,
        DS = 43,
        SSHFP = 44,
        IPSECKEY = 45,
        RRSIG = 46,
        NSEC = 47,
        DNSKEY = 48,
        DHCID = 49,
        NSEC3 = 50,
        NSEC3PARAM = 51,
        TLSA = 52,
        HIP = 55,
        CDS = 59,
        CDNSKEY = 60,
        SPF = 99,
        UINFO = 100,
        UID = 101,
        GID = 102,
        UNSPEC = 103,
        TKEY = 249,
        TSIG = 250,
        URI = 256,
        CAA = 257,
        TA = 32768,
        DLV = 32769,

        OPT = 41,
        AXFR = 252,
        MAILB = 253,
        MAILA = 254,
        ANY = 255
    }

    public enum DnsClass : ushort
    {
        IN = 1,
        CS = 2,
        CH = 3,
        HS = 4,

        ANY = 255
    }

    public class DnsClient
    {
        #region variables

        public static readonly NameServerAddress[] ROOT_NAME_SERVERS_IPv4;
        public static readonly NameServerAddress[] ROOT_NAME_SERVERS_IPv6;

        static RandomNumberGenerator _rnd = new RNGCryptoServiceProvider();

        NameServerAddress[] _servers;
        bool _tcp;

        #endregion

        #region constructor

        static DnsClient()
        {
            ROOT_NAME_SERVERS_IPv4 = new NameServerAddress[13];

            ROOT_NAME_SERVERS_IPv4[0] = new NameServerAddress("a.root-servers.net", IPAddress.Parse("198.41.0.4")); //VeriSign, Inc.
            ROOT_NAME_SERVERS_IPv4[1] = new NameServerAddress("b.root-servers.net", IPAddress.Parse("192.228.79.201")); //University of Southern California (ISI)
            ROOT_NAME_SERVERS_IPv4[2] = new NameServerAddress("c.root-servers.net", IPAddress.Parse("192.33.4.12")); //Cogent Communications
            ROOT_NAME_SERVERS_IPv4[3] = new NameServerAddress("d.root-servers.net", IPAddress.Parse("199.7.91.13")); //University of Maryland
            ROOT_NAME_SERVERS_IPv4[4] = new NameServerAddress("e.root-servers.net", IPAddress.Parse("192.203.230.10")); //NASA (Ames Research Center)
            ROOT_NAME_SERVERS_IPv4[5] = new NameServerAddress("f.root-servers.net", IPAddress.Parse("192.5.5.241")); //Internet Systems Consortium, Inc.
            ROOT_NAME_SERVERS_IPv4[6] = new NameServerAddress("g.root-servers.net", IPAddress.Parse("192.112.36.4")); //US Department of Defense (NIC)
            ROOT_NAME_SERVERS_IPv4[7] = new NameServerAddress("h.root-servers.net", IPAddress.Parse("198.97.190.53")); //US Army (Research Lab)
            ROOT_NAME_SERVERS_IPv4[8] = new NameServerAddress("i.root-servers.net", IPAddress.Parse("192.36.148.17")); //Netnod
            ROOT_NAME_SERVERS_IPv4[9] = new NameServerAddress("j.root-servers.net", IPAddress.Parse("192.58.128.30")); //VeriSign, Inc.
            ROOT_NAME_SERVERS_IPv4[10] = new NameServerAddress("k.root-servers.net", IPAddress.Parse("193.0.14.129")); //RIPE NCC
            ROOT_NAME_SERVERS_IPv4[11] = new NameServerAddress("l.root-servers.net", IPAddress.Parse("199.7.83.42")); //ICANN
            ROOT_NAME_SERVERS_IPv4[12] = new NameServerAddress("m.root-servers.net", IPAddress.Parse("202.12.27.33")); //WIDE Project


            ROOT_NAME_SERVERS_IPv6 = new NameServerAddress[13];

            ROOT_NAME_SERVERS_IPv6[0] = new NameServerAddress("a.root-servers.net", IPAddress.Parse("2001:503:ba3e::2:30")); //VeriSign, Inc.
            ROOT_NAME_SERVERS_IPv6[1] = new NameServerAddress("b.root-servers.net", IPAddress.Parse("2001:500:84::b")); //University of Southern California (ISI)
            ROOT_NAME_SERVERS_IPv6[2] = new NameServerAddress("c.root-servers.net", IPAddress.Parse("2001:500:2::c")); //Cogent Communications
            ROOT_NAME_SERVERS_IPv6[3] = new NameServerAddress("d.root-servers.net", IPAddress.Parse("2001:500:2d::d")); //University of Maryland
            ROOT_NAME_SERVERS_IPv6[4] = new NameServerAddress("e.root-servers.net", IPAddress.Parse("2001:500:a8::e")); //NASA (Ames Research Center)
            ROOT_NAME_SERVERS_IPv6[5] = new NameServerAddress("f.root-servers.net", IPAddress.Parse("2001:500:2f::f")); //Internet Systems Consortium, Inc.
            ROOT_NAME_SERVERS_IPv6[6] = new NameServerAddress("g.root-servers.net", IPAddress.Parse("2001:500:12::d0d")); //US Department of Defense (NIC)
            ROOT_NAME_SERVERS_IPv6[7] = new NameServerAddress("h.root-servers.net", IPAddress.Parse("2001:500:1::53")); //US Army (Research Lab)
            ROOT_NAME_SERVERS_IPv6[8] = new NameServerAddress("i.root-servers.net", IPAddress.Parse("2001:7fe::53")); //Netnod
            ROOT_NAME_SERVERS_IPv6[9] = new NameServerAddress("j.root-servers.net", IPAddress.Parse("2001:503:c27::2:30")); //VeriSign, Inc.
            ROOT_NAME_SERVERS_IPv6[10] = new NameServerAddress("k.root-servers.net", IPAddress.Parse("2001:7fd::1")); //RIPE NCC
            ROOT_NAME_SERVERS_IPv6[11] = new NameServerAddress("l.root-servers.net", IPAddress.Parse("2001:500:9f::42")); //ICANN
            ROOT_NAME_SERVERS_IPv6[12] = new NameServerAddress("m.root-servers.net", IPAddress.Parse("2001:dc3::35")); //WIDE Project
        }

        public DnsClient(IPAddress[] servers, bool tcp = false, ushort port = 53)
        {
            if (servers.Length == 0)
                throw new DnsClientException("Atleast one name server must be available for Dns Client.");

            _servers = new NameServerAddress[servers.Length];
            _tcp = tcp;

            for (int i = 0; i < servers.Length; i++)
                _servers[i] = new NameServerAddress(servers[i], port);
        }

        public DnsClient(IPAddress server, bool tcp = false, ushort port = 53)
            : this(new NameServerAddress(server, port), tcp)
        { }

        public DnsClient(IPEndPoint server, bool tcp = false)
            : this(new NameServerAddress(server), tcp)
        { }

        public DnsClient(NameServerAddress server, bool tcp = false)
        {
            _servers = new NameServerAddress[] { server };
            _tcp = tcp;
        }

        public DnsClient(NameServerAddress[] servers, bool tcp = false)
        {
            if (servers.Length == 0)
                throw new DnsClientException("Atleast one name server must be available for Dns Client.");

            _servers = servers;
            _tcp = tcp;
        }

        #endregion

        #region static

        public static DnsDatagram ResolveViaRootNameServers(string domain, DnsRecordType queryType, bool ipv6 = false, bool tcp = false, int retries = 2)
        {
            if (ipv6)
                return ResolveViaNameServers(ROOT_NAME_SERVERS_IPv6, domain, queryType, tcp, retries);
            else
                return ResolveViaNameServers(ROOT_NAME_SERVERS_IPv4, domain, queryType, tcp, retries);
        }

        public static DnsDatagram ResolveViaNameServers(NameServerAddress[] nameServers, string domain, DnsRecordType queryType, bool tcp = false, int retries = 2)
        {
            int hopCount = 0;
            IPAddress ptrIP = null;

            if (queryType == DnsRecordType.PTR)
                ptrIP = IPAddress.Parse(domain);

            while ((hopCount++) < 64)
            {
                DnsClient client = new DnsClient(nameServers, tcp);

                DnsDatagram response;

                if (queryType == DnsRecordType.PTR)
                    response = client.Resolve(new DnsQuestionRecord(ptrIP, DnsClass.IN), retries);
                else
                    response = client.Resolve(new DnsQuestionRecord(domain, queryType, DnsClass.IN), retries);

                switch (response.Header.RCODE)
                {
                    case DnsResponseCode.NoError:
                        if (response.Answer.Length > 0)
                            return response;

                        if (response.Authority.Length == 0)
                            return response;

                        nameServers = client.GetNameServersFromResponse(response);

                        if (nameServers.Length == 0)
                            return response;

                        break;

                    default:
                        return response;
                }
            }

            throw new DnsClientException("Dns client exceeded the maximum hop count to resolve the domain: " + domain);
        }

        #endregion

        #region private

        private NameServerAddress[] GetNameServersFromResponse(DnsDatagram response)
        {
            bool ipv6 = (response.NameServerAddress.EndPoint.AddressFamily == AddressFamily.InterNetworkV6);

            List<NameServerAddress> nameServers = new List<NameServerAddress>(4);
            List<string> nameServersWithoutIP = new List<string>(4);

            foreach (DnsResourceRecord authorityRecord in response.Authority)
            {
                if (authorityRecord.Type == DnsRecordType.NS)
                {
                    DnsNSRecord nsRecord = (DnsNSRecord)authorityRecord.RDATA;
                    IPEndPoint _endPoint = null;

                    //find ip address of authoritative name server from additional records
                    foreach (DnsResourceRecord rr in response.Additional)
                    {
                        if (rr.Name.Equals(nsRecord.NSDomainName, StringComparison.CurrentCultureIgnoreCase))
                        {
                            switch (rr.Type)
                            {
                                case DnsRecordType.A:
                                    _endPoint = new IPEndPoint(((DnsARecord)rr.RDATA).Address, 53);
                                    nameServers.Add(new NameServerAddress(nsRecord.NSDomainName, _endPoint));
                                    break;

                                case DnsRecordType.AAAA:
                                    if (ipv6)
                                    {
                                        _endPoint = new IPEndPoint(((DnsAAAARecord)rr.RDATA).Address, 53);
                                        nameServers.Add(new NameServerAddress(nsRecord.NSDomainName, _endPoint));
                                    }
                                    break;
                            }
                        }
                    }

                    if (_endPoint == null)
                        nameServersWithoutIP.Add(nsRecord.NSDomainName);
                }
            }

            if (nameServers.Count == 0)
            {
                //resolve name server ip addresses
                foreach (string nameServer in nameServersWithoutIP)
                {
                    try
                    {
                        if (ipv6)
                        {
                            DnsDatagram nsResponse = DnsClient.ResolveViaRootNameServers(nameServer, DnsRecordType.AAAA, true, _tcp);
                            if ((nsResponse.Header.RCODE == DnsResponseCode.NoError) && (nsResponse.Answer.Length > 0) && (nsResponse.Answer[0].Type == DnsRecordType.AAAA))
                                nameServers.Add(new NameServerAddress(nameServer, new IPEndPoint((nsResponse.Answer[0].RDATA as DnsAAAARecord).Address, 53)));
                        }

                        {
                            DnsDatagram nsResponse = DnsClient.ResolveViaRootNameServers(nameServer, DnsRecordType.A, false, _tcp);
                            if ((nsResponse.Header.RCODE == DnsResponseCode.NoError) && (nsResponse.Answer.Length > 0) && (nsResponse.Answer[0].Type == DnsRecordType.A))
                                nameServers.Add(new NameServerAddress(nameServer, new IPEndPoint((nsResponse.Answer[0].RDATA as DnsARecord).Address, 53)));
                        }
                    }
                    catch
                    { }
                }
            }

            return nameServers.ToArray();
        }

        private DnsDatagram Resolve(DnsQuestionRecord query, int retries)
        {
            byte[] buffer = new byte[2];
            int bytesRecv;
            byte[] recvbuffer = new byte[64 * 1024];
            int nextServerIndex = 0;

            if (_servers.Length > 1)
            {
                retries = retries * _servers.Length; //retries on per server basis

                byte[] select = new byte[1];
                _rnd.GetBytes(select);

                nextServerIndex = select[0] % _servers.Length;
            }

            int retry = 1;
            do
            {
                _rnd.GetBytes(buffer);
                ushort id = BitConverter.ToUInt16(buffer, 0);
                byte[] sendBuffer;

                using (MemoryStream dnsQueryStream = new MemoryStream(32))
                {
                    if (_tcp)
                        dnsQueryStream.Position = 2;

                    //write dns datagram
                    (new DnsHeader(id, false, DnsOpcode.StandardQuery, false, false, true, false, DnsResponseCode.NoError, 1, 0, 0, 0)).WriteTo(dnsQueryStream);
                    query.WriteTo(dnsQueryStream);

                    sendBuffer = dnsQueryStream.ToArray();

                    if (_tcp)
                    {
                        byte[] length = BitConverter.GetBytes(Convert.ToInt16(sendBuffer.Length - 2));

                        sendBuffer[0] = length[1];
                        sendBuffer[1] = length[0];
                    }
                }

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

                //query server
                Socket _socket = null;

                try
                {
                    retry++;

                    if (_tcp)
                    {
                        _socket = new Socket(server.EndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                        _socket.NoDelay = true;
                        _socket.SendTimeout = 2000;
                        _socket.ReceiveTimeout = 2000;

                        _socket.Connect(server.EndPoint);
                        _socket.Send(sendBuffer);

                        bytesRecv = _socket.Receive(recvbuffer, 0, 2, SocketFlags.None);

                        Array.Reverse(recvbuffer, 0, 2);
                        short length = BitConverter.ToInt16(recvbuffer, 0);

                        int offset = 0;
                        while (offset < length)
                        {
                            bytesRecv = _socket.Receive(recvbuffer, offset, length, SocketFlags.None);
                            offset += bytesRecv;
                        }

                        bytesRecv = length;
                    }
                    else
                    {
                        _socket = new Socket(server.EndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);

                        _socket.SendTimeout = 2000;
                        _socket.ReceiveTimeout = 2000;

                        _socket.SendTo(sendBuffer, server.EndPoint);

                        EndPoint remoteEP;

                        if (server.EndPoint.AddressFamily == AddressFamily.InterNetworkV6)
                            remoteEP = new IPEndPoint(IPAddress.IPv6Any, 0);
                        else
                            remoteEP = new IPEndPoint(IPAddress.Any, 0);

                        bytesRecv = _socket.ReceiveFrom(recvbuffer, ref remoteEP);
                    }

                    using (MemoryStream mS = new MemoryStream(recvbuffer, 0, bytesRecv, false))
                    {
                        DnsDatagram response = new DnsDatagram(mS, server);

                        if (response.Header.Identifier == id)
                            return response;
                    }
                }
                catch (SocketException ex)
                {
                    if (retry > retries)
                    {
                        throw new DnsClientException("A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond. Name Server: " + server.ToString(), ex);
                    }
                }
                finally
                {
                    if (_socket != null)
                        _socket.Dispose();
                }
            }
            while (true);
        }

        #endregion

        #region public

        public DnsDatagram Resolve(string domain, DnsRecordType queryType, int retries = 2)
        {
            if (queryType == DnsRecordType.PTR)
                return Resolve(new DnsQuestionRecord(IPAddress.Parse(domain), DnsClass.IN), retries);
            else
                return Resolve(new DnsQuestionRecord(domain, queryType, DnsClass.IN), retries);
        }

        public string ResolveMX(MailAddress emailAddress, bool resolveIP = false, bool ipv6 = false, int retries = 2)
        {
            return ResolveMX(emailAddress.Host, resolveIP, ipv6, retries);
        }

        public string ResolveMX(string domain, bool resolveIP = false, bool ipv6 = false, int retries = 2)
        {
            IPAddress parsedIP = null;

            if (IPAddress.TryParse(domain, out parsedIP))
            {
                //host is valid ip address
                return domain;
            }

            //host is domain
            DnsDatagram response = Resolve(new DnsQuestionRecord(domain, DnsRecordType.MX, DnsClass.IN), retries);

            switch (response.Header.RCODE)
            {
                case DnsResponseCode.NoError:
                    if ((response.Header.ANCOUNT == 0) || !response.Answer[0].Name.Equals(domain, StringComparison.CurrentCultureIgnoreCase) || (response.Answer[0].Type != DnsRecordType.MX))
                        throw new NameErrorDnsClientException("No answer received from name server for domain: " + domain + "; Name Server: " + response.NameServerAddress.ToString());

                    string mxDomain = ((DnsMXRecord)response.Answer[0].RDATA).Exchange;

                    if (!resolveIP)
                        return mxDomain;

                    //check glue records
                    foreach (DnsResourceRecord record in response.Additional)
                    {
                        if (record.Name.Equals(mxDomain, StringComparison.CurrentCultureIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsRecordType.A:
                                    if (!ipv6)
                                        return ((DnsARecord)record.RDATA).Address.ToString();

                                    break;

                                case DnsRecordType.AAAA:
                                    return ((DnsAAAARecord)record.RDATA).Address.ToString();
                            }
                        }
                    }

                    //no glue record found so resolve ip
                    return ResolveIP(mxDomain, ipv6, retries).ToString();

                case DnsResponseCode.NameError:
                    throw new NameErrorDnsClientException("Domain does not exists: " + domain + "; Name Server: " + response.NameServerAddress.ToString());

                default:
                    throw new DnsClientException("Name Server error. DNS opcode: " + Enum.GetName(typeof(DnsResponseCode), response.Header.RCODE) + " (" + response.Header.RCODE + ")");
            }
        }

        public string ResolvePTR(IPAddress ip, int retries = 2)
        {
            DnsDatagram response = Resolve(new DnsQuestionRecord(ip, DnsClass.IN), retries);

            if ((response.Header.RCODE == DnsResponseCode.NoError) && (response.Header.ANCOUNT > 0) && (response.Answer[0].Type == DnsRecordType.PTR))
                return ((DnsPTRRecord)response.Answer[0].RDATA).PTRDomainName;
            else
                throw new NameErrorDnsClientException("PTR record does not exists for ip: " + ip.ToString() + "; Name Server: " + response.NameServerAddress.ToString());
        }

        public IPAddress ResolveIP(string domain, bool ipv6 = false, int retries = 2)
        {
            DnsDatagram response = Resolve(new DnsQuestionRecord(domain, ipv6 ? DnsRecordType.AAAA : DnsRecordType.A, DnsClass.IN), retries);

            switch (response.Header.RCODE)
            {
                case DnsResponseCode.NoError:
                    if ((response.Header.ANCOUNT == 0) || !response.Answer[0].Name.Equals(domain, StringComparison.CurrentCultureIgnoreCase))
                        throw new NameErrorDnsClientException("No answer received from name server for domain: " + domain + "; Name Server: " + response.NameServerAddress.ToString());

                    switch (response.Answer[0].Type)
                    {
                        case DnsRecordType.A:
                            return ((DnsARecord)response.Answer[0].RDATA).Address;

                        case DnsRecordType.AAAA:
                            return ((DnsAAAARecord)response.Answer[0].RDATA).Address;

                        case DnsRecordType.CNAME:
                            string cnameDomain = ((DnsCNAMERecord)response.Answer[0].RDATA).CNAMEDomainName;

                            foreach (DnsResourceRecord record in response.Answer)
                            {
                                if (record.Name.Equals(cnameDomain, StringComparison.CurrentCultureIgnoreCase))
                                {
                                    switch (record.Type)
                                    {
                                        case DnsRecordType.A:
                                            return ((DnsARecord)record.RDATA).Address;

                                        case DnsRecordType.AAAA:
                                            return ((DnsAAAARecord)record.RDATA).Address;

                                        case DnsRecordType.CNAME:
                                            cnameDomain = ((DnsCNAMERecord)record.RDATA).CNAMEDomainName;
                                            break;
                                    }
                                }
                            }

                            return ResolveIP(cnameDomain);

                        default:
                            throw new NameErrorDnsClientException("No answer received from name server for domain: " + domain + "; Name Server: " + response.NameServerAddress.ToString());
                    }

                case DnsResponseCode.NameError:
                    throw new NameErrorDnsClientException("Domain does not exists: " + domain + "; Name Server: " + response.NameServerAddress.ToString());

                default:
                    throw new DnsClientException("Name Server error. DNS opcode: " + Enum.GetName(typeof(DnsResponseCode), response.Header.RCODE) + " (" + response.Header.RCODE + ")");
            }
        }

        #endregion

        #region property

        public NameServerAddress[] Servers
        { get { return _servers; } }

        #endregion
    }

    public class NameServerAddress
    {
        #region variables

        string _domainName;
        IPEndPoint _endPoint;

        #endregion

        #region constructors

        public NameServerAddress(IPAddress address, ushort port = 53)
            : this(null, new IPEndPoint(address, port))
        { }

        public NameServerAddress(IPEndPoint endPoint)
            : this(null, endPoint)
        { }

        public NameServerAddress(string domainName, IPAddress address, ushort port = 53)
            : this(domainName, new IPEndPoint(address, port))
        { }

        public NameServerAddress(string domainName, IPEndPoint endPoint)
        {
            _domainName = domainName;
            _endPoint = endPoint;
        }

        #endregion

        #region public

        public override string ToString()
        {
            if (string.IsNullOrEmpty(_domainName))
                return _endPoint.Address.ToString();
            else
                return _domainName + " [" + _endPoint.Address.ToString() + "]";
        }

        #endregion

        #region properties

        public string DomainName
        { get { return _domainName; } }

        public IPEndPoint EndPoint
        { get { return _endPoint; } }

        #endregion
    }

    public class DnsDatagram
    {
        #region variables

        NameServerAddress _server;

        DnsHeader _header;

        DnsQuestionRecord[] _question;
        DnsResourceRecord[] _answer;
        DnsResourceRecord[] _authority;
        DnsResourceRecord[] _additional;

        #endregion

        #region constructor

        public DnsDatagram(DnsHeader header, DnsQuestionRecord[] question, DnsResourceRecord[] answer, DnsResourceRecord[] authority, DnsResourceRecord[] additional)
        {
            _header = header;

            _question = question;
            _answer = answer;
            _authority = authority;
            _additional = additional;
        }

        public DnsDatagram(Stream s, NameServerAddress server = null)
        {
            _server = server;
            _header = new DnsHeader(s);

            _question = new DnsQuestionRecord[_header.QDCOUNT];
            for (int i = 0; i < _header.QDCOUNT; i++)
                _question[i] = new DnsQuestionRecord(s);

            _answer = new DnsResourceRecord[_header.ANCOUNT];
            for (int i = 0; i < _header.ANCOUNT; i++)
                _answer[i] = new DnsResourceRecord(s);

            _authority = new DnsResourceRecord[_header.NSCOUNT];
            for (int i = 0; i < _header.NSCOUNT; i++)
                _authority[i] = new DnsResourceRecord(s);

            _additional = new DnsResourceRecord[_header.ARCOUNT];
            for (int i = 0; i < _header.ARCOUNT; i++)
                _additional[i] = new DnsResourceRecord(s);
        }

        #endregion

        #region static

        internal static ushort ReadInt16NetworkOrder(Stream s)
        {
            byte[] b = new byte[2];

            if (s.Read(b, 0, 2) != 2)
                throw new EndOfStreamException();

            Array.Reverse(b);
            return BitConverter.ToUInt16(b, 0);
        }

        internal static void WriteInt16NetworkOrder(ushort value, Stream s)
        {
            byte[] b = BitConverter.GetBytes(value);
            Array.Reverse(b);
            s.Write(b, 0, b.Length);
        }

        internal static uint ReadInt32NetworkOrder(Stream s)
        {
            byte[] b = new byte[4];

            if (s.Read(b, 0, 4) != 4)
                throw new EndOfStreamException();

            Array.Reverse(b);
            return BitConverter.ToUInt32(b, 0);
        }

        internal static void WriteInt32NetworkOrder(uint value, Stream s)
        {
            byte[] b = BitConverter.GetBytes(value);
            Array.Reverse(b);
            s.Write(b, 0, b.Length);
        }

        internal static void ConvertDomainToLabel(string domain, Stream s)
        {
            foreach (string label in domain.Split('.'))
            {
                byte[] Lbl = Encoding.ASCII.GetBytes(label);

                if (Lbl.Length > 63)
                    throw new DnsClientException("ConvertDomainToLabel: Invalid domain name. Label cannot exceed 63 bytes.");

                s.WriteByte(Convert.ToByte(Lbl.Length));
                s.Write(Lbl, 0, Lbl.Length);
            }

            s.WriteByte(Convert.ToByte(0));
        }

        internal static string ConvertLabelToDomain(Stream s)
        {
            StringBuilder domainName = new StringBuilder();
            byte labelLength = Convert.ToByte(s.ReadByte());
            byte[] buffer = new byte[255];

            while (labelLength > 0)
            {
                if ((labelLength & 192) == 192)
                {
                    short Offset = BitConverter.ToInt16(new byte[] { Convert.ToByte(s.ReadByte()), Convert.ToByte((labelLength & 63)) }, 0);
                    long CurrentPosition = s.Position;
                    s.Position = Offset;
                    domainName.Append(ConvertLabelToDomain(s) + ".");
                    s.Position = CurrentPosition;
                    break;
                }
                else
                {
                    s.Read(buffer, 0, labelLength);
                    domainName.Append(Encoding.ASCII.GetString(buffer, 0, labelLength) + ".");
                    labelLength = Convert.ToByte(s.ReadByte());
                }
            }

            if (domainName.Length > 0)
                domainName.Length = domainName.Length - 1;

            return domainName.ToString();
        }

        #endregion

        #region public

        public void WriteTo(Stream s)
        {
            _header.WriteTo(s);

            for (int i = 0; i < _header.QDCOUNT; i++)
                _question[i].WriteTo(s);

            for (int i = 0; i < _header.ANCOUNT; i++)
                _answer[i].WriteTo(s);

            for (int i = 0; i < _header.NSCOUNT; i++)
                _authority[i].WriteTo(s);

            for (int i = 0; i < _header.ARCOUNT; i++)
                _additional[i].WriteTo(s);
        }

        #endregion

        #region properties

        [IgnoreDataMember]
        public NameServerAddress NameServerAddress
        { get { return _server; } }

        public string NameServer
        { get { return _server.DomainName; } }

        public string NameServerIPAddress
        { get { return _server.EndPoint.Address.ToString(); } }

        public DnsHeader Header
        { get { return _header; } }

        public DnsQuestionRecord[] Question
        { get { return _question; } }

        public DnsResourceRecord[] Answer
        { get { return _answer; } }

        public DnsResourceRecord[] Authority
        { get { return _authority; } }

        public DnsResourceRecord[] Additional
        { get { return _additional; } }

        #endregion
    }

    public enum DnsOpcode : byte
    {
        StandardQuery = 0,
        InverseQuery = 1,
        ServerStatusRequest = 2
    }

    public enum DnsResponseCode : byte
    {
        NoError = 0,
        FormatError = 1,
        ServerFailure = 2,
        NameError = 3,
        NotImplemented = 4,
        Refused = 5
    }

    public class DnsHeader
    {
        #region variables

        ushort _ID;

        byte _QR;
        DnsOpcode _OPCODE;
        byte _AA;
        byte _TC;
        byte _RD;
        byte _RA;
        byte _Z;
        DnsResponseCode _RCODE;

        ushort _QDCOUNT;
        ushort _ANCOUNT;
        ushort _NSCOUNT;
        ushort _ARCOUNT;

        #endregion

        #region constructor

        public DnsHeader(ushort ID, bool isResponse, DnsOpcode OPCODE, bool authoritativeAnswer, bool truncation, bool recursionDesired, bool recursionAvailable, DnsResponseCode RCODE, ushort QDCOUNT, ushort ANCOUNT, ushort NSCOUNT, ushort ARCOUNT)
        {
            _ID = ID;

            if (isResponse)
                _QR = 1;

            _OPCODE = OPCODE;

            if (authoritativeAnswer)
                _AA = 1;

            if (truncation)
                _TC = 1;

            if (recursionDesired)
                _RD = 1;

            if (recursionAvailable)
                _RA = 1;

            _RCODE = RCODE;

            _QDCOUNT = QDCOUNT;
            _ANCOUNT = ANCOUNT;
            _NSCOUNT = NSCOUNT;
            _ARCOUNT = ARCOUNT;
        }

        public DnsHeader(Stream s)
        {
            _ID = DnsDatagram.ReadInt16NetworkOrder(s);

            int lB = s.ReadByte();
            _QR = Convert.ToByte((lB & 0x80) >> 7);
            _OPCODE = (DnsOpcode)Convert.ToByte((lB & 0x78) >> 3);
            _AA = Convert.ToByte((lB & 0x4) >> 2);
            _TC = Convert.ToByte((lB & 0x2) >> 1);
            _RD = Convert.ToByte(lB & 0x1);

            int rB = s.ReadByte();
            _RA = Convert.ToByte((rB & 0x80) >> 7);
            _Z = Convert.ToByte((rB & 0x70) >> 4);
            _RCODE = (DnsResponseCode)(rB & 0xf);

            _QDCOUNT = DnsDatagram.ReadInt16NetworkOrder(s);
            _ANCOUNT = DnsDatagram.ReadInt16NetworkOrder(s);
            _NSCOUNT = DnsDatagram.ReadInt16NetworkOrder(s);
            _ARCOUNT = DnsDatagram.ReadInt16NetworkOrder(s);
        }

        #endregion

        #region public

        public void WriteTo(Stream s)
        {
            DnsDatagram.WriteInt16NetworkOrder(_ID, s);
            s.WriteByte(Convert.ToByte((_QR << 7) | ((byte)_OPCODE << 3) | (_AA << 2) | (_TC << 1) | _RD));
            s.WriteByte(Convert.ToByte((_RA << 7) | (_Z << 4) | (byte)_RCODE));
            DnsDatagram.WriteInt16NetworkOrder(_QDCOUNT, s);
            DnsDatagram.WriteInt16NetworkOrder(_ANCOUNT, s);
            DnsDatagram.WriteInt16NetworkOrder(_NSCOUNT, s);
            DnsDatagram.WriteInt16NetworkOrder(_ARCOUNT, s);
        }

        #endregion

        #region properties

        public ushort Identifier
        { get { return _ID; } }

        public bool IsResponse
        { get { return _QR == 1; } }

        public DnsOpcode OPCODE
        { get { return _OPCODE; } }

        public bool AuthoritativeAnswer
        { get { return _AA == 1; } }

        public bool Truncation
        { get { return _TC == 1; } }

        public bool RecursionDesired
        { get { return _RD == 1; } }

        public bool RecursionAvailable
        { get { return _RA == 1; } }

        public byte Z
        { get { return _Z; } }

        public DnsResponseCode RCODE
        { get { return _RCODE; } }

        public ushort QDCOUNT
        { get { return _QDCOUNT; } }

        public ushort ANCOUNT
        { get { return _ANCOUNT; } }

        public ushort NSCOUNT
        { get { return _NSCOUNT; } }

        public ushort ARCOUNT
        { get { return _ARCOUNT; } }

        #endregion
    }

    public class DnsQuestionRecord
    {
        #region variables

        string _name;
        DnsRecordType _type;
        DnsClass _class;

        #endregion

        #region constructor

        public DnsQuestionRecord(string name, DnsRecordType type, DnsClass @class)
        {
            _type = type;
            _class = @class;

            if (_type == DnsRecordType.PTR)
                throw new DnsClientException("Invalid type selected for question record");
            else
                _name = name;
        }

        public DnsQuestionRecord(IPAddress ip, DnsClass @class)
        {
            _type = DnsRecordType.PTR;
            _class = @class;

            byte[] ipBytes = ip.GetAddressBytes();

            switch (ip.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    for (int i = ipBytes.Length - 1; i >= 0; i += -1)
                        _name += ipBytes[i] + ".";

                    _name += "IN-ADDR.ARPA";
                    break;

                case AddressFamily.InterNetworkV6:
                    for (int i = ipBytes.Length - 1; i >= 0; i += -1)
                        _name += (ipBytes[i] & 0x0F).ToString("X") + "." + (ipBytes[i] >> 4).ToString("X") + ".";

                    _name += "IP6.ARPA";
                    break;

                default:
                    throw new DnsClientException("IP address family not supported for PTR query.");
            }
        }

        public DnsQuestionRecord(Stream s)
        {
            _name = DnsDatagram.ConvertLabelToDomain(s);
            _type = (DnsRecordType)DnsDatagram.ReadInt16NetworkOrder(s);
            _class = (DnsClass)DnsDatagram.ReadInt16NetworkOrder(s);
        }

        #endregion

        #region public

        public void WriteTo(Stream s)
        {
            DnsDatagram.ConvertDomainToLabel(_name, s);
            DnsDatagram.WriteInt16NetworkOrder((ushort)_type, s);
            DnsDatagram.WriteInt16NetworkOrder((ushort)_class, s);
        }

        #endregion

        #region properties

        public string Name
        { get { return _name; } }

        public DnsRecordType Type
        { get { return _type; } }

        public DnsClass Class
        { get { return _class; } }

        #endregion
    }

    public class DnsResourceRecord
    {
        #region variables

        string _name;
        DnsRecordType _type;
        DnsClass _class;
        uint _ttl;
        DnsResourceRecordData _data;

        #endregion

        #region constructor

        public DnsResourceRecord(string name, DnsRecordType type, DnsClass @class, uint ttl, DnsResourceRecordData data)
        {
            _name = name;
            _type = type;
            _class = @class;
            _ttl = ttl;
            _data = data;
        }

        public DnsResourceRecord(Stream s)
        {
            _name = DnsDatagram.ConvertLabelToDomain(s);
            _type = (DnsRecordType)DnsDatagram.ReadInt16NetworkOrder(s);
            _class = (DnsClass)DnsDatagram.ReadInt16NetworkOrder(s);
            _ttl = DnsDatagram.ReadInt32NetworkOrder(s);

            switch (_type)
            {
                case DnsRecordType.A:
                    _data = new DnsARecord(s);
                    break;

                case DnsRecordType.NS:
                    _data = new DnsNSRecord(s);
                    break;

                case DnsRecordType.CNAME:
                    _data = new DnsCNAMERecord(s);
                    break;

                case DnsRecordType.SOA:
                    _data = new DnsSOARecord(s);
                    break;

                case DnsRecordType.PTR:
                    _data = new DnsPTRRecord(s);
                    break;

                case DnsRecordType.MX:
                    _data = new DnsMXRecord(s);
                    break;

                case DnsRecordType.TXT:
                    _data = new DnsTXTRecord(s);
                    break;

                case DnsRecordType.AAAA:
                    _data = new DnsAAAARecord(s);
                    break;

                default:
                    _data = new DnsUnknownRecord(s);
                    break;
            }
        }

        #endregion

        #region public

        public void WriteTo(Stream s)
        {
            DnsDatagram.ConvertDomainToLabel(_name, s);
            DnsDatagram.WriteInt16NetworkOrder((ushort)_type, s);
            DnsDatagram.WriteInt16NetworkOrder((ushort)_class, s);
            DnsDatagram.WriteInt32NetworkOrder(_ttl, s);

            _data.WriteTo(s);
        }

        #endregion

        #region properties

        public string Name
        { get { return _name; } }

        public DnsRecordType Type
        { get { return _type; } }

        public DnsClass Class
        { get { return _class; } }

        [IgnoreDataMember]
        public uint TTLValue
        { get { return _ttl; } }

        public string TTL
        { get { return _ttl + " (" + WebUtilities.GetFormattedTime(_ttl) + ")"; } }

        public ushort RDLENGTH
        { get { return _data.RDLENGTH; } }

        public DnsResourceRecordData RDATA
        { get { return _data; } }

        #endregion
    }

    public abstract class DnsResourceRecordData
    {
        #region variables

        protected ushort _length;

        #endregion

        #region constructor

        protected DnsResourceRecordData(ushort length)
        {
            _length = length;
        }

        public DnsResourceRecordData(Stream s)
        {
            //read RDLENGTH
            _length = DnsDatagram.ReadInt16NetworkOrder(s);

            //read RDATA
            Parse(s);
        }

        #endregion

        #region protected

        protected abstract void Parse(Stream s);

        protected abstract void WriteRecordData(Stream s);

        #endregion

        #region public

        public void WriteTo(Stream s)
        {
            if (_length < 1)
            {
                using (MemoryStream mS = new MemoryStream(32))
                {
                    WriteRecordData(mS);

                    //write RDLENGTH
                    _length = Convert.ToUInt16(mS.Length);
                    DnsDatagram.WriteInt16NetworkOrder(_length, s);

                    //write RDATA
                    mS.WriteTo(s);
                }
            }
            else
            {
                //write RDLENGTH
                DnsDatagram.WriteInt16NetworkOrder(_length, s);
                //write RDATA
                WriteRecordData(s);
            }
        }

        #endregion

        #region properties

        [IgnoreDataMember]
        public ushort RDLENGTH
        { get { return _length; } }

        #endregion
    }

    public class DnsUnknownRecord : DnsResourceRecordData
    {
        #region variables

        byte[] _data;

        #endregion

        #region constructor

        public DnsUnknownRecord(byte[] data)
            : base(Convert.ToUInt16(data.Length))
        {
            _data = data;
        }

        public DnsUnknownRecord(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void Parse(Stream s)
        {
            _data = new byte[_length];

            if (s.Read(_data, 0, _length) != _length)
                throw new EndOfStreamException();
        }

        protected override void WriteRecordData(Stream s)
        {
            s.Write(_data, 0, _data.Length);
        }

        #endregion

        #region properties

        public byte[] DATA
        { get { return _data; } }

        #endregion
    }

    public class DnsARecord : DnsResourceRecordData
    {
        #region variables

        IPAddress _address;

        #endregion

        #region constructor

        public DnsARecord(IPAddress address)
            : base(4)
        {
            _address = address;
        }

        public DnsARecord(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void Parse(Stream s)
        {
            byte[] buffer = new byte[4];
            s.Read(buffer, 0, 4);
            _address = new IPAddress(buffer);
        }

        protected override void WriteRecordData(Stream s)
        {
            byte[] addr = _address.GetAddressBytes();
            s.Write(addr, 0, 4);
        }

        #endregion

        #region properties

        [IgnoreDataMember]
        public IPAddress Address
        { get { return _address; } }

        public string IPAddress
        { get { return _address.ToString(); } }

        #endregion
    }

    public class DnsNSRecord : DnsResourceRecordData
    {
        #region variables

        string _nsDomainName;

        #endregion

        #region constructor

        public DnsNSRecord(string nsDomainName)
            : base(0)
        {
            _nsDomainName = nsDomainName;
        }

        public DnsNSRecord(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void Parse(Stream s)
        {
            _nsDomainName = DnsDatagram.ConvertLabelToDomain(s);
        }

        protected override void WriteRecordData(Stream s)
        {
            DnsDatagram.ConvertDomainToLabel(_nsDomainName, s);
        }

        #endregion

        #region properties

        public string NSDomainName
        { get { return _nsDomainName; } }

        #endregion
    }

    public class DnsCNAMERecord : DnsResourceRecordData
    {
        #region variables

        string _cnameDomainName;

        #endregion

        #region constructor

        public DnsCNAMERecord(string cnameDomainName)
            : base(0)
        {
            _cnameDomainName = cnameDomainName;
        }

        public DnsCNAMERecord(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void Parse(Stream s)
        {
            _cnameDomainName = DnsDatagram.ConvertLabelToDomain(s);
        }

        protected override void WriteRecordData(Stream s)
        {
            DnsDatagram.ConvertDomainToLabel(_cnameDomainName, s);
        }

        #endregion

        #region properties

        public string CNAMEDomainName
        { get { return _cnameDomainName; } }

        #endregion
    }

    public class DnsSOARecord : DnsResourceRecordData
    {
        #region variables

        string _masterNameServer;
        string _responsiblePerson;
        uint _serial;
        uint _refresh;
        uint _retry;
        uint _expire;
        uint _minimum;

        #endregion

        #region constructor

        public DnsSOARecord(string masterNameServer, string responsiblePerson, uint serial, uint refresh, uint retry, uint expire, uint minimum)
            : base(0)
        {
            _masterNameServer = masterNameServer;
            _responsiblePerson = responsiblePerson;
            _serial = serial;
            _refresh = refresh;
            _retry = retry;
            _expire = expire;
            _minimum = minimum;
        }

        public DnsSOARecord(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void Parse(Stream s)
        {
            _masterNameServer = DnsDatagram.ConvertLabelToDomain(s);
            _responsiblePerson = DnsDatagram.ConvertLabelToDomain(s);
            _serial = DnsDatagram.ReadInt32NetworkOrder(s);
            _refresh = DnsDatagram.ReadInt32NetworkOrder(s);
            _retry = DnsDatagram.ReadInt32NetworkOrder(s);
            _expire = DnsDatagram.ReadInt32NetworkOrder(s);
            _minimum = DnsDatagram.ReadInt32NetworkOrder(s);
        }

        protected override void WriteRecordData(Stream s)
        {
            DnsDatagram.ConvertDomainToLabel(_masterNameServer, s);
            DnsDatagram.ConvertDomainToLabel(_responsiblePerson, s);
            DnsDatagram.WriteInt32NetworkOrder(_serial, s);
            DnsDatagram.WriteInt32NetworkOrder(_refresh, s);
            DnsDatagram.WriteInt32NetworkOrder(_retry, s);
            DnsDatagram.WriteInt32NetworkOrder(_expire, s);
            DnsDatagram.WriteInt32NetworkOrder(_minimum, s);
        }

        #endregion

        #region properties

        public string MasterNameServer
        { get { return _masterNameServer; } }

        public string ResponsiblePerson
        { get { return _responsiblePerson; } }

        public uint Serial
        { get { return _serial; } }

        public uint Refresh
        { get { return _refresh; } }

        public uint Retry
        { get { return _retry; } }

        public uint Expire
        { get { return _expire; } }

        public uint Minimum
        { get { return _minimum; } }

        #endregion
    }

    public class DnsPTRRecord : DnsResourceRecordData
    {
        #region variables

        string _ptrDomainName;

        #endregion

        #region constructor

        public DnsPTRRecord(string ptrDomainName)
            : base(0)
        {
            _ptrDomainName = ptrDomainName;
        }

        public DnsPTRRecord(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void Parse(Stream s)
        {
            _ptrDomainName = DnsDatagram.ConvertLabelToDomain(s);
        }

        protected override void WriteRecordData(Stream s)
        {
            DnsDatagram.ConvertDomainToLabel(_ptrDomainName, s);
        }

        #endregion

        #region properties

        public string PTRDomainName
        { get { return _ptrDomainName; } }

        #endregion
    }

    public class DnsMXRecord : DnsResourceRecordData
    {
        #region variables

        ushort _preference;
        string _exchange;

        #endregion

        #region constructor

        public DnsMXRecord(ushort preference, string exchange)
            : base(0)
        {
            _preference = preference;
            _exchange = exchange;
        }

        public DnsMXRecord(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void Parse(Stream s)
        {
            _preference = DnsDatagram.ReadInt16NetworkOrder(s);
            _exchange = DnsDatagram.ConvertLabelToDomain(s);
        }

        protected override void WriteRecordData(Stream s)
        {
            DnsDatagram.WriteInt16NetworkOrder(_preference, s);
            DnsDatagram.ConvertDomainToLabel(_exchange, s);
        }

        #endregion

        #region properties

        public ushort Preference
        { get { return _preference; } }

        public string Exchange
        { get { return _exchange; } }

        #endregion
    }

    public class DnsTXTRecord : DnsResourceRecordData
    {
        #region variables

        string _txtData;

        #endregion

        #region constructor

        public DnsTXTRecord(string txtData)
            : base(Convert.ToUInt16(1 + txtData.Length))
        {
            _txtData = txtData;
        }

        public DnsTXTRecord(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void Parse(Stream s)
        {
            int length = s.ReadByte();
            if (length < 0)
                throw new EndOfStreamException();

            byte[] data = new byte[length];
            s.Read(data, 0, length);
            _txtData = Encoding.ASCII.GetString(data, 0, length);
        }

        protected override void WriteRecordData(Stream s)
        {
            byte[] data = Encoding.ASCII.GetBytes(_txtData);

            s.WriteByte(Convert.ToByte(data.Length));
            s.Write(data, 0, data.Length);
        }

        #endregion

        #region properties

        public string TXTData
        { get { return _txtData; } }

        #endregion
    }

    public class DnsAAAARecord : DnsResourceRecordData
    {
        #region variables

        IPAddress _address;

        #endregion

        #region constructor

        public DnsAAAARecord(IPAddress address)
            : base(16)
        {
            _address = address;
        }

        #endregion

        #region static

        public DnsAAAARecord(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void Parse(Stream s)
        {
            byte[] buffer = new byte[16];
            s.Read(buffer, 0, 16);
            _address = new IPAddress(buffer);
        }

        protected override void WriteRecordData(Stream s)
        {
            byte[] addr = _address.GetAddressBytes();
            s.Write(addr, 0, 16);
        }

        #endregion

        #region properties

        [IgnoreDataMember]
        public IPAddress Address
        { get { return _address; } }

        public string IPAddress
        { get { return _address.ToString(); } }

        #endregion
    }

    public class DnsClientException : Exception
    {
        #region constructors

        public DnsClientException()
            : base()
        { }

        public DnsClientException(string message)
            : base(message)
        { }

        public DnsClientException(string message, Exception innerException)
            : base(message, innerException)
        { }

        protected DnsClientException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context)
            : base(info, context)
        { }

        #endregion
    }

    public class NameErrorDnsClientException : DnsClientException
    {
        #region constructors

        public NameErrorDnsClientException()
            : base()
        { }

        public NameErrorDnsClientException(string message)
            : base(message)
        { }

        public NameErrorDnsClientException(string message, Exception innerException)
            : base(message, innerException)
        { }

        protected NameErrorDnsClientException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context)
            : base(info, context)
        { }

        #endregion
    }
}
