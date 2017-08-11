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
using System.IO;
using System.Net;
using System.Net.Mail;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;

namespace TechnitiumLibrary.Net
{
    public enum DnsResourceRecordType : ushort
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
        OPT = 41,
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
        SMIMEA = 53,
        HIP = 55,
        NINFO = 56,
        RKEY = 57,
        TALINK = 58,
        CDS = 59,
        CDNSKEY = 60,
        OPENPGPKEY = 61,
        CSYNC = 62,
        SPF = 99,
        UINFO = 100,
        UID = 101,
        GID = 102,
        UNSPEC = 103,
        NID = 104,
        L32 = 105,
        L64 = 106,
        LP = 107,
        EUI48 = 108,
        EUI64 = 109,
        TKEY = 249,
        TSIG = 250,
        IXFR = 251,
        AXFR = 252,
        MAILB = 253,
        MAILA = 254,
        ANY = 255,
        URI = 256,
        CAA = 257,
        AVC = 258,
        TA = 32768,
        DLV = 32769
    }

    public enum DnsClass : ushort
    {
        IN = 1, //the Internet
        CS = 2, //the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
        CH = 3, //the CHAOS class
        HS = 4, //Hesiod

        NONE = 254,
        ANY = 255
    }

    public class DnsClient
    {
        #region variables

        public static readonly NameServerAddress[] ROOT_NAME_SERVERS_IPv4;
        public static readonly NameServerAddress[] ROOT_NAME_SERVERS_IPv6;

        internal static RandomNumberGenerator _rnd = new RNGCryptoServiceProvider();

        NameServerAddress[] _servers;
        bool _enableIPv6;
        bool _tcp;
        int _retries;

        int _connectionTimeout = 5000;
        int _sendTimeout = 2000;
        int _recvTimeout = 2000;

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

        public DnsClient(bool enableIPv6 = false, bool tcp = false, int retries = 2, ushort port = 53)
        {
            NetworkInfo defaultNetworkInfo = NetUtilities.GetDefaultNetworkInfo();
            if (defaultNetworkInfo == null)
                throw new DnsClientException("No default network connection was found on this computer.");

            IPAddressCollection servers = defaultNetworkInfo.Interface.GetIPProperties().DnsAddresses;

            if (servers.Count == 0)
                throw new DnsClientException("Default network does not have any DNS server configured.");

            _servers = new NameServerAddress[servers.Count];
            _enableIPv6 = enableIPv6;
            _tcp = tcp;
            _retries = retries;

            for (int i = 0; i < servers.Count; i++)
                _servers[i] = new NameServerAddress(servers[i], port);
        }

        public DnsClient(IPAddress[] servers, bool enableIPv6 = false, bool tcp = false, int retries = 2, ushort port = 53)
        {
            if (servers.Length == 0)
                throw new DnsClientException("Atleast one name server must be available for Dns Client.");

            _servers = new NameServerAddress[servers.Length];
            _enableIPv6 = enableIPv6;
            _tcp = tcp;
            _retries = retries;

            for (int i = 0; i < servers.Length; i++)
                _servers[i] = new NameServerAddress(servers[i], port);
        }

        public DnsClient(IPAddress server, bool enableIPv6 = false, bool tcp = false, int retries = 2, ushort port = 53)
            : this(new NameServerAddress(server, port), enableIPv6, tcp, retries)
        { }

        public DnsClient(IPEndPoint server, bool enableIPv6 = false, bool tcp = false, int retries = 2)
            : this(new NameServerAddress(server), enableIPv6, tcp, retries)
        { }

        public DnsClient(NameServerAddress server, bool enableIPv6 = false, bool tcp = false, int retries = 2)
        {
            _servers = new NameServerAddress[] { server };
            _tcp = tcp;
            _retries = retries;
        }

        public DnsClient(NameServerAddress[] servers, bool enableIPv6 = false, bool tcp = false, int retries = 2)
        {
            if (servers.Length == 0)
                throw new DnsClientException("Atleast one name server must be available for Dns Client.");

            _servers = servers;
            _enableIPv6 = enableIPv6;
            _tcp = tcp;
            _retries = retries;
        }

        #endregion

        #region static

        public static DnsDatagram ResolveViaRootNameServers(string domain, DnsResourceRecordType queryType, bool enableIPv6 = false, bool tcp = false, int retries = 2)
        {
            if (enableIPv6)
                return ResolveViaNameServers(ROOT_NAME_SERVERS_IPv6, domain, queryType, enableIPv6, tcp, retries);
            else
                return ResolveViaNameServers(ROOT_NAME_SERVERS_IPv4, domain, queryType, enableIPv6, tcp, retries);
        }

        public static DnsDatagram ResolveViaNameServers(NameServerAddress[] nameServers, string domain, DnsResourceRecordType queryType, bool enableIPv6 = false, bool tcp = false, int retries = 2)
        {
            int hopCount = 0;
            IPAddress ptrIP = null;

            if (queryType == DnsResourceRecordType.PTR)
                ptrIP = IPAddress.Parse(domain);

            while ((hopCount++) < 64)
            {
                DnsClient client = new DnsClient(nameServers, enableIPv6, tcp, retries);

                DnsDatagram response;

                if (queryType == DnsResourceRecordType.PTR)
                    response = client.Resolve(new DnsQuestionRecord(ptrIP, DnsClass.IN));
                else
                    response = client.Resolve(new DnsQuestionRecord(domain, queryType, DnsClass.IN));

                switch (response.Header.RCODE)
                {
                    case DnsResponseCode.NoError:
                        if (response.Answer.Length > 0)
                            return response;

                        if (response.Authority.Length == 0)
                            return response;

                        nameServers = NameServerAddress.GetNameServersFromResponse(response, enableIPv6);

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

        private DnsDatagram Resolve(DnsDatagram request)
        {
            int bytesRecv;
            byte[] responseBuffer = new byte[64 * 1024];
            int nextServerIndex = 0;
            int retries = _retries;
            byte[] requestBuffer;

            //serialize request
            using (MemoryStream mS = new MemoryStream(32))
            {
                if (_tcp)
                    mS.Position = 2;

                //write dns datagram
                request.WriteTo(mS);

                requestBuffer = mS.ToArray();

                if (_tcp)
                {
                    byte[] length = BitConverter.GetBytes(Convert.ToInt16(requestBuffer.Length - 2));

                    requestBuffer[0] = length[1];
                    requestBuffer[1] = length[0];
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

                if (server.EndPoint == null)
                {
                    server.ResolveAddress(_enableIPv6, _tcp, _retries);

                    if (server.EndPoint == null)
                    {
                        retry++;
                        continue;
                    }
                }

                //query server
                Socket _socket = null;
                double rtt;

                try
                {
                    retry++;

                    if (_tcp)
                    {
                        _socket = new Socket(server.EndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                        _socket.NoDelay = true;
                        _socket.SendTimeout = _sendTimeout;
                        _socket.ReceiveTimeout = _recvTimeout;

                        DateTime sentAt = DateTime.UtcNow;

                        IAsyncResult result = _socket.BeginConnect(server.EndPoint, null, null);
                        if (!result.AsyncWaitHandle.WaitOne(_connectionTimeout))
                            throw new SocketException((int)SocketError.TimedOut);

                        _socket.Send(requestBuffer);

                        bytesRecv = _socket.Receive(responseBuffer, 0, 2, SocketFlags.None);
                        if (bytesRecv < 1)
                            throw new SocketException();

                        Array.Reverse(responseBuffer, 0, 2);
                        short length = BitConverter.ToInt16(responseBuffer, 0);

                        int offset = 0;
                        while (offset < length)
                        {
                            bytesRecv = _socket.Receive(responseBuffer, offset, length, SocketFlags.None);
                            if (bytesRecv < 1)
                                throw new SocketException();

                            offset += bytesRecv;
                        }

                        bytesRecv = length;
                        rtt = (DateTime.UtcNow - sentAt).TotalMilliseconds;
                    }
                    else
                    {
                        _socket = new Socket(server.EndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);

                        _socket.SendTimeout = _sendTimeout;
                        _socket.ReceiveTimeout = _recvTimeout;

                        DateTime sentAt = DateTime.UtcNow;
                        _socket.SendTo(requestBuffer, server.EndPoint);

                        EndPoint remoteEP;

                        if (server.EndPoint.AddressFamily == AddressFamily.InterNetworkV6)
                            remoteEP = new IPEndPoint(IPAddress.IPv6Any, 0);
                        else
                            remoteEP = new IPEndPoint(IPAddress.Any, 0);

                        bytesRecv = _socket.ReceiveFrom(responseBuffer, ref remoteEP);
                        rtt = (DateTime.UtcNow - sentAt).TotalMilliseconds;
                    }

                    //parse response
                    using (MemoryStream mS = new MemoryStream(responseBuffer, 0, bytesRecv, false))
                    {
                        DnsDatagram response = new DnsDatagram(mS, server, (_tcp ? ProtocolType.Tcp : ProtocolType.Udp), rtt);

                        if (response.Header.Identifier == request.Header.Identifier)
                            return response;
                    }
                }
                catch (SocketException)
                { }
                finally
                {
                    if (_socket != null)
                        _socket.Dispose();
                }
            }

            throw new DnsClientException("Dns Client failed to resolve the request: exceeded retry limit.");
        }

        #endregion

        #region public

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

            while ((hopCount++) < 64)
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
                                        throw new DnsClientException("DNS Server [" + response.NameServerAddress.ToString() + "] returned unexpected record type [ " + record.Type.ToString() + "] for domain: " + domain);
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
                                                    mxEntries.Add(((DnsARecord)record.RDATA).Address.ToString());
                                                    glueRecordFound = true;
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
                        throw new NameErrorDnsClientException("Domain does not exists: " + domain + "; Name Server: " + response.NameServerAddress.ToString());

                    default:
                        throw new DnsClientException("Name Server error. DNS opcode: " + Enum.GetName(typeof(DnsResponseCode), response.Header.RCODE) + " (" + response.Header.RCODE + ")");
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
                    throw new NameErrorDnsClientException("PTR record does not exists for ip: " + ip.ToString() + "; Name Server: " + response.NameServerAddress.ToString());

                default:
                    throw new DnsClientException("Name Server error. DNS opcode: " + Enum.GetName(typeof(DnsResponseCode), response.Header.RCODE) + " (" + response.Header.RCODE + ")");
            }
        }

        public IPAddress[] ResolveIP(string domain, bool preferIPv6 = false)
        {
            int hopCount = 0;
            DnsResourceRecordType type = preferIPv6 ? DnsResourceRecordType.AAAA : DnsResourceRecordType.A;

            while ((hopCount++) < 64)
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
                                        throw new DnsClientException("DNS Server [" + response.NameServerAddress.ToString() + "] returned unexpected record type [ " + record.Type.ToString() + "] for domain: " + domain);
                                }
                            }
                        }

                        if (ipAddresses.Count > 0)
                            return ipAddresses.ToArray();

                        break;

                    case DnsResponseCode.NameError:
                        throw new NameErrorDnsClientException("Domain does not exists: " + domain + "; Name Server: " + response.NameServerAddress.ToString());

                    default:
                        throw new DnsClientException("Name Server error. DNS opcode: " + Enum.GetName(typeof(DnsResponseCode), response.Header.RCODE) + " (" + response.Header.RCODE + ")");
                }
            }

            throw new DnsClientException("No answer received from name server for domain: " + domain);
        }

        #endregion

        #region property

        public NameServerAddress[] Servers
        { get { return _servers; } }

        public bool EnableIPv6
        {
            get { return _enableIPv6; }
            set { _enableIPv6 = value; }
        }

        public bool Tcp
        {
            get { return _tcp; }
            set { _tcp = value; }
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

        public int Retries
        {
            get { return _retries; }
            set { _retries = value; }
        }

        #endregion
    }

    public class NameServerAddress
    {
        #region variables

        string _domain;
        IPEndPoint _endPoint;

        #endregion

        #region constructors

        public NameServerAddress(IPAddress address, ushort port = 53)
            : this(null, new IPEndPoint(address, port))
        { }

        public NameServerAddress(IPEndPoint endPoint)
            : this(null, endPoint)
        { }

        public NameServerAddress(string domain)
            : this(domain, null)
        { }

        public NameServerAddress(string domain, IPAddress address, ushort port = 53)
            : this(domain, new IPEndPoint(address, port))
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

        public static NameServerAddress[] GetNameServersFromResponse(DnsDatagram response, bool enableIPv6)
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
                        if (rr.Name.Equals(nsRecord.NSDomainName, StringComparison.CurrentCultureIgnoreCase))
                        {
                            switch (rr.Type)
                            {
                                case DnsResourceRecordType.A:
                                    endPoint = new IPEndPoint(((DnsARecord)rr.RDATA).Address, 53);
                                    nameServers.Add(new NameServerAddress(nsRecord.NSDomainName, endPoint));
                                    break;

                                case DnsResourceRecordType.AAAA:
                                    if (enableIPv6)
                                    {
                                        endPoint = new IPEndPoint(((DnsAAAARecord)rr.RDATA).Address, 53);
                                        nameServers.Add(new NameServerAddress(nsRecord.NSDomainName, endPoint));
                                    }
                                    break;
                            }
                        }
                    }

                    if (endPoint == null)
                        nameServers.Add(new NameServerAddress(nsRecord.NSDomainName));
                }
            }

            return nameServers.ToArray();
        }

        #endregion

        #region public

        public void ResolveAddress(bool enableIPv6, bool tcp, int retries)
        {
            if ((_domain != null) && (_endPoint == null))
            {
                try
                {
                    if (enableIPv6)
                    {
                        DnsDatagram nsResponse = DnsClient.ResolveViaRootNameServers(_domain, DnsResourceRecordType.AAAA, true, tcp, retries);
                        if ((nsResponse.Header.RCODE == DnsResponseCode.NoError) && (nsResponse.Answer.Length > 0) && (nsResponse.Answer[0].Type == DnsResourceRecordType.AAAA))
                            _endPoint = new IPEndPoint((nsResponse.Answer[0].RDATA as DnsAAAARecord).Address, 53);
                    }

                    if (_endPoint == null)
                    {
                        DnsDatagram nsResponse = DnsClient.ResolveViaRootNameServers(_domain, DnsResourceRecordType.A, false, tcp, retries);
                        if ((nsResponse.Header.RCODE == DnsResponseCode.NoError) && (nsResponse.Answer.Length > 0) && (nsResponse.Answer[0].Type == DnsResourceRecordType.A))
                            _endPoint = new IPEndPoint((nsResponse.Answer[0].RDATA as DnsARecord).Address, 53);
                    }
                }
                catch
                { }
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

    public class DnsDatagram
    {
        #region variables

        NameServerAddress _server;
        ProtocolType _protocol;
        long _size;
        double _rtt;

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

        public DnsDatagram(Stream s, NameServerAddress server = null, ProtocolType protocol = ProtocolType.Udp, double rtt = 0)
        {
            _server = server;
            _protocol = protocol;
            _size = s.Length;
            _rtt = rtt;
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

        internal static ushort ReadUInt16NetworkOrder(Stream s)
        {
            byte[] b = new byte[2];

            if (s.Read(b, 0, 2) != 2)
                throw new EndOfStreamException();

            Array.Reverse(b);
            return BitConverter.ToUInt16(b, 0);
        }

        internal static void WriteUInt16NetworkOrder(ushort value, Stream s)
        {
            byte[] b = BitConverter.GetBytes(value);
            Array.Reverse(b);
            s.Write(b, 0, b.Length);
        }

        internal static uint ReadUInt32NetworkOrder(Stream s)
        {
            byte[] b = new byte[4];

            if (s.Read(b, 0, 4) != 4)
                throw new EndOfStreamException();

            Array.Reverse(b);
            return BitConverter.ToUInt32(b, 0);
        }

        internal static void WriteUInt32NetworkOrder(uint value, Stream s)
        {
            byte[] b = BitConverter.GetBytes(value);
            Array.Reverse(b);
            s.Write(b, 0, b.Length);
        }

        internal static void ConvertDomainToLabel(string domain, Stream s, List<DnsDomainOffset> domainEntries)
        {
            while (!string.IsNullOrEmpty(domain))
            {
                //search domain list
                foreach (DnsDomainOffset domainEntry in domainEntries)
                {
                    if (domain.Equals(domainEntry.Domain, StringComparison.CurrentCultureIgnoreCase))
                    {
                        //found matching domain offset for compression
                        ushort pointer = 0xC000;
                        pointer |= domainEntry.Offset;

                        byte[] pointerBytes = BitConverter.GetBytes(pointer);
                        Array.Reverse(pointerBytes); //convert to network order

                        //write pointer
                        s.Write(pointerBytes, 0, 2);
                        return;
                    }
                }

                domainEntries.Add(new DnsDomainOffset(Convert.ToUInt16(s.Position), domain));

                string label;
                int i = domain.IndexOf('.');
                if (i < 0)
                {
                    label = domain;
                    domain = null;
                }
                else
                {
                    label = domain.Substring(0, i);
                    domain = domain.Substring(i + 1);
                }

                byte[] labelBytes = Encoding.ASCII.GetBytes(label);
                if (labelBytes.Length > 63)
                    throw new DnsClientException("ConvertDomainToLabel: Invalid domain name. Label cannot exceed 63 bytes.");

                s.WriteByte(Convert.ToByte(labelBytes.Length));
                s.Write(labelBytes, 0, labelBytes.Length);
            }

            s.WriteByte(Convert.ToByte(0));
        }

        internal static string ConvertLabelToDomain(Stream s)
        {
            StringBuilder domain = new StringBuilder();
            byte labelLength = Convert.ToByte(s.ReadByte());
            byte[] buffer = new byte[255];

            while (labelLength > 0)
            {
                if ((labelLength & 0xC0) == 0xC0)
                {
                    short Offset = BitConverter.ToInt16(new byte[] { Convert.ToByte(s.ReadByte()), Convert.ToByte((labelLength & 0x3F)) }, 0);
                    long CurrentPosition = s.Position;
                    s.Position = Offset;
                    domain.Append(ConvertLabelToDomain(s) + ".");
                    s.Position = CurrentPosition;
                    break;
                }
                else
                {
                    s.Read(buffer, 0, labelLength);
                    domain.Append(Encoding.ASCII.GetString(buffer, 0, labelLength) + ".");
                    labelLength = Convert.ToByte(s.ReadByte());
                }
            }

            if (domain.Length > 0)
                domain.Length = domain.Length - 1;

            return domain.ToString();
        }

        #endregion

        #region public

        public void WriteTo(Stream s)
        {
            _header.WriteTo(s);

            List<DnsDomainOffset> domainEntries = new List<DnsDomainOffset>(1);

            for (int i = 0; i < _header.QDCOUNT; i++)
                _question[i].WriteTo(s, domainEntries);

            for (int i = 0; i < _header.ANCOUNT; i++)
                _answer[i].WriteTo(s, domainEntries);

            for (int i = 0; i < _header.NSCOUNT; i++)
                _authority[i].WriteTo(s, domainEntries);

            for (int i = 0; i < _header.ARCOUNT; i++)
                _additional[i].WriteTo(s, domainEntries);
        }

        #endregion

        #region properties

        [IgnoreDataMember]
        public NameServerAddress NameServerAddress
        { get { return _server; } }

        public string NameServer
        { get { return _server.Domain; } }

        public string NameServerIPAddress
        { get { return _server.EndPoint.Address.ToString(); } }

        public ProtocolType Protocol
        { get { return _protocol; } }

        [IgnoreDataMember]
        public long Size
        { get { return _size; } }

        public string DatagramSize
        { get { return _size + " bytes"; } }

        [IgnoreDataMember]
        public double RTT
        { get { return _rtt; } }

        public string RoundTripTime
        { get { return Math.Round(_rtt, 2) + " ms"; } }

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

    public class DnsDomainOffset
    {
        #region variables

        ushort _offset;
        string _domain;

        #endregion

        #region constructor

        public DnsDomainOffset(ushort offset, string domain)
        {
            _offset = offset;
            _domain = domain;
        }

        #endregion

        #region public

        public override string ToString()
        {
            return _domain;
        }

        #endregion

        #region properties

        public ushort Offset
        { get { return _offset; } }

        public string Domain
        { get { return _domain; } }

        #endregion
    }

    public enum DnsOpcode : byte
    {
        StandardQuery = 0,
        InverseQuery = 1,
        ServerStatusRequest = 2,
        Notify = 4,
        Update = 5
    }

    public enum DnsResponseCode : byte
    {
        NoError = 0,
        FormatError = 1,
        ServerFailure = 2,
        NameError = 3,
        NotImplemented = 4,
        Refused = 5,
        YXDomain = 6,
        YXRRSet = 7,
        NXRRSet = 8,
        NotAuthorized = 9,
        NotZone = 10,
        BADSIG = 16,
        BADKEY = 17,
        BADTIME = 18,
        BADMODE = 19,
        BADNAME = 20,
        BADALG = 21,
        BADTRUNC = 22,
        BADCOOKIE = 23
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
        byte _AD;
        byte _CD;
        DnsResponseCode _RCODE;

        ushort _QDCOUNT;
        ushort _ANCOUNT;
        ushort _NSCOUNT;
        ushort _ARCOUNT;

        #endregion

        #region constructor

        public DnsHeader(ushort ID, bool isResponse, DnsOpcode OPCODE, bool authoritativeAnswer, bool truncation, bool recursionDesired, bool recursionAvailable, bool authenticData, bool checkingDisabled, DnsResponseCode RCODE, ushort QDCOUNT, ushort ANCOUNT, ushort NSCOUNT, ushort ARCOUNT)
        {
            _ID = ID;

            if (_ID == 0)
            {
                byte[] buffer = new byte[2];
                DnsClient._rnd.GetBytes(buffer);

                _ID = BitConverter.ToUInt16(buffer, 0);
            }

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

            if (authenticData)
                _AD = 1;

            if (checkingDisabled)
                _CD = 1;

            _RCODE = RCODE;

            _QDCOUNT = QDCOUNT;
            _ANCOUNT = ANCOUNT;
            _NSCOUNT = NSCOUNT;
            _ARCOUNT = ARCOUNT;
        }

        public DnsHeader(Stream s)
        {
            _ID = DnsDatagram.ReadUInt16NetworkOrder(s);

            int lB = s.ReadByte();
            _QR = Convert.ToByte((lB & 0x80) >> 7);
            _OPCODE = (DnsOpcode)Convert.ToByte((lB & 0x78) >> 3);
            _AA = Convert.ToByte((lB & 0x4) >> 2);
            _TC = Convert.ToByte((lB & 0x2) >> 1);
            _RD = Convert.ToByte(lB & 0x1);

            int rB = s.ReadByte();
            _RA = Convert.ToByte((rB & 0x80) >> 7);
            _Z = Convert.ToByte((rB & 0x40) >> 6);
            _AD = Convert.ToByte((rB & 0x20) >> 5);
            _CD = Convert.ToByte((rB & 0x10) >> 4);
            _RCODE = (DnsResponseCode)(rB & 0xf);

            _QDCOUNT = DnsDatagram.ReadUInt16NetworkOrder(s);
            _ANCOUNT = DnsDatagram.ReadUInt16NetworkOrder(s);
            _NSCOUNT = DnsDatagram.ReadUInt16NetworkOrder(s);
            _ARCOUNT = DnsDatagram.ReadUInt16NetworkOrder(s);
        }

        #endregion

        #region public

        public void WriteTo(Stream s)
        {
            DnsDatagram.WriteUInt16NetworkOrder(_ID, s);
            s.WriteByte(Convert.ToByte((_QR << 7) | ((byte)_OPCODE << 3) | (_AA << 2) | (_TC << 1) | _RD));
            s.WriteByte(Convert.ToByte((_RA << 7) | (_Z << 6) | (_AD << 5) | (_CD << 4) | (byte)_RCODE));
            DnsDatagram.WriteUInt16NetworkOrder(_QDCOUNT, s);
            DnsDatagram.WriteUInt16NetworkOrder(_ANCOUNT, s);
            DnsDatagram.WriteUInt16NetworkOrder(_NSCOUNT, s);
            DnsDatagram.WriteUInt16NetworkOrder(_ARCOUNT, s);
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

        public bool AuthenticData
        { get { return _AD == 1; } }

        public bool CheckingDisabled
        { get { return _CD == 1; } }

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
        DnsResourceRecordType _type;
        DnsClass _class;

        #endregion

        #region constructor

        public DnsQuestionRecord(string name, DnsResourceRecordType type, DnsClass @class)
        {
            _type = type;
            _class = @class;

            if (_type == DnsResourceRecordType.PTR)
                throw new DnsClientException("Invalid type selected for question record");
            else
                _name = name;
        }

        public DnsQuestionRecord(IPAddress ip, DnsClass @class)
        {
            _type = DnsResourceRecordType.PTR;
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
            _type = (DnsResourceRecordType)DnsDatagram.ReadUInt16NetworkOrder(s);
            _class = (DnsClass)DnsDatagram.ReadUInt16NetworkOrder(s);
        }

        #endregion

        #region public

        public void WriteTo(Stream s, List<DnsDomainOffset> domainEntries)
        {
            DnsDatagram.ConvertDomainToLabel(_name, s, domainEntries);
            DnsDatagram.WriteUInt16NetworkOrder((ushort)_type, s);
            DnsDatagram.WriteUInt16NetworkOrder((ushort)_class, s);
        }

        #endregion

        #region properties

        public string Name
        { get { return _name; } }

        public DnsResourceRecordType Type
        { get { return _type; } }

        public DnsClass Class
        { get { return _class; } }

        #endregion
    }

    public class DnsResourceRecord
    {
        #region variables

        string _name;
        DnsResourceRecordType _type;
        DnsClass _class;
        uint _ttl;
        DnsResourceRecordData _data;

        bool _setExpiry = false;
        DateTime _dateExpires;

        #endregion

        #region constructor

        public DnsResourceRecord(string name, DnsResourceRecordType type, DnsClass @class, uint ttl, DnsResourceRecordData data)
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
            _type = (DnsResourceRecordType)DnsDatagram.ReadUInt16NetworkOrder(s);
            _class = (DnsClass)DnsDatagram.ReadUInt16NetworkOrder(s);
            _ttl = DnsDatagram.ReadUInt32NetworkOrder(s);

            switch (_type)
            {
                case DnsResourceRecordType.A:
                    _data = new DnsARecord(s);
                    break;

                case DnsResourceRecordType.NS:
                    _data = new DnsNSRecord(s);
                    break;

                case DnsResourceRecordType.CNAME:
                    _data = new DnsCNAMERecord(s);
                    break;

                case DnsResourceRecordType.SOA:
                    _data = new DnsSOARecord(s);
                    break;

                case DnsResourceRecordType.PTR:
                    _data = new DnsPTRRecord(s);
                    break;

                case DnsResourceRecordType.MX:
                    _data = new DnsMXRecord(s);
                    break;

                case DnsResourceRecordType.TXT:
                    _data = new DnsTXTRecord(s);
                    break;

                case DnsResourceRecordType.AAAA:
                    _data = new DnsAAAARecord(s);
                    break;

                default:
                    _data = new DnsUnknownRecord(s);
                    break;
            }
        }

        #endregion

        #region public

        public void SetExpiry()
        {
            _setExpiry = true;
            _dateExpires = DateTime.UtcNow.AddSeconds(_ttl);
        }

        public void WriteTo(Stream s, List<DnsDomainOffset> domainEntries)
        {
            DnsDatagram.ConvertDomainToLabel(_name, s, domainEntries);
            DnsDatagram.WriteUInt16NetworkOrder((ushort)_type, s);
            DnsDatagram.WriteUInt16NetworkOrder((ushort)_class, s);
            DnsDatagram.WriteUInt32NetworkOrder(TTLValue, s);

            _data.WriteTo(s, domainEntries);
        }

        #endregion

        #region properties

        public string Name
        { get { return _name; } }

        public DnsResourceRecordType Type
        { get { return _type; } }

        public DnsClass Class
        { get { return _class; } }

        [IgnoreDataMember]
        public uint TTLValue
        {
            get
            {
                if (_setExpiry)
                {
                    DateTime currentDate = DateTime.UtcNow;

                    if (currentDate > _dateExpires)
                        return 0u;
                    else
                        return Convert.ToUInt32((_dateExpires - DateTime.UtcNow).TotalSeconds);
                }
                else
                {
                    return _ttl;
                }
            }
        }

        public string TTL
        { get { return this.TTLValue + " (" + WebUtilities.GetFormattedTime(this.TTLValue) + ")"; } }

        public string RDLENGTH
        { get { return _data.RDLENGTH + " bytes"; } }

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

        protected DnsResourceRecordData()
        { }

        public DnsResourceRecordData(Stream s)
        {
            //read RDLENGTH
            _length = DnsDatagram.ReadUInt16NetworkOrder(s);

            //read RDATA
            Parse(s);
        }

        #endregion

        #region protected

        protected abstract void Parse(Stream s);

        protected abstract void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries);

        #endregion

        #region public

        public void WriteTo(Stream s, List<DnsDomainOffset> domainEntries)
        {
            long originalPosition = s.Position;

            //write dummy RDLENGTH
            s.Write(new byte[] { 0, 0 }, 0, 2);

            //write RDATA
            WriteRecordData(s, domainEntries);

            long finalPosition = s.Position;

            //write actual RDLENGTH
            ushort length = Convert.ToUInt16(finalPosition - originalPosition - 2);
            s.Position = originalPosition;
            DnsDatagram.WriteUInt16NetworkOrder(length, s);

            s.Position = finalPosition;
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

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
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

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
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

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
        {
            DnsDatagram.ConvertDomainToLabel(_nsDomainName, s, domainEntries);
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

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
        {
            DnsDatagram.ConvertDomainToLabel(_cnameDomainName, s, domainEntries);
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
            _serial = DnsDatagram.ReadUInt32NetworkOrder(s);
            _refresh = DnsDatagram.ReadUInt32NetworkOrder(s);
            _retry = DnsDatagram.ReadUInt32NetworkOrder(s);
            _expire = DnsDatagram.ReadUInt32NetworkOrder(s);
            _minimum = DnsDatagram.ReadUInt32NetworkOrder(s);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
        {
            DnsDatagram.ConvertDomainToLabel(_masterNameServer, s, domainEntries);
            DnsDatagram.ConvertDomainToLabel(_responsiblePerson, s, domainEntries);
            DnsDatagram.WriteUInt32NetworkOrder(_serial, s);
            DnsDatagram.WriteUInt32NetworkOrder(_refresh, s);
            DnsDatagram.WriteUInt32NetworkOrder(_retry, s);
            DnsDatagram.WriteUInt32NetworkOrder(_expire, s);
            DnsDatagram.WriteUInt32NetworkOrder(_minimum, s);
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

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
        {
            DnsDatagram.ConvertDomainToLabel(_ptrDomainName, s, domainEntries);
        }

        #endregion

        #region properties

        public string PTRDomainName
        { get { return _ptrDomainName; } }

        #endregion
    }

    public class DnsMXRecord : DnsResourceRecordData, IComparable<DnsMXRecord>
    {
        #region variables

        ushort _preference;
        string _exchange;

        #endregion

        #region constructor

        public DnsMXRecord(ushort preference, string exchange)
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
            _preference = DnsDatagram.ReadUInt16NetworkOrder(s);
            _exchange = DnsDatagram.ConvertLabelToDomain(s);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
        {
            DnsDatagram.WriteUInt16NetworkOrder(_preference, s);
            DnsDatagram.ConvertDomainToLabel(_exchange, s, domainEntries);
        }

        #endregion

        #region public

        public int CompareTo(DnsMXRecord other)
        {
            return _preference.CompareTo(other._preference);
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

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
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

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
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
