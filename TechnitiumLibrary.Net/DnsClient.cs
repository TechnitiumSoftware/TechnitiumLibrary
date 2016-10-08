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
using System.Collections.ObjectModel;
using System.IO;
using System.Net;
using System.Net.Mail;
using System.Net.Sockets;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;

namespace TechnitiumLibrary.Net
{
    public enum DnsRecordType : short
    {
        A = 1,
        NS = 2,
        CNAME = 5,
        SOA = 6,
        PTR = 12,
        MX = 15,
        TXT = 16,
        AAAA = 28,
        ANY = 255
    }

    public enum DnsClass : short
    {
        Internet = 1
    }

    public class DnsClient : IDisposable
    {
        #region variables

        static readonly string[] ROOTSERVERS = new string[] { "198.41.0.4", "192.228.79.201", "192.33.4.12", "199.7.91.13", "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42", "202.12.27.33" };

        static RandomNumberGenerator _rnd = new RNGCryptoServiceProvider();

        Socket _socket;
        IPEndPoint _server;

        #endregion

        #region constructor

        public DnsClient(string server, ushort port = 53, bool tcp = false)
            : this(new IPEndPoint(IPAddress.Parse(server), port), tcp)
        { }

        public DnsClient(IPAddress server, ushort port = 53, bool tcp = false)
            : this(new IPEndPoint(server, port), tcp)
        { }

        public DnsClient(IPEndPoint server, bool tcp = false)
        {
            _server = server;

            if (tcp)
            {
                _socket = new Socket(_server.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                _socket.Connect(_server);
                _socket.NoDelay = true;
            }
            else
            {
                _socket = new Socket(_server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            }

            _socket.SendTimeout = 2000;
            _socket.ReceiveTimeout = 2000;
        }

        #endregion

        #region IDisposable

        ~DnsClient()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        bool _disposed = false;

        private void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                _socket.Dispose();

                _disposed = true;
            }
        }

        #endregion

        #region static

        public static DnsDatagram ResolveViaRootNameServers(string domain, DnsRecordType queryType, int retries = 3, bool tcp = false)
        {
            return ResolveViaNameServers(ROOTSERVERS, domain, queryType, retries, tcp);
        }

        public static DnsDatagram ResolveViaNameServers(string[] nameServers, string domain, DnsRecordType queryType, int retries = 3, bool tcp = false)
        {
            Random rnd = new Random();
            int hopCount = 0;
            IPAddress nextNameServer = IPAddress.Parse(nameServers[rnd.Next() % nameServers.Length]);

            while ((hopCount++) < 64)
            {
                using (DnsClient client = new DnsClient(nextNameServer, 53, tcp))
                {
                    DnsDatagram response = client.Resolve(domain, queryType, retries);

                    switch (response.Header.RCODE)
                    {
                        case DnsResponseCode.NoError:
                            if (response.Answer.Count > 0)
                                return response;

                            if ((response.Authority.Count == 0) || (response.Authority[0].Type != DnsRecordType.NS))
                                return response;

                            //select an authoritative name server
                            string nameserver = ((DnsNSRecord)response.Authority[rnd.Next() % response.Authority.Count].Data).NSDomainName;

                            //find ip address of authoritative name server from additional records
                            IPAddress nameserverIp = null;

                            foreach (DnsResourceRecord record in response.Additional)
                            {
                                if ((record.Type == DnsRecordType.A) && (record.Name.Equals(nameserver, StringComparison.CurrentCultureIgnoreCase)))
                                {
                                    nameserverIp = ((DnsARecord)record.Data).Address;
                                    break;
                                }
                            }

                            if (nameserverIp == null)
                            {
                                DnsDatagram nsResponse = ResolveViaNameServers(nameServers, nameserver, DnsRecordType.A, retries, tcp);
                                if ((nsResponse.Header.RCODE != DnsResponseCode.NoError) || (nsResponse.Answer.Count == 0) || (nsResponse.Answer[0].Type != DnsRecordType.A))
                                    return response;

                                nameserverIp = (nsResponse.Answer[0].Data as DnsARecord).Address;
                            }

                            nextNameServer = nameserverIp;
                            break;

                        default:
                            return response;
                    }
                }
            }

            throw new DnsClientException("Dns client exceeded the maximum hop count to resolve the domain: " + domain);
        }

        #endregion

        #region public

        public DnsDatagram Resolve(string domain, DnsRecordType queryType, int retries = 3)
        {
            byte[] buffer = new byte[2];

            int retry = 1;
            do
            {
                _rnd.GetBytes(buffer);
                short id = BitConverter.ToInt16(buffer, 0);

                DnsHeader header = new DnsHeader(id, false, DnsOpcode.StandardQuery, false, false, true, false, DnsResponseCode.NoError, 1, 0, 0, 0);
                DnsQuestionRecord question = new DnsQuestionRecord(domain, queryType, DnsClass.Internet);

                using (MemoryStream dnsQueryStream = new MemoryStream(128))
                {
                    header.WriteTo(dnsQueryStream);
                    question.WriteTo(dnsQueryStream);

                    if (_socket.ProtocolType == ProtocolType.Tcp)
                        _socket.Send(dnsQueryStream.ToArray());
                    else
                        _socket.SendTo(dnsQueryStream.ToArray(), _server);
                }

                byte[] recvbuffer = new byte[32 * 1024];
                EndPoint remoteEP = new IPEndPoint(0, 0);

                try
                {
                    retry += 1;

                    int bytesRecv;

                    if (_socket.ProtocolType == ProtocolType.Tcp)
                        bytesRecv = _socket.Receive(recvbuffer);
                    else
                        bytesRecv = _socket.ReceiveFrom(recvbuffer, ref remoteEP);

                    using (MemoryStream mS = new MemoryStream(recvbuffer, 0, bytesRecv, false))
                    {
                        DnsDatagram response = DnsDatagram.Parse(mS, _server);

                        if (response.Header.Identifier == id)
                            return response;
                    }
                }
                catch (SocketException)
                {
                    if (retry > retries)
                    {
                        throw;
                    }
                }
            }
            while (true);
        }

        public string ResolveMX(MailAddress emailAddress, bool resolveIP = false, bool ipv6 = false)
        {
            return ResolveMX(emailAddress.Host, resolveIP, ipv6);
        }

        public string ResolveMX(string domain, bool resolveIP = false, bool ipv6 = false)
        {
            IPAddress parsedIP = null;

            if (IPAddress.TryParse(domain, out parsedIP))
            {
                //host is valid ip address
                return domain;
            }

            //host is domain
            DnsDatagram response = Resolve(domain, DnsRecordType.MX);

            switch (response.Header.RCODE)
            {
                case DnsResponseCode.NoError:
                    if ((response.Header.ANCOUNT == 0) || !response.Answer[0].Name.Equals(domain, StringComparison.CurrentCultureIgnoreCase) || (response.Answer[0].Type != DnsRecordType.MX))
                        throw new NameErrorDnsClientException("No answer received from DNS server for domain: " + domain + "; DNS Server: " + _server.Address.ToString());

                    string mxDomain = ((DnsMXRecord)response.Answer[0].Data).Exchange;

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
                                        return ((DnsARecord)record.Data).Address.ToString();

                                    break;

                                case DnsRecordType.AAAA:
                                    return ((DnsAAAARecord)record.Data).Address.ToString();
                            }
                        }
                    }

                    //no glue record found so resolve ip
                    return ResolveIP(mxDomain, ipv6).ToString();

                case DnsResponseCode.NameError:
                    throw new NameErrorDnsClientException("Domain does not exists: " + domain);

                default:
                    throw new DnsClientException("DNS Server error. DNS opcode: " + Enum.GetName(typeof(DnsResponseCode), response.Header.RCODE) + " (" + response.Header.RCODE + ")");
            }
        }

        public string ResolvePTR(IPAddress ip)
        {
            DnsDatagram response = Resolve(ip.ToString(), DnsRecordType.PTR);

            if ((response.Header.RCODE == DnsResponseCode.NoError) && (response.Header.ANCOUNT > 0) && (response.Answer[0].Type == DnsRecordType.PTR))
                return ((DnsPTRRecord)response.Answer[0].Data).PTRDomainName;
            else
                throw new NameErrorDnsClientException("Cannot resolve PTR for ip: " + ip.ToString());
        }

        public IPAddress ResolveIP(string domain, bool ipv6 = false)
        {
            DnsDatagram response = Resolve(domain, ipv6 ? DnsRecordType.AAAA : DnsRecordType.A);

            switch (response.Header.RCODE)
            {
                case DnsResponseCode.NoError:
                    if ((response.Header.ANCOUNT == 0) || !response.Answer[0].Name.Equals(domain, StringComparison.CurrentCultureIgnoreCase))
                        throw new NameErrorDnsClientException("No answer received from DNS server for domain: " + domain + "; DNS Server: " + _server.Address.ToString());

                    switch (response.Answer[0].Type)
                    {
                        case DnsRecordType.A:
                            return ((DnsARecord)response.Answer[0].Data).Address;

                        case DnsRecordType.AAAA:
                            return ((DnsAAAARecord)response.Answer[0].Data).Address;

                        case DnsRecordType.CNAME:
                            string cnameDomain = ((DnsCNAMERecord)response.Answer[0].Data).CNAMEDomainName;

                            foreach (DnsResourceRecord record in response.Answer)
                            {
                                if (record.Name.Equals(cnameDomain, StringComparison.CurrentCultureIgnoreCase))
                                {
                                    switch (record.Type)
                                    {
                                        case DnsRecordType.A:
                                            return ((DnsARecord)record.Data).Address;

                                        case DnsRecordType.AAAA:
                                            return ((DnsAAAARecord)record.Data).Address;

                                        case DnsRecordType.CNAME:
                                            cnameDomain = ((DnsCNAMERecord)record.Data).CNAMEDomainName;
                                            break;
                                    }
                                }
                            }

                            return ResolveIP(cnameDomain);

                        default:
                            throw new NameErrorDnsClientException("No answer received from DNS server for domain: " + domain + "; DNS Server: " + _server.Address.ToString());
                    }

                case DnsResponseCode.NameError:
                    throw new NameErrorDnsClientException("Domain does not exists: " + domain);

                default:
                    throw new DnsClientException("DNS Server error. DNS opcode: " + Enum.GetName(typeof(DnsResponseCode), response.Header.RCODE) + " (" + response.Header.RCODE + ")");
            }
        }

        #endregion

        #region property

        public IPEndPoint Server
        { get { return _server; } }

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

        short _ID;

        byte _QR;
        DnsOpcode _opcode;
        byte _AA;
        byte _TC;
        byte _RD;
        byte _RA;
        byte _Z;
        DnsResponseCode _RCODE;

        short _QDCOUNT;
        short _ANCOUNT;
        short _NSCOUNT;
        short _ARCOUNT;

        #endregion

        #region constructor

        private DnsHeader()
        { }

        internal DnsHeader(short ID, bool isResponse, DnsOpcode opcode, bool authoritativeAnswer, bool truncation, bool recursionDesired, bool recursionAvailable, DnsResponseCode RCODE, short QDCOUNT, short ANCOUNT, short NSCOUNT, short ARCOUNT)
        {
            _ID = ID;

            if (isResponse)
                _QR = 1;

            _opcode = opcode;

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

        #endregion

        #region static

        internal static DnsHeader Parse(Stream s)
        {
            DnsHeader obj = new DnsHeader();

            obj._ID = DnsDatagram.ReadInt16NetworkOrder(s);

            int lB = s.ReadByte();
            obj._QR = Convert.ToByte((lB & 0x80) >> 7);
            obj._opcode = (DnsOpcode)Convert.ToByte((lB & 0x78) >> 3);
            obj._AA = Convert.ToByte((lB & 0x4) >> 2);
            obj._TC = Convert.ToByte((lB & 0x2) >> 1);
            obj._RD = Convert.ToByte(lB & 0x1);

            int rB = s.ReadByte();
            obj._RA = Convert.ToByte((rB & 0x80) >> 7);
            obj._Z = Convert.ToByte((rB & 0x70) >> 4);
            obj._RCODE = (DnsResponseCode)(rB & 0xf);

            obj._QDCOUNT = DnsDatagram.ReadInt16NetworkOrder(s);
            obj._ANCOUNT = DnsDatagram.ReadInt16NetworkOrder(s);
            obj._NSCOUNT = DnsDatagram.ReadInt16NetworkOrder(s);
            obj._ARCOUNT = DnsDatagram.ReadInt16NetworkOrder(s);

            return obj;
        }

        #endregion

        #region public

        public byte[] ToArray()
        {
            using (MemoryStream mS = new MemoryStream())
            {
                WriteTo(mS);
                return mS.ToArray();
            }
        }

        public void WriteTo(Stream s)
        {
            DnsDatagram.WriteInt16NetworkOrder(s, _ID);
            s.WriteByte(Convert.ToByte((_QR << 7) | ((byte)_opcode << 3) | (_AA << 2) | (_TC << 1) | _RD));
            s.WriteByte(Convert.ToByte((_RA << 7) | (_Z << 4) | (byte)_RCODE));
            DnsDatagram.WriteInt16NetworkOrder(s, _QDCOUNT);
            DnsDatagram.WriteInt16NetworkOrder(s, _ANCOUNT);
            DnsDatagram.WriteInt16NetworkOrder(s, _NSCOUNT);
            DnsDatagram.WriteInt16NetworkOrder(s, _ARCOUNT);
        }

        #endregion

        #region properties

        [IgnoreDataMember]
        public short Identifier
        { get { return _ID; } }

        [IgnoreDataMember]
        public bool IsResponse
        { get { return _QR == 1; } }

        public DnsOpcode Opcode
        { get { return _opcode; } }

        public bool AuthoritativeAnswer
        { get { return _AA == 1; } }

        public bool Truncation
        { get { return _TC == 1; } }

        public bool RecursionDesired
        { get { return _RD == 1; } }

        public bool RecursionAvailable
        { get { return _RA == 1; } }

        [IgnoreDataMember]
        public byte Z
        { get { return _Z; } }

        public DnsResponseCode RCODE
        { get { return _RCODE; } }

        [IgnoreDataMember]
        public short QDCOUNT
        { get { return _QDCOUNT; } }

        [IgnoreDataMember]
        public short ANCOUNT
        { get { return _ANCOUNT; } }

        [IgnoreDataMember]
        public short NSCOUNT
        { get { return _NSCOUNT; } }

        [IgnoreDataMember]
        public short ARCOUNT
        { get { return _ARCOUNT; } }

        #endregion
    }

    public class DnsDatagram
    {
        #region variables

        IPEndPoint _server;

        DnsHeader _header;

        ReadOnlyCollection<DnsQuestionRecord> _question;
        ReadOnlyCollection<DnsResourceRecord> _answer;
        ReadOnlyCollection<DnsResourceRecord> _authority;
        ReadOnlyCollection<DnsResourceRecord> _additional;

        #endregion

        #region constructor

        private DnsDatagram()
        { }

        #endregion

        #region static

        internal static DnsDatagram Parse(Stream s, IPEndPoint server)
        {
            DnsDatagram obj = new DnsDatagram();

            obj._server = server;
            obj._header = DnsHeader.Parse(s);

            List<DnsQuestionRecord> QuestionSection = new List<DnsQuestionRecord>(1);
            for (int i = 1; i <= obj._header.QDCOUNT; i++)
            {
                QuestionSection.Add(DnsQuestionRecord.Parse(s));
            }
            obj._question = QuestionSection.AsReadOnly();

            List<DnsResourceRecord> AnswerSection = new List<DnsResourceRecord>(obj._header.ANCOUNT);
            for (int i = 1; i <= obj._header.ANCOUNT; i++)
            {
                AnswerSection.Add(DnsResourceRecord.Parse(s));
            }
            obj._answer = AnswerSection.AsReadOnly();

            List<DnsResourceRecord> NameServerSection = new List<DnsResourceRecord>(obj._header.NSCOUNT);
            for (int i = 1; i <= obj._header.NSCOUNT; i++)
            {
                NameServerSection.Add(DnsResourceRecord.Parse(s));
            }
            obj._authority = NameServerSection.AsReadOnly();

            List<DnsResourceRecord> AdditionalRecordsSection = new List<DnsResourceRecord>(obj._header.ARCOUNT);
            for (int i = 1; i <= obj._header.ARCOUNT; i++)
            {
                AdditionalRecordsSection.Add(DnsResourceRecord.Parse(s));
            }
            obj._additional = AdditionalRecordsSection.AsReadOnly();

            return obj;
        }

        internal static short ReadInt16NetworkOrder(Stream s)
        {
            byte[] b = new byte[2];

            if (s.Read(b, 0, 2) != 2)
                throw new EndOfStreamException();

            Array.Reverse(b);
            return BitConverter.ToInt16(b, 0);
        }

        internal static void WriteInt16NetworkOrder(Stream s, short value)
        {
            byte[] b = BitConverter.GetBytes(value);
            Array.Reverse(b);
            s.Write(b, 0, b.Length);
        }

        internal static int ReadInt32NetworkOrder(Stream s)
        {
            byte[] b = new byte[4];

            if (s.Read(b, 0, 4) != 4)
                throw new EndOfStreamException();

            Array.Reverse(b);
            return BitConverter.ToInt32(b, 0);
        }

        internal static void WriteInt32NetworkOrder(Stream bW, int value)
        {
            byte[] b = BitConverter.GetBytes(value);
            Array.Reverse(b);
            bW.Write(b, 0, b.Length);
        }

        internal static uint ReadUInt32NetworkOrder(Stream s)
        {
            byte[] b = new byte[4];

            if (s.Read(b, 0, 4) != 4)
                throw new EndOfStreamException();

            Array.Reverse(b);
            return BitConverter.ToUInt32(b, 0);
        }

        internal static void WriteUInt32NetworkOrder(Stream bW, uint value)
        {
            byte[] b = BitConverter.GetBytes(value);
            Array.Reverse(b);
            bW.Write(b, 0, b.Length);
        }

        internal static byte[] ConvertDomainToLabel(string domain)
        {
            MemoryStream mS = new MemoryStream();

            foreach (string label in domain.Split('.'))
            {
                byte[] Lbl = Encoding.ASCII.GetBytes(label);

                if (Lbl.Length > 63)
                    throw new DnsClientException("ConvertDomainToLabel: Invalid domain name. Label cannot exceed 63 bytes.");

                mS.WriteByte(Convert.ToByte(Lbl.Length));
                mS.Write(Lbl, 0, Lbl.Length);
            }

            mS.WriteByte(Convert.ToByte(0));

            return mS.ToArray();
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

        #region properties

        [IgnoreDataMember]
        public IPEndPoint Server
        { get { return _server; } }

        public string ServerIPAddress
        { get { return _server.Address.ToString(); } }

        public DnsHeader Header
        { get { return _header; } }

        public ReadOnlyCollection<DnsQuestionRecord> Question
        { get { return _question; } }

        public ReadOnlyCollection<DnsResourceRecord> Answer
        { get { return _answer; } }

        public ReadOnlyCollection<DnsResourceRecord> Authority
        { get { return _authority; } }

        public ReadOnlyCollection<DnsResourceRecord> Additional
        { get { return _additional; } }

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

        private DnsQuestionRecord()
        { }

        internal DnsQuestionRecord(string name, DnsRecordType type, DnsClass @class)
        {
            _type = type;
            _class = @class;

            if (_type == DnsRecordType.PTR)
            {
                string[] IPAddr = name.Split(new char[] { '.' });

                for (int i = IPAddr.Length - 1; i >= 0; i += -1)
                    _name += IPAddr[i] + ".";

                _name += "IN-ADDR.ARPA";
            }
            else
            {
                _name = name;
            }
        }

        #endregion

        #region static

        internal static DnsQuestionRecord Parse(Stream s)
        {
            byte[] buffer = new byte[2];
            DnsQuestionRecord obj = new DnsQuestionRecord();

            obj._name = DnsDatagram.ConvertLabelToDomain(s);
            obj._type = (DnsRecordType)DnsDatagram.ReadInt16NetworkOrder(s);
            obj._class = (DnsClass)DnsDatagram.ReadInt16NetworkOrder(s);

            return obj;
        }

        #endregion

        #region public

        public byte[] ToArray()
        {
            using (MemoryStream mS = new MemoryStream())
            {
                WriteTo(mS);
                return mS.ToArray();
            }
        }

        public void WriteTo(Stream s)
        {
            byte[] Label = DnsDatagram.ConvertDomainToLabel(_name);
            s.Write(Label, 0, Label.Length);
            DnsDatagram.WriteInt16NetworkOrder(s, (short)_type);
            DnsDatagram.WriteInt16NetworkOrder(s, (short)_class);
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
        int _ttl;
        object _data;

        #endregion

        #region constructor

        private DnsResourceRecord()
        { }

        #endregion

        #region static

        internal static DnsResourceRecord Parse(Stream s)
        {
            byte[] buffer = new byte[4];
            DnsResourceRecord obj = new DnsResourceRecord();

            obj._name = DnsDatagram.ConvertLabelToDomain(s);
            obj._type = (DnsRecordType)DnsDatagram.ReadInt16NetworkOrder(s);
            obj._class = (DnsClass)DnsDatagram.ReadInt16NetworkOrder(s);
            obj._ttl = DnsDatagram.ReadInt32NetworkOrder(s);

            short length = DnsDatagram.ReadInt16NetworkOrder(s);

            switch (obj._type)
            {
                case DnsRecordType.A:
                    obj._data = DnsARecord.Parse(s);
                    break;

                case DnsRecordType.NS:
                    obj._data = DnsNSRecord.Parse(s);
                    break;

                case DnsRecordType.CNAME:
                    obj._data = DnsCNAMERecord.Parse(s);
                    break;

                case DnsRecordType.SOA:
                    obj._data = DnsSOARecord.Parse(s);
                    break;

                case DnsRecordType.PTR:
                    obj._data = DnsPTRRecord.Parse(s);
                    break;

                case DnsRecordType.MX:
                    obj._data = DnsMXRecord.Parse(s);
                    break;

                case DnsRecordType.TXT:
                    obj._data = DnsTXTRecord.Parse(s);
                    break;

                case DnsRecordType.AAAA:
                    obj._data = DnsAAAARecord.Parse(s);
                    break;

                default:
                    byte[] data = new byte[length];

                    if (s.Read(data, 0, length) != length)
                        throw new EndOfStreamException();

                    obj._data = data;
                    break;
            }

            return obj;
        }

        #endregion

        #region properties

        public string Name
        { get { return _name; } }

        public int TTL
        { get { return _ttl; } }

        public DnsRecordType Type
        { get { return _type; } }

        public object Data
        { get { return _data; } }

        #endregion
    }

    public class DnsARecord
    {
        #region variables

        IPAddress _address;

        #endregion

        #region constructor

        private DnsARecord()
        { }

        #endregion

        #region static

        internal static DnsARecord Parse(Stream s)
        {
            DnsARecord obj = new DnsARecord();

            byte[] buffer = new byte[4];
            s.Read(buffer, 0, 4);
            obj._address = new IPAddress(buffer);

            return obj;
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

    public class DnsNSRecord
    {
        #region variables

        string _nsDomainName;

        #endregion

        #region constructor

        private DnsNSRecord()
        { }

        #endregion

        #region static

        internal static DnsNSRecord Parse(Stream s)
        {
            DnsNSRecord obj = new DnsNSRecord();

            obj._nsDomainName = DnsDatagram.ConvertLabelToDomain(s);

            return obj;
        }

        #endregion

        #region properties

        public string NSDomainName
        { get { return _nsDomainName; } }

        #endregion
    }

    public class DnsCNAMERecord
    {
        #region variables

        string _cnameDomainName;

        #endregion

        #region constructor

        private DnsCNAMERecord()
        { }

        #endregion

        #region static

        internal static DnsCNAMERecord Parse(Stream s)
        {
            DnsCNAMERecord obj = new DnsCNAMERecord();

            obj._cnameDomainName = DnsDatagram.ConvertLabelToDomain(s);

            return obj;
        }

        #endregion

        #region properties

        public string CNAMEDomainName
        { get { return _cnameDomainName; } }

        #endregion
    }

    public class DnsSOARecord
    {
        #region variables

        string _masterNameServer;
        string _responsiblePerson;
        uint _serial;
        int _refresh;
        int _retry;
        int _expire;
        uint _minimum;

        #endregion

        #region constructor

        private DnsSOARecord()
        { }

        #endregion

        #region static

        internal static DnsSOARecord Parse(Stream s)
        {
            DnsSOARecord obj = new DnsSOARecord();

            obj._masterNameServer = DnsDatagram.ConvertLabelToDomain(s);
            obj._responsiblePerson = DnsDatagram.ConvertLabelToDomain(s);
            obj._serial = DnsDatagram.ReadUInt32NetworkOrder(s);
            obj._refresh = DnsDatagram.ReadInt32NetworkOrder(s);
            obj._retry = DnsDatagram.ReadInt32NetworkOrder(s);
            obj._expire = DnsDatagram.ReadInt32NetworkOrder(s);
            obj._minimum = DnsDatagram.ReadUInt32NetworkOrder(s);

            return obj;
        }

        #endregion

        #region properties

        public string MasterNameServer
        { get { return _masterNameServer; } }

        public string ResponsiblePerson
        { get { return _responsiblePerson; } }

        public uint Serial
        { get { return _serial; } }

        public int Refresh
        { get { return _refresh; } }

        public int Retry
        { get { return _retry; } }

        public int Expire
        { get { return _expire; } }

        public uint Minimum
        { get { return _minimum; } }

        #endregion
    }

    public class DnsPTRRecord
    {
        #region variables

        string _ptrDomainName;

        #endregion

        #region constructor

        private DnsPTRRecord()
        { }

        #endregion

        #region static

        internal static DnsPTRRecord Parse(Stream s)
        {
            DnsPTRRecord obj = new DnsPTRRecord();

            obj._ptrDomainName = DnsDatagram.ConvertLabelToDomain(s);

            return obj;
        }

        #endregion

        #region properties

        public string PTRDomainName
        { get { return _ptrDomainName; } }

        #endregion
    }

    public class DnsMXRecord
    {
        #region variables

        short _preference;
        string _exchange;

        #endregion

        #region constructor

        private DnsMXRecord()
        { }

        #endregion

        #region static

        internal static DnsMXRecord Parse(Stream s)
        {
            DnsMXRecord obj = new DnsMXRecord();

            obj._preference = DnsDatagram.ReadInt16NetworkOrder(s);
            obj._exchange = DnsDatagram.ConvertLabelToDomain(s);

            return obj;
        }

        #endregion

        #region properties

        public short Preference
        { get { return _preference; } }

        public string Exchange
        { get { return _exchange; } }

        #endregion
    }

    public class DnsTXTRecord
    {
        #region variables

        string _txtData;

        #endregion

        #region constructor

        private DnsTXTRecord()
        { }

        #endregion

        #region static

        internal static DnsTXTRecord Parse(Stream s)
        {
            DnsTXTRecord obj = new DnsTXTRecord();

            int length = s.ReadByte();
            if (length < 0)
                throw new EndOfStreamException();

            byte[] data = new byte[length];
            s.Read(data, 0, length);
            obj._txtData = Encoding.UTF8.GetString(data, 0, length);

            return obj;
        }

        #endregion

        #region properties

        public string TXTData
        { get { return _txtData; } }

        #endregion
    }

    public class DnsAAAARecord
    {
        #region variables

        IPAddress _address;

        #endregion

        #region constructor

        private DnsAAAARecord()
        { }

        #endregion

        #region static

        internal static DnsAAAARecord Parse(Stream s)
        {
            DnsAAAARecord obj = new DnsAAAARecord();

            byte[] buffer = new byte[16];
            s.Read(buffer, 0, 16);
            obj._address = new IPAddress(buffer);

            return obj;
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
