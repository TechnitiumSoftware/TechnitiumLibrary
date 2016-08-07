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
        AXFR = 252,
        ALL = 255
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

        public DnsClient(IPEndPoint server)
        {
            _server = server;

            _socket = new Socket(_server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            _socket.SendTimeout = 2000;
            _socket.ReceiveTimeout = 2000;
        }

        public DnsClient(IPAddress serverIP, ushort port = 53)
        {
            _server = new IPEndPoint(serverIP, port);

            _socket = new Socket(_server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
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

        public static DnsDatagram ResolveViaRootNameServers(string domain, DnsRecordType queryType, int retries = 3)
        {
            return ResolveViaNameServers(ROOTSERVERS, domain, queryType, retries);
        }

        public static DnsDatagram ResolveViaNameServers(string[] nameServers, string domain, DnsRecordType queryType, int retries = 3)
        {
            Random rnd = new Random();
            int hopCount = 0;
            DnsClient client = new DnsClient(IPAddress.Parse(nameServers[rnd.Next() % nameServers.Length]));

            while ((hopCount++) < 64)
            {
                DnsDatagram response = client.Resolve(domain, queryType, retries);

                switch (response.Header.RCODE)
                {
                    case DnsResponseCode.NoError:
                        if (response.AnswerSection.Count > 0)
                            return response;

                        if ((response.NameServerSection.Count == 0) || (response.NameServerSection[0].Type != DnsRecordType.NS))
                            throw new NameErrorDnsClientException("No answer received from DNS server for domain: " + domain + "; DNS Server: " + client.Server.Address.ToString());

                        //select a name server
                        string nameserver = ((DnsNSRecord)response.NameServerSection[rnd.Next() % response.NameServerSection.Count].RData).NSDomainName;

                        //find ip address of name server from additional records
                        IPAddress nameserverIp = null;

                        foreach (DnsResourceRecord record in response.AdditionalRecordsSection)
                        {
                            if ((record.Type == DnsRecordType.A) && (record.DomainName.Equals(nameserver, StringComparison.CurrentCultureIgnoreCase)))
                            {
                                nameserverIp = ((DnsARecord)record.RData).Address;
                                break;
                            }
                        }

                        if (nameserverIp == null)
                            throw new NameErrorDnsClientException("No answer received from DNS server for domain: " + domain + "; DNS Server: " + client.Server.Address.ToString());

                        client.Server.Address = nameserverIp;
                        break;

                    case DnsResponseCode.NameError:
                        throw new NameErrorDnsClientException("Domain does not exists: " + domain);

                    default:
                        throw new DnsClientException("DNS Server error. DNS opcode: " + Enum.GetName(typeof(DnsResponseCode), response.Header.RCODE) + " (" + response.Header.RCODE + ")");
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

                    _socket.SendTo(dnsQueryStream.ToArray(), _server);
                }

                byte[] recvbuffer = new byte[32 * 1024];
                EndPoint remoteEP = new IPEndPoint(0, 0);

                try
                {
                    retry += 1;

                    while (true)
                    {
                        int bytesRecv = _socket.ReceiveFrom(recvbuffer, ref remoteEP);

                        DnsDatagram response = DnsDatagram.Parse(new MemoryStream(recvbuffer, 0, bytesRecv, false));

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
            } while (true);
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
                    if ((response.Header.ANCOUNT == 0) || !response.AnswerSection[0].DomainName.Equals(domain, StringComparison.CurrentCultureIgnoreCase) || (response.AnswerSection[0].Type != DnsRecordType.MX))
                        throw new NameErrorDnsClientException("No answer received from DNS server for domain: " + domain + "; DNS Server: " + _server.Address.ToString());

                    string mxDomain = ((DnsMXRecord)response.AnswerSection[0].RData).Exchange;

                    if (!resolveIP)
                        return mxDomain;

                    //check glue records
                    foreach (DnsResourceRecord record in response.AdditionalRecordsSection)
                    {
                        if (record.DomainName.Equals(mxDomain, StringComparison.CurrentCultureIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsRecordType.A:
                                    if (!ipv6)
                                        return ((DnsARecord)record.RData).Address.ToString();

                                    break;

                                case DnsRecordType.AAAA:
                                    return ((DnsAAAARecord)record.RData).Address.ToString();
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

            if ((response.Header.RCODE == DnsResponseCode.NoError) && (response.Header.ANCOUNT > 0) && (response.AnswerSection[0].Type == DnsRecordType.PTR))
                return ((DnsPTRRecord)response.AnswerSection[0].RData).PTRDomainName;
            else
                throw new NameErrorDnsClientException("Cannot resolve PTR for ip: " + ip.ToString());
        }

        public IPAddress ResolveIP(string domain, bool ipv6 = false)
        {
            DnsDatagram response = Resolve(domain, ipv6 ? DnsRecordType.AAAA : DnsRecordType.A);

            switch (response.Header.RCODE)
            {
                case DnsResponseCode.NoError:
                    if ((response.Header.ANCOUNT == 0) || !response.AnswerSection[0].DomainName.Equals(domain, StringComparison.CurrentCultureIgnoreCase))
                        throw new NameErrorDnsClientException("No answer received from DNS server for domain: " + domain + "; DNS Server: " + _server.Address.ToString());

                    switch (response.AnswerSection[0].Type)
                    {
                        case DnsRecordType.A:
                            return ((DnsARecord)response.AnswerSection[0].RData).Address;

                        case DnsRecordType.AAAA:
                            return ((DnsAAAARecord)response.AnswerSection[0].RData).Address;

                        case DnsRecordType.CNAME:
                            string cnameDomain = ((DnsCNAMERecord)response.AnswerSection[0].RData).CNAMEDomainName;

                            foreach (DnsResourceRecord record in response.AnswerSection)
                            {
                                if (record.DomainName.Equals(cnameDomain, StringComparison.CurrentCultureIgnoreCase))
                                {
                                    switch (record.Type)
                                    {
                                        case DnsRecordType.A:
                                            return ((DnsARecord)record.RData).Address;

                                        case DnsRecordType.AAAA:
                                            return ((DnsAAAARecord)record.RData).Address;

                                        case DnsRecordType.CNAME:
                                            cnameDomain = ((DnsCNAMERecord)record.RData).CNAMEDomainName;
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
        {
            get { return _server; }
            set { _server = value; }
        }

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

        public DnsHeader(short ID, bool isResponse, DnsOpcode opcode, bool authoritativeAnswer, bool truncation, bool recursionDesired, bool recursionAvailable, DnsResponseCode RCODE, short QDCOUNT, short ANCOUNT, short NSCOUNT, short ARCOUNT)
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

        public static DnsHeader Parse(Stream s)
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

        public short Identifier
        { get { return _ID; } }

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

        public byte Z
        { get { return _Z; } }

        public DnsResponseCode RCODE
        { get { return _RCODE; } }

        public short QDCOUNT
        { get { return _QDCOUNT; } }

        public short ANCOUNT
        { get { return _ANCOUNT; } }

        public short NSCOUNT
        { get { return _NSCOUNT; } }

        public short ARCOUNT
        { get { return _ARCOUNT; } }

        #endregion
    }

    public class DnsDatagram
    {
        #region variables

        DnsHeader _header;

        ReadOnlyCollection<DnsQuestionRecord> _questionSection;
        ReadOnlyCollection<DnsResourceRecord> _answerSection;
        ReadOnlyCollection<DnsResourceRecord> _nameServerSection;
        ReadOnlyCollection<DnsResourceRecord> _additionalRecordsSection;

        #endregion

        #region constructor

        private DnsDatagram()
        { }

        public DnsDatagram(DnsHeader header, ReadOnlyCollection<DnsQuestionRecord> questionSection, ReadOnlyCollection<DnsResourceRecord> answerSection, ReadOnlyCollection<DnsResourceRecord> nameServerSection, ReadOnlyCollection<DnsResourceRecord> additionalRecordsSection)
        {
            _header = header;

            _questionSection = questionSection;
            _answerSection = answerSection;
            _nameServerSection = nameServerSection;
            _additionalRecordsSection = additionalRecordsSection;
        }

        #endregion

        #region static

        public static DnsDatagram Parse(Stream s)
        {
            DnsDatagram obj = new DnsDatagram();

            obj._header = DnsHeader.Parse(s);

            List<DnsQuestionRecord> QuestionSection = new List<DnsQuestionRecord>();
            for (int i = 1; i <= obj._header.QDCOUNT; i++)
            {
                QuestionSection.Add(DnsQuestionRecord.Parse(s));
            }
            obj._questionSection = QuestionSection.AsReadOnly();

            List<DnsResourceRecord> AnswerSection = new List<DnsResourceRecord>();
            for (int i = 1; i <= obj._header.ANCOUNT; i++)
            {
                AnswerSection.Add(DnsResourceRecord.Parse(s));
            }
            obj._answerSection = AnswerSection.AsReadOnly();

            List<DnsResourceRecord> NameServerSection = new List<DnsResourceRecord>();
            for (int i = 1; i <= obj._header.NSCOUNT; i++)
            {
                NameServerSection.Add(DnsResourceRecord.Parse(s));
            }
            obj._nameServerSection = NameServerSection.AsReadOnly();

            List<DnsResourceRecord> AdditionalRecordsSection = new List<DnsResourceRecord>();
            for (int i = 1; i <= obj._header.ARCOUNT; i++)
            {
                AdditionalRecordsSection.Add(DnsResourceRecord.Parse(s));
            }
            obj._additionalRecordsSection = AdditionalRecordsSection.AsReadOnly();

            return obj;
        }

        public static short ReadInt16NetworkOrder(Stream s)
        {
            byte[] b = new byte[2];

            if (s.Read(b, 0, 2) != 2)
                throw new IOException("ReadInt16NetworkOrder: Cannot parse; end of stream.");

            Array.Reverse(b);
            return BitConverter.ToInt16(b, 0);
        }

        public static void WriteInt16NetworkOrder(Stream s, short Value)
        {
            byte[] b = BitConverter.GetBytes(Value);
            Array.Reverse(b);
            s.Write(b, 0, b.Length);
        }

        public static int ReadInt32NetworkOrder(Stream s)
        {
            byte[] b = new byte[4];

            if (s.Read(b, 0, 4) != 4)
                throw new IOException("ReadInt32NetworkOrder: Cannot parse; end of stream.");

            Array.Reverse(b);
            return BitConverter.ToInt16(b, 0);
        }

        public static void WriteInt32NetworkOrder(Stream bW, int Value)
        {
            byte[] b = BitConverter.GetBytes(Value);
            Array.Reverse(b);
            bW.Write(b, 0, b.Length);
        }

        public static byte[] ConvertDomainToLabel(string Domain)
        {
            MemoryStream mS = new MemoryStream();

            foreach (string label in Domain.Split('.'))
            {
                byte[] Lbl = System.Text.Encoding.ASCII.GetBytes(label);

                if (Lbl.Length > 63)
                    throw new DnsClientException("ConvertDomainToLabel: Invalid domain name. Label cannot exceed 63 bytes.");

                mS.WriteByte(Convert.ToByte(Lbl.Length));
                mS.Write(Lbl, 0, Lbl.Length);
            }

            mS.WriteByte(Convert.ToByte(0));

            return mS.ToArray();
        }

        public static string ConvertLabelToDomain(Stream label)
        {
            StringBuilder domainName = new StringBuilder();
            byte labelLength = Convert.ToByte(label.ReadByte());
            byte[] buffer = new byte[255];

            while (labelLength > 0)
            {
                if ((labelLength & 192) == 192)
                {
                    short Offset = BitConverter.ToInt16(new byte[] { Convert.ToByte(label.ReadByte()), Convert.ToByte((labelLength & 63)) }, 0);
                    long CurrentPosition = label.Position;
                    label.Position = Offset;
                    domainName.Append(ConvertLabelToDomain(label) + ".");
                    label.Position = CurrentPosition;
                    break;
                }
                else
                {
                    label.Read(buffer, 0, labelLength);
                    domainName.Append(System.Text.Encoding.ASCII.GetString(buffer, 0, labelLength) + ".");
                    labelLength = Convert.ToByte(label.ReadByte());
                }
            }

            if (domainName.Length > 0)
                domainName.Length = domainName.Length - 1;

            return domainName.ToString();
        }

        #endregion

        #region properties

        public DnsHeader Header
        { get { return _header; } }

        public ReadOnlyCollection<DnsQuestionRecord> QuestionSection
        { get { return _questionSection; } }

        public ReadOnlyCollection<DnsResourceRecord> AnswerSection
        { get { return _answerSection; } }

        public ReadOnlyCollection<DnsResourceRecord> NameServerSection
        { get { return _nameServerSection; } }

        public ReadOnlyCollection<DnsResourceRecord> AdditionalRecordsSection
        { get { return _additionalRecordsSection; } }

        #endregion
    }

    public class DnsQuestionRecord
    {
        #region variables

        string _domainName;
        DnsRecordType _type;
        DnsClass _class;

        #endregion

        #region constructor

        private DnsQuestionRecord()
        { }

        public DnsQuestionRecord(string domainName, DnsRecordType type, DnsClass @class)
        {
            _type = type;
            _class = @class;

            if (_type == DnsRecordType.PTR)
            {
                string[] IPAddr = domainName.Split(new char[] { '.' });

                for (int i = IPAddr.Length - 1; i >= 0; i += -1)
                    _domainName += IPAddr[i] + ".";

                _domainName += "IN-ADDR.ARPA";
            }
            else
            {
                _domainName = domainName;
            }
        }

        #endregion

        #region static

        public static DnsQuestionRecord Parse(Stream s)
        {
            byte[] buffer = new byte[2];
            DnsQuestionRecord obj = new DnsQuestionRecord();

            obj._domainName = DnsDatagram.ConvertLabelToDomain(s);
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
            byte[] Label = DnsDatagram.ConvertDomainToLabel(_domainName);
            s.Write(Label, 0, Label.Length);
            DnsDatagram.WriteInt16NetworkOrder(s, (short)_type);
            DnsDatagram.WriteInt16NetworkOrder(s, (short)_class);
        }

        #endregion

        #region properties

        public string DomainName
        { get { return _domainName; } }

        public DnsRecordType Type
        { get { return _type; } }

        public DnsClass Class
        { get { return _class; } }

        #endregion
    }

    public class DnsResourceRecord
    {
        #region variables

        string _domainName;
        DnsRecordType _type;
        DnsClass _class;
        int _TTL;
        object _RData;

        #endregion

        #region constructor

        private DnsResourceRecord()
        { }

        public DnsResourceRecord(string domainName, int TTL, DnsRecordType type, byte[] RData)
        {
            _domainName = domainName;
            _TTL = TTL;
            _type = type;
            _RData = RData;
        }

        #endregion

        #region static

        public static DnsResourceRecord Parse(Stream s)
        {
            byte[] buffer = new byte[4];
            DnsResourceRecord obj = new DnsResourceRecord();

            obj._domainName = DnsDatagram.ConvertLabelToDomain(s);
            obj._type = (DnsRecordType)DnsDatagram.ReadInt16NetworkOrder(s);
            obj._class = (DnsClass)DnsDatagram.ReadInt16NetworkOrder(s);
            obj._TTL = DnsDatagram.ReadInt32NetworkOrder(s);

            short RDLENGTH = DnsDatagram.ReadInt16NetworkOrder(s);

            switch (obj._type)
            {
                case DnsRecordType.A:
                    obj._RData = DnsARecord.Parse(s);
                    break;

                case DnsRecordType.AAAA:
                    obj._RData = DnsAAAARecord.Parse(s);
                    break;

                case DnsRecordType.CNAME:
                    obj._RData = DnsCNAMERecord.Parse(s);
                    break;

                case DnsRecordType.MX:
                    obj._RData = DnsMXRecord.Parse(s);
                    break;

                case DnsRecordType.PTR:
                    obj._RData = DnsPTRRecord.Parse(s);
                    break;

                case DnsRecordType.NS:
                    obj._RData = DnsNSRecord.Parse(s);
                    break;

                default:
                    byte[] RDATA = new byte[RDLENGTH];

                    if (s.Read(RDATA, 0, RDLENGTH) != RDLENGTH)
                        throw new IOException("Cannot parse DnsResourceRecord; end of stream.");

                    obj._RData = RDATA;
                    break;
            }

            return obj;
        }

        #endregion

        #region properties

        public string DomainName
        { get { return _domainName; } }

        public int TTL
        { get { return _TTL; } }

        public DnsRecordType Type
        { get { return _type; } }

        public object RData
        { get { return _RData; } }

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

        public DnsARecord(IPAddress address)
        {
            _address = address;
        }

        #endregion

        #region static

        public static DnsARecord Parse(Stream s)
        {
            DnsARecord obj = new DnsARecord();

            byte[] buffer = new byte[4];
            s.Read(buffer, 0, 4);
            obj._address = new IPAddress(buffer);

            return obj;
        }

        #endregion

        #region properties

        public IPAddress Address
        { get { return _address; } }

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

        public DnsAAAARecord(IPAddress address)
        {
            _address = address;
        }

        #endregion

        #region static

        public static DnsAAAARecord Parse(Stream s)
        {
            DnsAAAARecord obj = new DnsAAAARecord();

            byte[] buffer = new byte[16];
            s.Read(buffer, 0, 16);
            obj._address = new IPAddress(buffer);

            return obj;
        }

        #endregion

        #region properties

        public IPAddress Address
        { get { return _address; } }

        #endregion
    }

    public class DnsCNAMERecord
    {
        #region variables

        string _CNAMEDomainName;

        #endregion

        #region constructor

        private DnsCNAMERecord()
        { }

        public DnsCNAMERecord(string CNAMEDomainName)
        {
            _CNAMEDomainName = CNAMEDomainName;
        }

        #endregion

        #region static

        public static DnsCNAMERecord Parse(Stream s)
        {
            DnsCNAMERecord obj = new DnsCNAMERecord();

            obj._CNAMEDomainName = DnsDatagram.ConvertLabelToDomain(s);

            return obj;
        }

        #endregion

        #region properties

        public string CNAMEDomainName
        { get { return _CNAMEDomainName; } }

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

        public DnsMXRecord(short preference, string exchange)
        {
            _preference = preference;
            _exchange = exchange;
        }

        #endregion

        #region static

        public static DnsMXRecord Parse(Stream s)
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

    public class DnsPTRRecord
    {
        #region variables

        string _PTRDomainName;

        #endregion

        #region constructor

        private DnsPTRRecord()
        { }

        public DnsPTRRecord(string PTRDomainName)
        {
            _PTRDomainName = PTRDomainName;
        }

        #endregion

        #region static

        public static DnsPTRRecord Parse(Stream s)
        {
            DnsPTRRecord obj = new DnsPTRRecord();

            obj._PTRDomainName = DnsDatagram.ConvertLabelToDomain(s);

            return obj;
        }

        #endregion

        #region properties

        public string PTRDomainName
        { get { return _PTRDomainName; } }

        #endregion
    }

    public class DnsNSRecord
    {
        #region variables

        string _NSDomainName;

        #endregion

        #region constructor

        private DnsNSRecord()
        { }

        public DnsNSRecord(string NSDomainName)
        {
            _NSDomainName = NSDomainName;
        }

        #endregion

        #region static

        public static DnsNSRecord Parse(Stream s)
        {
            DnsNSRecord obj = new DnsNSRecord();

            obj._NSDomainName = DnsDatagram.ConvertLabelToDomain(s);

            return obj;
        }

        #endregion

        #region properties

        public string NSDomainName
        { get { return _NSDomainName; } }

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
