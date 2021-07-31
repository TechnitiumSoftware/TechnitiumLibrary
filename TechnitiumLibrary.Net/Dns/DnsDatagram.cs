/*
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

using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Net.Dns
{
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
        NxDomain = 3,
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

    public sealed class DnsDatagram
    {
        #region variables

        const int MAX_XFR_RESPONSE_SIZE = 16384; //since the compressed name pointer offset can only address 16384 bytes in datagram

        readonly static RandomNumberGenerator _rnd = new RNGCryptoServiceProvider();

        DnsDatagramMetadata _metadata;
        int _size = -1;

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

        IReadOnlyList<DnsQuestionRecord> _question;
        IReadOnlyList<DnsResourceRecord> _answer;
        IReadOnlyList<DnsResourceRecord> _authority;
        IReadOnlyList<DnsResourceRecord> _additional;

        Exception _parsingException;

        DnsDatagram _nextDatagram; //used for TCP XFR multiple messages

        #endregion

        #region constructor

        private DnsDatagram()
        { }

        public DnsDatagram(ushort ID, bool isResponse, DnsOpcode OPCODE, bool authoritativeAnswer, bool truncation, bool recursionDesired, bool recursionAvailable, bool authenticData, bool checkingDisabled, DnsResponseCode RCODE, IReadOnlyList<DnsQuestionRecord> question, IReadOnlyList<DnsResourceRecord> answer = null, IReadOnlyList<DnsResourceRecord> authority = null, IReadOnlyList<DnsResourceRecord> additional = null)
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

            if (authenticData)
                _AD = 1;

            if (checkingDisabled)
                _CD = 1;

            _RCODE = RCODE;

            _question = question;
            _answer = answer;
            _authority = authority;
            _additional = additional;

            if (_question is null)
                _question = Array.Empty<DnsQuestionRecord>();

            if (_answer is null)
                _answer = Array.Empty<DnsResourceRecord>();

            if (_authority is null)
                _authority = Array.Empty<DnsResourceRecord>();

            if (_additional is null)
                _additional = Array.Empty<DnsResourceRecord>();
        }

        #endregion

        #region static

        public static DnsDatagram ReadFrom(Stream s)
        {
            DnsDatagram datagram = new DnsDatagram();

            datagram._ID = ReadUInt16NetworkOrder(s);

            int lB = s.ReadByte();
            datagram._QR = Convert.ToByte((lB & 0x80) >> 7);
            datagram._OPCODE = (DnsOpcode)Convert.ToByte((lB & 0x78) >> 3);
            datagram._AA = Convert.ToByte((lB & 0x4) >> 2);
            datagram._TC = Convert.ToByte((lB & 0x2) >> 1);
            datagram._RD = Convert.ToByte(lB & 0x1);

            int rB = s.ReadByte();
            datagram._RA = Convert.ToByte((rB & 0x80) >> 7);
            datagram._Z = Convert.ToByte((rB & 0x40) >> 6);
            datagram._AD = Convert.ToByte((rB & 0x20) >> 5);
            datagram._CD = Convert.ToByte((rB & 0x10) >> 4);
            datagram._RCODE = (DnsResponseCode)(rB & 0xf);

            ushort QDCOUNT = ReadUInt16NetworkOrder(s);
            ushort ANCOUNT = ReadUInt16NetworkOrder(s);
            ushort NSCOUNT = ReadUInt16NetworkOrder(s);
            ushort ARCOUNT = ReadUInt16NetworkOrder(s);

            try
            {
                if (QDCOUNT == 0)
                {
                    datagram._question = Array.Empty<DnsQuestionRecord>();
                }
                else
                {
                    DnsQuestionRecord[] question = new DnsQuestionRecord[QDCOUNT];

                    for (int i = 0; i < question.Length; i++)
                        question[i] = new DnsQuestionRecord(s);

                    datagram._question = question;
                }

                if (ANCOUNT == 0)
                {
                    datagram._answer = Array.Empty<DnsResourceRecord>();
                }
                else
                {
                    DnsResourceRecord[] answer = new DnsResourceRecord[ANCOUNT];

                    for (int i = 0; i < answer.Length; i++)
                        answer[i] = new DnsResourceRecord(s);

                    datagram._answer = answer;
                }

                if (NSCOUNT == 0)
                {
                    datagram._authority = Array.Empty<DnsResourceRecord>();
                }
                else
                {
                    DnsResourceRecord[] authority = new DnsResourceRecord[NSCOUNT];

                    for (int i = 0; i < authority.Length; i++)
                        authority[i] = new DnsResourceRecord(s);

                    datagram._authority = authority;
                }

                if (ARCOUNT == 0)
                {
                    datagram._additional = Array.Empty<DnsResourceRecord>();
                }
                else
                {
                    DnsResourceRecord[] additional = new DnsResourceRecord[ARCOUNT];

                    for (int i = 0; i < additional.Length; i++)
                        additional[i] = new DnsResourceRecord(s);

                    datagram._additional = additional;
                }
            }
            catch (Exception ex)
            {
                datagram._parsingException = ex;

                if (datagram._question is null)
                    datagram._question = Array.Empty<DnsQuestionRecord>();

                if (datagram._answer is null)
                    datagram._answer = Array.Empty<DnsResourceRecord>();

                if (datagram._authority is null)
                    datagram._authority = Array.Empty<DnsResourceRecord>();

                if (datagram._additional is null)
                    datagram._additional = Array.Empty<DnsResourceRecord>();
            }

            datagram._size = Convert.ToInt32(s.Position);

            return datagram;
        }

        public static async Task<DnsDatagram> ReadFromTcpAsync(Stream stream, CancellationToken cancellationToken = default)
        {
            using (MemoryStream mS = new MemoryStream(4096))
            {
                return await ReadFromTcpAsync(stream, mS, cancellationToken);
            }
        }

        public static async Task<DnsDatagram> ReadFromTcpAsync(Stream stream, MemoryStream sharedBuffer, CancellationToken cancellationToken = default)
        {
            //read tcp datagram length
            int length = await ReadUInt16NetworkOrderAsync(stream, cancellationToken);

            //read datagram from source to buffer
            sharedBuffer.SetLength(0);
            await stream.CopyToAsync(sharedBuffer, Math.Min(4096, length), length, cancellationToken);
            sharedBuffer.Position = 0;

            //parse datagram from buffer
            return ReadFrom(sharedBuffer);
        }

        public static DnsDatagram ReadFromJson(dynamic jsonResponse, int size)
        {
            DnsDatagram datagram = new DnsDatagram();

            datagram._QR = 1; //is response
            datagram._OPCODE = DnsOpcode.StandardQuery;

            datagram._TC = (byte)(jsonResponse.TC.Value ? 1 : 0);
            datagram._RD = (byte)(jsonResponse.RD.Value ? 1 : 0);
            datagram._RA = (byte)(jsonResponse.RA.Value ? 1 : 0);
            datagram._AD = (byte)(jsonResponse.AD.Value ? 1 : 0);
            datagram._CD = (byte)(jsonResponse.CD.Value ? 1 : 0);
            datagram._RCODE = (DnsResponseCode)jsonResponse.Status;

            try
            {
                //question
                if ((jsonResponse.Question == null) || (jsonResponse.Question.Count == 0))
                {
                    datagram._question = Array.Empty<DnsQuestionRecord>();
                }
                else
                {
                    ushort QDCOUNT = Convert.ToUInt16(jsonResponse.Question.Count);
                    List<DnsQuestionRecord> question = new List<DnsQuestionRecord>(QDCOUNT);
                    datagram._question = question;

                    foreach (dynamic jsonQuestionRecord in jsonResponse.Question)
                        question.Add(new DnsQuestionRecord(jsonQuestionRecord));
                }

                //answer
                if ((jsonResponse.Answer == null) || (jsonResponse.Answer.Count == 0))
                {
                    datagram._answer = Array.Empty<DnsResourceRecord>();
                }
                else
                {
                    ushort ANCOUNT = Convert.ToUInt16(jsonResponse.Answer.Count);
                    List<DnsResourceRecord> answer = new List<DnsResourceRecord>(ANCOUNT);
                    datagram._answer = answer;

                    foreach (dynamic jsonAnswerRecord in jsonResponse.Answer)
                        answer.Add(new DnsResourceRecord(jsonAnswerRecord));
                }

                //authority
                if ((jsonResponse.Authority == null) || (jsonResponse.Authority.Count == 0))
                {
                    datagram._authority = Array.Empty<DnsResourceRecord>();
                }
                else
                {
                    ushort NSCOUNT = Convert.ToUInt16(jsonResponse.Authority.Count);
                    List<DnsResourceRecord> authority = new List<DnsResourceRecord>(NSCOUNT);
                    datagram._authority = authority;

                    foreach (dynamic jsonAuthorityRecord in jsonResponse.Authority)
                        authority.Add(new DnsResourceRecord(jsonAuthorityRecord));
                }

                //additional
                if ((jsonResponse.Additional == null) || (jsonResponse.Additional.Count == 0))
                {
                    datagram._additional = Array.Empty<DnsResourceRecord>();
                }
                else
                {
                    ushort ARCOUNT = Convert.ToUInt16(jsonResponse.Additional.Count);
                    List<DnsResourceRecord> additional = new List<DnsResourceRecord>(ARCOUNT);
                    datagram._additional = additional;

                    foreach (dynamic jsonAdditionalRecord in jsonResponse.Additional)
                        additional.Add(new DnsResourceRecord(jsonAdditionalRecord));
                }
            }
            catch (Exception ex)
            {
                datagram._parsingException = ex;

                if (datagram._question is null)
                    datagram._question = Array.Empty<DnsQuestionRecord>();

                if (datagram._answer is null)
                    datagram._answer = Array.Empty<DnsResourceRecord>();

                if (datagram._authority is null)
                    datagram._authority = Array.Empty<DnsResourceRecord>();

                if (datagram._additional is null)
                    datagram._additional = Array.Empty<DnsResourceRecord>();
            }

            datagram._size = size;

            return datagram;
        }

        internal static async Task<ushort> ReadUInt16NetworkOrderAsync(Stream s, CancellationToken cancellationToken = default)
        {
            byte[] b = await s.ReadBytesAsync(2, cancellationToken);
            Array.Reverse(b);
            return BitConverter.ToUInt16(b, 0);
        }

        internal static ushort ReadUInt16NetworkOrder(Stream s)
        {
            byte[] b = s.ReadBytes(2);
            Array.Reverse(b);
            return BitConverter.ToUInt16(b, 0);
        }

        internal static void WriteUInt16NetworkOrder(ushort value, Stream s)
        {
            byte[] b = BitConverter.GetBytes(value);
            Array.Reverse(b);
            s.Write(b, 0, 2);
        }

        internal static uint ReadUInt32NetworkOrder(Stream s)
        {
            byte[] b = s.ReadBytes(4);
            Array.Reverse(b);
            return BitConverter.ToUInt32(b, 0);
        }

        internal static void WriteUInt32NetworkOrder(uint value, Stream s)
        {
            byte[] b = BitConverter.GetBytes(value);
            Array.Reverse(b);
            s.Write(b, 0, 4);
        }

        internal static ulong ReadUInt48NetworkOrder(Stream s)
        {
            byte[] b = new byte[8];
            s.ReadBytes(b, 2, 6);
            Array.Reverse(b);
            return BitConverter.ToUInt64(b, 0);
        }

        internal static void WriteUInt48NetworkOrder(ulong value, Stream s)
        {
            byte[] b = BitConverter.GetBytes(value);
            Array.Reverse(b);
            s.Write(b, 2, 6);
        }

        internal static byte[] ConvertToUInt48NetworkOrder(ulong value)
        {
            byte[] b = BitConverter.GetBytes(value);
            Array.Reverse(b);

            byte[] t = new byte[6];
            Buffer.BlockCopy(b, 2, t, 0, 6);

            return t;
        }

        public static void SerializeDomainName(string domain, Stream s, List<DnsDomainOffset> domainEntries = null)
        {
            while (!string.IsNullOrEmpty(domain))
            {
                if (domainEntries != null)
                {
                    //search domain list
                    foreach (DnsDomainOffset domainEntry in domainEntries)
                    {
                        if (domain.Equals(domainEntry.Domain, StringComparison.OrdinalIgnoreCase))
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
                }

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

        public static string DeserializeDomainName(Stream s, int maxDepth = 10, bool ignoreMissingNullTermination = false)
        {
            if (maxDepth < 0)
                throw new DnsClientException("Error while reading domain name: max depth for decompression reached");

            int labelLength = s.ReadByte();
            if (labelLength < 0)
                throw new EndOfStreamException();

            StringBuilder domain = new StringBuilder();
            byte[] buffer = null;

            while (labelLength > 0)
            {
                if ((labelLength & 0xC0) == 0xC0)
                {
                    int secondByte = s.ReadByte();
                    if (secondByte < 0)
                        throw new EndOfStreamException();

                    short Offset = BitConverter.ToInt16(new byte[] { (byte)secondByte, (byte)(labelLength & 0x3F) }, 0);
                    long CurrentPosition = s.Position;
                    s.Position = Offset;
                    domain.Append(DeserializeDomainName(s, maxDepth - 1, ignoreMissingNullTermination));
                    domain.Append('.');
                    s.Position = CurrentPosition;
                    break;
                }
                else
                {
                    if (buffer == null)
                        buffer = new byte[255]; //late buffer init to avoid unnecessary allocation in most cases

                    s.ReadBytes(buffer, 0, labelLength);
                    domain.Append(Encoding.ASCII.GetChars(buffer, 0, labelLength));
                    domain.Append('.');

                    if (ignoreMissingNullTermination && (s.Length == s.Position))
                        break; //option to ignore for buggy DHCP clients

                    labelLength = s.ReadByte();
                    if (labelLength < 0)
                        throw new EndOfStreamException();
                }
            }

            if (domain.Length > 0)
                domain.Length--;

            return domain.ToString();
        }

        internal static string EncodeCharacterString(string value)
        {
            if (value.Contains(" ") || value.Contains("\t"))
                value = "\"" + value.Replace("\"", "\\\"") + "\"";

            return value;
        }

        internal static string DecodeCharacterString(string value)
        {
            if (value.StartsWith("\"") && value.EndsWith("\""))
                value = value.Substring(1, value.Length - 2).Replace("\\\"", "\"");

            return value;
        }

        #endregion

        #region internal

        internal DnsDatagram CloneHeadersAndQuestions()
        {
            DnsQuestionRecord[] clonedQuestion = new DnsQuestionRecord[_question.Count];

            for (int i = 0; i < _question.Count; i++)
                clonedQuestion[i] = _question[i].Clone();

            DnsDatagram datagram = new DnsDatagram(_ID, _QR == 1, _OPCODE, _AA == 1, _TC == 1, _RD == 1, _RA == 1, _AD == 1, _CD == 1, _RCODE, clonedQuestion, _answer, _authority, _additional);

            datagram._metadata = _metadata;
            datagram.Tag = Tag;

            return datagram;
        }

        internal DnsDatagram Clone(IReadOnlyList<DnsResourceRecord> answer, IReadOnlyList<DnsResourceRecord> authority)
        {
            if (answer == null)
                answer = _answer;

            if (authority == null)
                authority = _authority;

            DnsDatagram datagram = new DnsDatagram(_ID, _QR == 1, _OPCODE, _AA == 1, _TC == 1, _RD == 1, _RA == 1, _AD == 1, _CD == 1, _RCODE, _question, answer, authority, _additional);

            datagram._metadata = _metadata;
            datagram.Tag = Tag;

            return datagram;
        }

        #endregion

        #region public

        public void SetMetadata(NameServerAddress server = null, DnsTransportProtocol protocol = DnsTransportProtocol.Udp, double rtt = 0.0)
        {
            if (_metadata != null)
                throw new InvalidOperationException("Cannot overwrite existing Metadata.");

            _metadata = new DnsDatagramMetadata(server, protocol, _size, rtt);
        }

        public void SetIdentifier(ushort id)
        {
            _ID = id;
        }

        public void SetRandomIdentifier()
        {
            Span<byte> buffer = stackalloc byte[2];
            _rnd.GetBytes(buffer);

            _ID = BitConverter.ToUInt16(buffer);
        }

        public void WriteTo(Stream s)
        {
            WriteUInt16NetworkOrder(_ID, s);
            s.WriteByte(Convert.ToByte((_QR << 7) | ((byte)_OPCODE << 3) | (_AA << 2) | (_TC << 1) | _RD));
            s.WriteByte(Convert.ToByte((_RA << 7) | (_Z << 6) | (_AD << 5) | (_CD << 4) | (byte)_RCODE));
            WriteUInt16NetworkOrder(Convert.ToUInt16(_question.Count), s);
            WriteUInt16NetworkOrder(Convert.ToUInt16(_answer.Count), s);
            WriteUInt16NetworkOrder(Convert.ToUInt16(_authority.Count), s);
            WriteUInt16NetworkOrder(Convert.ToUInt16(_additional.Count), s);

            List<DnsDomainOffset> domainEntries = new List<DnsDomainOffset>(1);

            foreach (DnsQuestionRecord question in _question)
                question.WriteTo(s, domainEntries);

            foreach (DnsResourceRecord answer in _answer)
                answer.WriteTo(s, domainEntries);

            foreach (DnsResourceRecord authority in _authority)
                authority.WriteTo(s, domainEntries);

            foreach (DnsResourceRecord additional in _additional)
                additional.WriteTo(s, domainEntries);
        }

        public async Task WriteToTcpAsync(Stream s)
        {
            using (MemoryStream mS = new MemoryStream(4096))
            {
                await WriteToTcpAsync(s, mS);
            }
        }

        public async Task WriteToTcpAsync(Stream s, MemoryStream sharedBuffer)
        {
            OffsetStream sharedBufferOffset = new OffsetStream(sharedBuffer);

            DnsDatagram current = this;

            do
            {
                sharedBuffer.SetLength(0);
                sharedBufferOffset.Reset(2, 0, 0);
                current.WriteTo(sharedBufferOffset);

                sharedBuffer.Position = 0;
                WriteUInt16NetworkOrder(Convert.ToUInt16(sharedBuffer.Length - 2), sharedBuffer);

                sharedBuffer.Position = 0;
                await sharedBuffer.CopyToAsync(s, Math.Min(4096, (int)sharedBuffer.Length));

                current = current._nextDatagram;
            }
            while (current is not null);
        }

        public void WriteToJson(JsonTextWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WritePropertyName("Status");
            jsonWriter.WriteValue((int)_RCODE);

            jsonWriter.WritePropertyName("TC");
            jsonWriter.WriteValue(_TC == 1);

            jsonWriter.WritePropertyName("RD");
            jsonWriter.WriteValue(_RD == 1);

            jsonWriter.WritePropertyName("RA");
            jsonWriter.WriteValue(_RA == 1);

            jsonWriter.WritePropertyName("AD");
            jsonWriter.WriteValue(_AD == 1);

            jsonWriter.WritePropertyName("CD");
            jsonWriter.WriteValue(_CD == 1);

            jsonWriter.WritePropertyName("Question");
            jsonWriter.WriteStartArray();

            foreach (DnsQuestionRecord question in _question)
            {
                jsonWriter.WriteStartObject();

                jsonWriter.WritePropertyName("name");
                jsonWriter.WriteValue(question.Name + ".");

                jsonWriter.WritePropertyName("type");
                jsonWriter.WriteValue((int)question.Type);

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WriteEndArray();

            if (_answer.Count > 0)
                WriteSection(jsonWriter, _answer, "Answer");

            if (_authority.Count > 0)
                WriteSection(jsonWriter, _authority, "Authority");

            if (_additional.Count > 0)
                WriteSection(jsonWriter, _additional, "Additional");

            jsonWriter.WriteEndObject();
        }

        public DnsDatagram Split()
        {
            if (!IsResponse)
                throw new InvalidOperationException("Cannot split this datagram: datagram must be a response.");

            if (!IsZoneTransfer)
                throw new InvalidOperationException("Cannot split this datagram: datagram must be for a zone transfer.");

            if (IsSigned)
                throw new InvalidOperationException("Cannot split this datagram: datagram must not be signed.");

            if (_answer.Count == 0)
                return this;

            DnsDatagram first = null;
            DnsDatagram last = null;
            int iQD = 0;
            int iAN = 0;
            int iNS = 0;
            int iAR = 0;

            do
            {
                int datagramSize = 12; //init with header size

                IReadOnlyList<DnsQuestionRecord> question = null;
                IReadOnlyList<DnsResourceRecord> answer = null;
                IReadOnlyList<DnsResourceRecord> authority = null;
                IReadOnlyList<DnsResourceRecord> additional = null;

                if (iQD < _question.Count)
                {
                    datagramSize += _question[0].UncompressedLength;
                    question = _question;
                    iQD = _question.Count;
                }

                if (iAN < _answer.Count)
                {
                    List<DnsResourceRecord> list = new List<DnsResourceRecord>();

                    for (; (iAN < _answer.Count) && (datagramSize < MAX_XFR_RESPONSE_SIZE); iAN++)
                    {
                        DnsResourceRecord record = _answer[iAN];

                        datagramSize += record.UncompressedLength;
                        list.Add(record);
                    }

                    answer = list;
                }

                if ((iNS < _authority.Count) && (datagramSize < MAX_XFR_RESPONSE_SIZE))
                {
                    List<DnsResourceRecord> list = new List<DnsResourceRecord>();

                    for (; (iNS < _authority.Count) && (datagramSize < MAX_XFR_RESPONSE_SIZE); iNS++)
                    {
                        DnsResourceRecord record = _authority[iNS];

                        datagramSize += record.UncompressedLength;
                        list.Add(record);
                    }

                    authority = list;
                }

                if ((iAR < _additional.Count) && (datagramSize < MAX_XFR_RESPONSE_SIZE))
                {
                    List<DnsResourceRecord> list = new List<DnsResourceRecord>();

                    for (; (iAR < _additional.Count) && (datagramSize < MAX_XFR_RESPONSE_SIZE); iAR++)
                    {
                        DnsResourceRecord record = _additional[iAR];

                        datagramSize += record.UncompressedLength;
                        list.Add(record);
                    }

                    _additional = list;
                }

                DnsDatagram datagram = new DnsDatagram(_ID, _QR == 1, _OPCODE, _AA == 1, _TC == 1, _RD == 1, _RA == 1, _AD == 1, _CD == 1, _RCODE, question, answer, authority, additional);

                if (first is null)
                {
                    first = datagram;
                    first._metadata = _metadata;
                    first.Tag = Tag;

                    last = datagram;
                }
                else
                {
                    last._nextDatagram = datagram;
                    last = datagram;
                }
            }
            while ((iAN < _answer.Count) || (iNS < _authority.Count) || (iAR < _additional.Count));

            return first;
        }

        public DnsDatagram Join()
        {
            if (!IsResponse)
                throw new InvalidOperationException("Cannot join this datagram: datagram must be a response.");

            if (!IsZoneTransfer)
                throw new InvalidOperationException("Cannot join this datagram: datagram must be for a zone transfer.");

            if (IsSigned)
                throw new InvalidOperationException("Cannot join this datagram: datagram must not be signed.");

            if (_nextDatagram is null)
                return this;

            List<DnsResourceRecord> answer = new List<DnsResourceRecord>(_answer.Count * 2);
            DnsDatagram current = this;
            int size = 0;

            do
            {
                size += current._size;
                answer.AddRange(current._answer);

                current = current._nextDatagram;
            }
            while (current is not null);

            DnsDatagram joinedDatagram = new DnsDatagram(_ID, _QR == 1, _OPCODE, _AA == 1, _TC == 1, _RD == 1, _RA == 1, _AD == 1, _CD == 1, _RCODE, _question, answer, _authority, _additional);
            joinedDatagram._size = size;
            joinedDatagram.SetMetadata(_metadata.NameServerAddress, _metadata.Protocol, _metadata.RTT);
            joinedDatagram.Tag = Tag;

            return joinedDatagram;
        }

        public DnsDatagram SignRequest(string keyName, string sharedSecret, string algorithmName, ushort fudge)
        {
            if (IsResponse)
                throw new InvalidOperationException("Cannot sign this datagram: datagram must be a request.");

            if (algorithmName.Equals("hmac-md5", StringComparison.OrdinalIgnoreCase))
                algorithmName = DnsTSIGRecord.ALGORITHM_NAME_HMAC_MD5;

            ulong timeSigned = Convert.ToUInt64((DateTime.UtcNow - DateTime.UnixEpoch).TotalSeconds);
            DnsTsigError error = DnsTsigError.NoError;
            byte[] otherData = Array.Empty<byte>();

            byte[] mac = ComputeRequestMAC(keyName, algorithmName, timeSigned, fudge, error, otherData, sharedSecret, 0);

            DnsResourceRecord tsigRecord = new DnsResourceRecord(keyName, DnsResourceRecordType.TSIG, DnsClass.ANY, 0, new DnsTSIGRecord(algorithmName, timeSigned, fudge, mac, _ID, error, otherData));

            IReadOnlyList<DnsResourceRecord> additional;

            if (_additional.Count == 0)
            {
                additional = new DnsResourceRecord[] { tsigRecord };
            }
            else
            {
                List<DnsResourceRecord> list = new List<DnsResourceRecord>(_additional.Count + 1);

                foreach (DnsResourceRecord record in _additional)
                {
                    if (record.Type == DnsResourceRecordType.TSIG)
                        throw new InvalidOperationException("Cannot sign this datagram: a TSIG record already exists.");

                    list.Add(record);
                }

                list.Add(tsigRecord);

                additional = list;
            }

            DnsDatagram signedDatagram = new DnsDatagram(_ID, _QR == 1, _OPCODE, _AA == 1, _TC == 1, _RD == 1, _RA == 1, _AD == 1, _CD == 1, _RCODE, _question, _answer, _authority, additional);
            signedDatagram._metadata = _metadata;
            signedDatagram.Tag = Tag;

            return signedDatagram;
        }

        public bool VerifySignedRequest(IReadOnlyDictionary<string, string> keys, out DnsDatagram unsignedRequest, out DnsDatagram errorResponse)
        {
            if (IsResponse)
                throw new InvalidOperationException("Cannot verify this datagram: datagram must be a request.");

            if (!IsSigned)
            {
                //datagram not signed
                unsignedRequest = null;

                //unsigned error response
                errorResponse = new DnsDatagram(_ID, true, _OPCODE, _AA == 1, _TC == 1, _RD == 1, _RA == 1, _AD == 1, _CD == 1, DnsResponseCode.NotAuthorized, _question);

                return false;
            }

            IReadOnlyList<DnsResourceRecord> additional;

            if (_additional.Count == 1)
            {
                additional = Array.Empty<DnsResourceRecord>();
            }
            else
            {
                List<DnsResourceRecord> list = new List<DnsResourceRecord>(_additional.Count - 1);

                for (int i = 0; i < _additional.Count - 1; i++)
                {
                    DnsResourceRecord record = _additional[i];

                    if (record.Type == DnsResourceRecordType.TSIG)
                    {
                        //contains extra TSIG
                        unsignedRequest = null;

                        //unsigned error response
                        errorResponse = new DnsDatagram(_ID, true, _OPCODE, _AA == 1, _TC == 1, _RD == 1, _RA == 1, _AD == 1, _CD == 1, DnsResponseCode.FormatError, _question);

                        return false;
                    }

                    list.Add(record);
                }

                additional = list;
            }

            DnsResourceRecord tsigRecord = _additional[_additional.Count - 1];
            DnsTSIGRecord tsig = tsigRecord.RDATA as DnsTSIGRecord;

            //get unsigned datagram
            unsignedRequest = new DnsDatagram(tsig.OriginalID, _QR == 1, _OPCODE, _AA == 1, _TC == 1, _RD == 1, _RA == 1, _AD == 1, _CD == 1, _RCODE, _question, _answer, _authority, additional);
            unsignedRequest._metadata = _metadata;
            unsignedRequest.Tag = Tag;

            //verify
            ushort expectedMacSize = GetMACSize(tsig.AlgorithmName);

            //Key Check
            if ((expectedMacSize == ushort.MinValue) || !keys.TryGetValue(tsigRecord.Name.ToLower(), out string sharedSecret))
            {
                unsignedRequest = null;

                //unsigned error response
                DnsTSIGRecord errorTsig = new DnsTSIGRecord(tsig.AlgorithmName, tsig.TimeSigned, tsig.Fudge, Array.Empty<byte>(), tsig.OriginalID, DnsTsigError.BADKEY, Array.Empty<byte>());
                DnsResourceRecord errorTsigRecord = new DnsResourceRecord(tsigRecord.Name, DnsResourceRecordType.TSIG, DnsClass.ANY, 0, errorTsig);
                errorResponse = new DnsDatagram(_ID, true, _OPCODE, _AA == 1, _TC == 1, _RD == 1, _RA == 1, _AD == 1, _CD == 1, DnsResponseCode.NotAuthorized, _question, null, null, new DnsResourceRecord[] { errorTsigRecord });

                return false;
            }

            //MAC Check
            if ((tsig.MAC.Length > expectedMacSize) || (tsig.MAC.Length < Math.Max(10, expectedMacSize / 2)))
            {
                unsignedRequest = null;

                //unsigned error response
                errorResponse = new DnsDatagram(_ID, true, _OPCODE, _AA == 1, _TC == 1, _RD == 1, _RA == 1, _AD == 1, _CD == 1, DnsResponseCode.FormatError, _question);

                return false;
            }

            byte[] computedMac = unsignedRequest.ComputeRequestMAC(tsigRecord.Name, tsig.AlgorithmName, tsig.TimeSigned, tsig.Fudge, tsig.Error, tsig.OtherData, sharedSecret, tsig.MAC.Length);
            if (!BinaryNumber.Equals(computedMac, tsig.MAC))
            {
                unsignedRequest = null;

                //unsigned error response
                DnsTSIGRecord errorTsig = new DnsTSIGRecord(tsig.AlgorithmName, tsig.TimeSigned, tsig.Fudge, Array.Empty<byte>(), tsig.OriginalID, DnsTsigError.BADSIG, Array.Empty<byte>());
                DnsResourceRecord errorTsigRecord = new DnsResourceRecord(tsigRecord.Name, DnsResourceRecordType.TSIG, DnsClass.ANY, 0, errorTsig);
                errorResponse = new DnsDatagram(_ID, true, _OPCODE, _AA == 1, _TC == 1, _RD == 1, _RA == 1, _AD == 1, _CD == 1, DnsResponseCode.NotAuthorized, _question, null, null, new DnsResourceRecord[] { errorTsigRecord });

                return false;
            }

            //Check time values
            DateTime startTime = DateTime.UnixEpoch.AddSeconds(tsig.TimeSigned - tsig.Fudge);
            DateTime endTime = DateTime.UnixEpoch.AddSeconds(tsig.TimeSigned + tsig.Fudge);
            DateTime utcNow = DateTime.UtcNow;

            if ((utcNow < startTime) || (utcNow > endTime))
            {
                unsignedRequest = null;

                //signed error response
                errorResponse = new DnsDatagram(_ID, true, _OPCODE, _AA == 1, _TC == 1, _RD == 1, _RA == 1, _AD == 1, _CD == 1, DnsResponseCode.NotAuthorized, _question);
                errorResponse = errorResponse.SignResponse(this, keys, DnsTsigError.BADTIME);

                return false;
            }

            //Check truncation policy
            if (tsig.MAC.Length < expectedMacSize)
            {
                unsignedRequest = null;

                //signed error response
                errorResponse = new DnsDatagram(_ID, true, _OPCODE, _AA == 1, _TC == 1, _RD == 1, _RA == 1, _AD == 1, _CD == 1, DnsResponseCode.NotAuthorized, _question);
                errorResponse = errorResponse.SignResponse(this, keys, DnsTsigError.BADTRUNC);

                return false;
            }

            //return
            errorResponse = null;
            return true;
        }

        public DnsDatagram SignResponse(DnsDatagram signedRequest, IReadOnlyDictionary<string, string> keys, DnsTsigError error)
        {
            if (!IsResponse)
                throw new InvalidOperationException("Cannot sign this datagram: datagram must be a response.");

            if (!signedRequest.IsSigned)
                throw new InvalidOperationException("Cannot sign this datagram: a signed request datagram is expected.");

            DnsResourceRecord requestTsigRecord = signedRequest._additional[signedRequest._additional.Count - 1];
            DnsTSIGRecord requestTsig = requestTsigRecord.RDATA as DnsTSIGRecord;

            ulong timeSigned;
            byte[] otherData;

            switch (error)
            {
                case DnsTsigError.BADTIME:
                    timeSigned = requestTsig.TimeSigned;
                    otherData = ConvertToUInt48NetworkOrder(Convert.ToUInt64((DateTime.UtcNow - DateTime.UnixEpoch).TotalSeconds));
                    break;

                default:
                    timeSigned = Convert.ToUInt64((DateTime.UtcNow - DateTime.UnixEpoch).TotalSeconds);
                    otherData = Array.Empty<byte>();
                    break;
            }

            if (!keys.TryGetValue(requestTsigRecord.Name.ToLower(), out string sharedSecret))
                throw new InvalidOperationException("Cannot sign this datagram: key not found.");

            byte[] mac = ComputeResponseMAC(requestTsigRecord, requestTsigRecord.Name, requestTsig.AlgorithmName, timeSigned, requestTsig.Fudge, error, otherData, sharedSecret, 0);

            DnsTSIGRecord tsig = new DnsTSIGRecord(requestTsig.AlgorithmName, timeSigned, requestTsig.Fudge, mac, requestTsig.OriginalID, error, otherData);
            DnsResourceRecord tsigRecord = new DnsResourceRecord(requestTsigRecord.Name, DnsResourceRecordType.TSIG, DnsClass.ANY, 0, tsig);

            IReadOnlyList<DnsResourceRecord> additional;

            if (_additional.Count == 0)
            {
                additional = new DnsResourceRecord[] { tsigRecord };
            }
            else
            {
                List<DnsResourceRecord> list = new List<DnsResourceRecord>(_additional.Count + 1);

                foreach (DnsResourceRecord record in _additional)
                {
                    if (record.Type == DnsResourceRecordType.TSIG)
                        throw new InvalidOperationException("Cannot sign this datagram: a TSIG record already exists.");

                    list.Add(record);
                }

                list.Add(tsigRecord);

                additional = list;
            }

            DnsDatagram signedDatagram = new DnsDatagram(signedRequest._ID, _QR == 1, _OPCODE, _AA == 1, _TC == 1, _RD == 1, _RA == 1, _AD == 1, _CD == 1, _RCODE, _question, _answer, _authority, additional);
            signedDatagram._metadata = _metadata;
            signedDatagram.Tag = Tag;

            //sign next messages
            if (_nextDatagram is not null)
            {
                DnsDatagram current = _nextDatagram;
                DnsTSIGRecord priorTsig = tsig;
                DnsDatagram lastSigned = signedDatagram;

                while (current is not null)
                {
                    byte[] currentMac = ComputeXfrResponseMAC(priorTsig, new DnsDatagram[] { current }, timeSigned, requestTsig.Fudge, sharedSecret, 0);

                    DnsTSIGRecord currentTsig = new DnsTSIGRecord(requestTsig.AlgorithmName, timeSigned, requestTsig.Fudge, currentMac, requestTsig.OriginalID, error, otherData);
                    DnsResourceRecord currentTsigRecord = new DnsResourceRecord(requestTsigRecord.Name, DnsResourceRecordType.TSIG, DnsClass.ANY, 0, currentTsig);

                    IReadOnlyList<DnsResourceRecord> currentAdditional;

                    if (current._additional.Count == 0)
                    {
                        currentAdditional = new DnsResourceRecord[] { currentTsigRecord };
                    }
                    else
                    {
                        List<DnsResourceRecord> list = new List<DnsResourceRecord>(current._additional.Count + 1);

                        foreach (DnsResourceRecord record in current._additional)
                        {
                            if (record.Type == DnsResourceRecordType.TSIG)
                                throw new InvalidOperationException("Cannot sign this datagram: a TSIG record already exists.");

                            list.Add(record);
                        }

                        list.Add(currentTsigRecord);

                        currentAdditional = list;
                    }

                    DnsDatagram signedCurrent = new DnsDatagram(signedRequest._ID, _QR == 1, _OPCODE, _AA == 1, _TC == 1, _RD == 1, _RA == 1, _AD == 1, _CD == 1, _RCODE, current._question, current._answer, current._authority, currentAdditional);

                    current = current._nextDatagram;
                    priorTsig = currentTsig;
                    lastSigned._nextDatagram = signedCurrent;
                    lastSigned = signedCurrent;
                }
            }

            return signedDatagram;
        }

        public bool VerifySignedResponse(DnsDatagram signedRequest, string keyName, string sharedSecret, out DnsDatagram unsignedResponse, out DnsResponseCode rCode, out DnsTsigError error)
        {
            if (!IsResponse)
                throw new InvalidOperationException("Cannot verify this datagram: datagram must be a response.");

            if (!IsSigned)
            {
                //datagram not signed; discard it
                unsignedResponse = null;
                rCode = DnsResponseCode.FormatError;
                error = DnsTsigError.NoError;
                return false;
            }

            IReadOnlyList<DnsResourceRecord> additional;

            if (_additional.Count == 1)
            {
                additional = Array.Empty<DnsResourceRecord>();
            }
            else
            {
                List<DnsResourceRecord> list = new List<DnsResourceRecord>(_additional.Count - 1);

                for (int i = 0; i < _additional.Count - 1; i++)
                {
                    DnsResourceRecord record = _additional[i];

                    if (record.Type == DnsResourceRecordType.TSIG)
                    {
                        //contains extra TSIG
                        unsignedResponse = null;
                        rCode = DnsResponseCode.FormatError;
                        error = DnsTsigError.NoError;
                        return false;
                    }

                    list.Add(record);
                }

                additional = list;
            }

            DnsResourceRecord tsigRecord = _additional[_additional.Count - 1];
            DnsTSIGRecord tsig = tsigRecord.RDATA as DnsTSIGRecord;

            //get unsigned datagram
            unsignedResponse = new DnsDatagram(tsig.OriginalID, _QR == 1, _OPCODE, _AA == 1, _TC == 1, _RD == 1, _RA == 1, _AD == 1, _CD == 1, _RCODE, _question, _answer, _authority, additional);
            unsignedResponse._metadata = _metadata;
            unsignedResponse.Tag = Tag;

            //verify
            ushort expectedMacSize = GetMACSize(tsig.AlgorithmName);

            //Key Check
            if ((expectedMacSize == ushort.MinValue) || !tsigRecord.Name.Equals(keyName, StringComparison.OrdinalIgnoreCase))
            {
                unsignedResponse = null;
                rCode = DnsResponseCode.NotAuthorized;
                error = DnsTsigError.BADKEY;
                return false;
            }

            //MAC Check
            if ((tsig.MAC.Length > expectedMacSize) || (tsig.MAC.Length < Math.Max(10, expectedMacSize / 2)))
            {
                unsignedResponse = null;
                rCode = DnsResponseCode.FormatError;
                error = DnsTsigError.NoError;
                return false;
            }

            DnsResourceRecord requestTsigRecord = signedRequest._additional[signedRequest._additional.Count - 1];

            byte[] computedMac = unsignedResponse.ComputeResponseMAC(requestTsigRecord, tsigRecord.Name, tsig.AlgorithmName, tsig.TimeSigned, tsig.Fudge, tsig.Error, tsig.OtherData, sharedSecret, tsig.MAC.Length);
            if (!BinaryNumber.Equals(computedMac, tsig.MAC))
            {
                unsignedResponse = null;
                rCode = DnsResponseCode.NotAuthorized;
                error = DnsTsigError.BADSIG;
                return false;
            }

            //Check time values
            DateTime utcNow = DateTime.UtcNow;
            DateTime startTime = DateTime.UnixEpoch.AddSeconds(tsig.TimeSigned - tsig.Fudge);
            DateTime endTime = DateTime.UnixEpoch.AddSeconds(tsig.TimeSigned + tsig.Fudge);

            if ((utcNow < startTime) || (utcNow > endTime))
            {
                unsignedResponse = null;
                rCode = DnsResponseCode.NotAuthorized;
                error = DnsTsigError.BADTIME;
                return false;
            }

            //Check truncation policy
            if (tsig.MAC.Length < expectedMacSize)
            {
                unsignedResponse = null;
                rCode = DnsResponseCode.NotAuthorized;
                error = DnsTsigError.BADTRUNC;
                return false;
            }

            //verify next messages
            if (_nextDatagram is not null)
            {
                DnsDatagram unsignedPrior = unsignedResponse;
                DnsDatagram current = _nextDatagram;
                DnsTSIGRecord priorTsig = tsig;
                List<DnsDatagram> dnsMessages = new List<DnsDatagram>();

                while (current is not null)
                {
                    if (!current.IsSigned)
                    {
                        dnsMessages.Add(current);

                        if (dnsMessages.Count < 100)
                            continue; //MUST accept up to 99 intermediary messages without a TSIG

                        unsignedResponse = null;
                        rCode = DnsResponseCode.FormatError;
                        error = DnsTsigError.NoError;
                        return false;
                    }

                    IReadOnlyList<DnsResourceRecord> currentAdditional;

                    if (_additional.Count == 1)
                    {
                        currentAdditional = Array.Empty<DnsResourceRecord>();
                    }
                    else
                    {
                        List<DnsResourceRecord> list = new List<DnsResourceRecord>(_additional.Count - 1);

                        for (int i = 0; i < _additional.Count - 1; i++)
                        {
                            DnsResourceRecord record = _additional[i];

                            if (record.Type == DnsResourceRecordType.TSIG)
                            {
                                //contains extra TSIG
                                unsignedResponse = null;
                                rCode = DnsResponseCode.FormatError;
                                error = DnsTsigError.NoError;
                                return false;
                            }

                            list.Add(record);
                        }

                        currentAdditional = list;
                    }

                    DnsResourceRecord currentTsigRecord = current._additional[current._additional.Count - 1];
                    DnsTSIGRecord currentTsig = currentTsigRecord.RDATA as DnsTSIGRecord;

                    DnsDatagram unsignedCurrentResponse = new DnsDatagram(currentTsig.OriginalID, _QR == 1, _OPCODE, _AA == 1, _TC == 1, _RD == 1, _RA == 1, _AD == 1, _CD == 1, _RCODE, current._question, current._answer, current._authority, currentAdditional);
                    dnsMessages.Add(unsignedCurrentResponse);

                    //verify
                    //MAC Check
                    if ((currentTsig.MAC.Length > expectedMacSize) || (currentTsig.MAC.Length < Math.Max(10, expectedMacSize / 2)))
                    {
                        unsignedResponse = null;
                        rCode = DnsResponseCode.FormatError;
                        error = DnsTsigError.NoError;
                        return false;
                    }

                    byte[] currentComputedMac = ComputeXfrResponseMAC(priorTsig, dnsMessages, currentTsig.TimeSigned, currentTsig.Fudge, sharedSecret, currentTsig.MAC.Length);
                    if (!BinaryNumber.Equals(currentComputedMac, currentTsig.MAC))
                    {
                        unsignedResponse = null;
                        rCode = DnsResponseCode.NotAuthorized;
                        error = DnsTsigError.BADSIG;
                        return false;
                    }

                    //Check time values
                    DateTime currentStartTime = DateTime.UnixEpoch.AddSeconds(currentTsig.TimeSigned - currentTsig.Fudge);
                    DateTime currentEndTime = DateTime.UnixEpoch.AddSeconds(currentTsig.TimeSigned + currentTsig.Fudge);

                    if ((utcNow < currentStartTime) || (utcNow > currentEndTime))
                    {
                        unsignedResponse = null;
                        rCode = DnsResponseCode.NotAuthorized;
                        error = DnsTsigError.BADTIME;
                        return false;
                    }

                    //Check truncation policy
                    if (currentTsig.MAC.Length < expectedMacSize)
                    {
                        unsignedResponse = null;
                        rCode = DnsResponseCode.NotAuthorized;
                        error = DnsTsigError.BADTRUNC;
                        return false;
                    }

                    unsignedPrior._nextDatagram = unsignedCurrentResponse;
                    unsignedPrior = unsignedCurrentResponse;
                    current = current._nextDatagram;
                    priorTsig = currentTsig;
                    dnsMessages.Clear();
                }

                if (dnsMessages.Count > 0)
                {
                    //last message was unsigned
                    unsignedResponse = null;
                    rCode = DnsResponseCode.FormatError;
                    error = DnsTsigError.NoError;
                    return false;
                }
            }

            //return
            rCode = DnsResponseCode.NoError;
            error = DnsTsigError.NoError;
            return true;
        }

        #endregion

        #region private

        private static void WriteSection(JsonTextWriter jsonWriter, IReadOnlyList<DnsResourceRecord> section, string sectionName)
        {
            jsonWriter.WritePropertyName(sectionName);
            jsonWriter.WriteStartArray();

            foreach (DnsResourceRecord record in section)
            {
                jsonWriter.WriteStartObject();

                jsonWriter.WritePropertyName("name");
                jsonWriter.WriteValue(record.Name + ".");

                jsonWriter.WritePropertyName("type");
                jsonWriter.WriteValue((ushort)record.Type);

                jsonWriter.WritePropertyName("TTL");
                jsonWriter.WriteValue(record.TtlValue);

                jsonWriter.WritePropertyName("data");
                jsonWriter.WriteValue(record.RDATA.ToString());

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WriteEndArray();
        }

        private byte[] ComputeRequestMAC(string keyName, string algorithmName, ulong timeSigned, ushort fudge, DnsTsigError error, byte[] otherData, string sharedSecret, int truncationLength)
        {
            using (MemoryStream mS = new MemoryStream(256))
            {
                //write DNS Message (request)
                WriteTo(mS);

                //write TSIG Variables (request)
                SerializeDomainName(keyName.ToLower(), mS); //NAME
                WriteUInt16NetworkOrder((ushort)DnsClass.ANY, mS); //CLASS
                WriteUInt32NetworkOrder(0u, mS); //TTL
                SerializeDomainName(algorithmName.ToLower(), mS); //Algorithm Name
                WriteUInt48NetworkOrder(timeSigned, mS); //Time Signed
                WriteUInt16NetworkOrder(fudge, mS); //Fudge
                WriteUInt16NetworkOrder((ushort)error, mS); //Error
                WriteUInt16NetworkOrder(Convert.ToUInt16(otherData.Length), mS); //Other Len
                mS.Write(otherData); //Other Data

                //compute mac
                mS.Position = 0;
                return ComputeMAC(algorithmName, sharedSecret, truncationLength, mS);
            }
        }

        private byte[] ComputeResponseMAC(DnsResourceRecord requestTsigRecord, string keyName, string algorithmName, ulong timeSigned, ushort fudge, DnsTsigError error, byte[] otherData, string sharedSecret, int truncationLength)
        {
            DnsTSIGRecord requestTsig = requestTsigRecord.RDATA as DnsTSIGRecord;

            using (MemoryStream mS = new MemoryStream(256))
            {
                //write Request MAC
                WriteUInt16NetworkOrder(Convert.ToUInt16(requestTsig.MAC.Length), mS);
                mS.Write(requestTsig.MAC);

                //write DNS Message (response)
                WriteTo(mS);

                //write TSIG Variables (response)
                SerializeDomainName(keyName.ToLower(), mS); //NAME
                WriteUInt16NetworkOrder((ushort)DnsClass.ANY, mS); //CLASS
                WriteUInt32NetworkOrder(0u, mS); //TTL
                SerializeDomainName(algorithmName.ToLower(), mS); //Algorithm Name
                WriteUInt48NetworkOrder(timeSigned, mS); //Time Signed
                WriteUInt16NetworkOrder(fudge, mS); //Fudge
                WriteUInt16NetworkOrder((ushort)error, mS); //Error
                WriteUInt16NetworkOrder(Convert.ToUInt16(otherData.Length), mS); //Other Len
                mS.Write(otherData); //Other Data

                //compute mac
                mS.Position = 0;
                return ComputeMAC(algorithmName, sharedSecret, truncationLength, mS);
            }
        }

        private static byte[] ComputeXfrResponseMAC(DnsTSIGRecord priorTsig, IReadOnlyList<DnsDatagram> dnsMessages, ulong timeSigned, ushort fudge, string sharedSecret, int truncationLength)
        {
            using (MemoryStream mS = new MemoryStream(256))
            {
                //write Prior MAC (running)
                WriteUInt16NetworkOrder(Convert.ToUInt16(priorTsig.MAC.Length), mS);
                mS.Write(priorTsig.MAC);

                //write DNS Messages (any unsigned messages since the last TSIG)
                foreach (DnsDatagram unsignedMessage in dnsMessages)
                    unsignedMessage.WriteTo(mS);

                //write TSIG Timers (current message)
                WriteUInt48NetworkOrder(timeSigned, mS); //Time Signed
                WriteUInt16NetworkOrder(fudge, mS); //Fudge

                //compute mac
                mS.Position = 0;
                return ComputeMAC(priorTsig.AlgorithmName, sharedSecret, truncationLength, mS);
            }
        }

        private static ushort GetMACSize(string algorithmName)
        {
            switch (algorithmName.ToLower())
            {
                case DnsTSIGRecord.ALGORITHM_NAME_HMAC_MD5:
                    return 16;

                case DnsTSIGRecord.ALGORITHM_NAME_HMAC_SHA1:
                    return 20;

                case DnsTSIGRecord.ALGORITHM_NAME_HMAC_SHA256:
                    return 32;

                case DnsTSIGRecord.ALGORITHM_NAME_HMAC_SHA256_128:
                    return 16;

                case DnsTSIGRecord.ALGORITHM_NAME_HMAC_SHA384:
                    return 48;

                case DnsTSIGRecord.ALGORITHM_NAME_HMAC_SHA384_192:
                    return 24;

                case DnsTSIGRecord.ALGORITHM_NAME_HMAC_SHA512:
                    return 64;

                case DnsTSIGRecord.ALGORITHM_NAME_HMAC_SHA512_256:
                    return 32;

                default:
                    return ushort.MinValue;
            }
        }

        private static byte[] ComputeMAC(string algorithmName, string sharedSecret, int truncationLength, Stream s)
        {
            byte[] key;

            try
            {
                key = Convert.FromBase64String(sharedSecret);
            }
            catch (FormatException)
            {
                key = Encoding.UTF8.GetBytes(sharedSecret);
            }

            byte[] mac;

            switch (algorithmName.ToLower())
            {
                case DnsTSIGRecord.ALGORITHM_NAME_HMAC_MD5:
                    using (HMAC hmac = new HMACMD5(key))
                    {
                        mac = hmac.ComputeHash(s);
                    }
                    break;

                case DnsTSIGRecord.ALGORITHM_NAME_HMAC_SHA1:
                    using (HMAC hmac = new HMACSHA1(key))
                    {
                        mac = hmac.ComputeHash(s);
                    }
                    break;

                case DnsTSIGRecord.ALGORITHM_NAME_HMAC_SHA256:
                    using (HMAC hmac = new HMACSHA256(key))
                    {
                        mac = hmac.ComputeHash(s);
                    }
                    break;

                case DnsTSIGRecord.ALGORITHM_NAME_HMAC_SHA256_128:
                    using (HMAC hmac = new HMACSHA256(key))
                    {
                        mac = hmac.ComputeHash(s);
                    }

                    if (truncationLength < 1)
                        truncationLength = 16;

                    break;

                case DnsTSIGRecord.ALGORITHM_NAME_HMAC_SHA384:
                    using (HMAC hmac = new HMACSHA384(key))
                    {
                        mac = hmac.ComputeHash(s);
                    }
                    break;

                case DnsTSIGRecord.ALGORITHM_NAME_HMAC_SHA384_192:
                    using (HMAC hmac = new HMACSHA384(key))
                    {
                        mac = hmac.ComputeHash(s);
                    }

                    if (truncationLength < 1)
                        truncationLength = 24;

                    break;

                case DnsTSIGRecord.ALGORITHM_NAME_HMAC_SHA512:
                    using (HMAC hmac = new HMACSHA512(key))
                    {
                        mac = hmac.ComputeHash(s);
                    }
                    break;

                case DnsTSIGRecord.ALGORITHM_NAME_HMAC_SHA512_256:
                    using (HMAC hmac = new HMACSHA512(key))
                    {
                        mac = hmac.ComputeHash(s);
                    }

                    if (truncationLength < 1)
                        truncationLength = 32;

                    break;

                default:
                    throw new NotSupportedException("TSIG HMAC algorithm is not supported: " + algorithmName);
            }

            if ((truncationLength > 0) && (truncationLength < mac.Length))
            {
                byte[] truncatedMac = new byte[truncationLength];

                Buffer.BlockCopy(mac, 0, truncatedMac, 0, truncatedMac.Length);

                return truncatedMac;
            }

            return mac;
        }

        #endregion

        #region properties

        public DnsDatagramMetadata Metadata
        { get { return _metadata; } }

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

        public int QDCOUNT
        { get { return _question.Count; } }

        public int ANCOUNT
        { get { return _answer.Count; } }

        public int NSCOUNT
        { get { return _authority.Count; } }

        public int ARCOUNT
        { get { return _additional.Count; } }

        public IReadOnlyList<DnsQuestionRecord> Question
        { get { return _question; } }

        public IReadOnlyList<DnsResourceRecord> Answer
        { get { return _answer; } }

        public IReadOnlyList<DnsResourceRecord> Authority
        { get { return _authority; } }

        public IReadOnlyList<DnsResourceRecord> Additional
        { get { return _additional; } }

        [IgnoreDataMember]
        public bool IsSigned
        { get { return (_additional.Count > 0) && (_additional[_additional.Count - 1].Type == DnsResourceRecordType.TSIG); } }

        [IgnoreDataMember]
        public DnsTsigError TsigError
        {
            get
            {
                if ((_additional.Count > 0) && (_additional[_additional.Count - 1].RDATA is DnsTSIGRecord tsig))
                    return tsig.Error;

                return DnsTsigError.NoError;
            }
        }

        [IgnoreDataMember]
        public bool IsZoneTransfer
        { get { return (_question.Count > 0) && ((_question[0].Type == DnsResourceRecordType.IXFR) || (_question[0].Type == DnsResourceRecordType.AXFR)); } }

        [IgnoreDataMember]
        public Exception ParsingException
        { get { return _parsingException; } }

        [IgnoreDataMember]
        public DnsDatagram NextDatagram
        {
            get { return _nextDatagram; }
            set
            {
                if (_nextDatagram is not null)
                    throw new InvalidOperationException("Cannot overwrite next datagram.");

                _nextDatagram = value;
            }
        }

        [IgnoreDataMember]
        public object Tag { get; set; }

        #endregion
    }
}
