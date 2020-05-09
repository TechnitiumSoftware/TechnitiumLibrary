﻿/*
Technitium Library
Copyright (C) 2020  Shreyas Zare (shreyas@technitium.com)

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
using TechnitiumLibrary.IO;

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

    public class DnsDatagram
    {
        #region variables

        readonly static RandomNumberGenerator _rnd = new RNGCryptoServiceProvider();

        DnsDatagramMetadata _metadata;

        ushort _ID;

        readonly byte _QR;
        readonly DnsOpcode _OPCODE;
        readonly byte _AA;
        readonly byte _TC;
        readonly byte _RD;
        readonly byte _RA;
        readonly byte _Z;
        readonly byte _AD;
        readonly byte _CD;
        readonly DnsResponseCode _RCODE;

        readonly IReadOnlyList<DnsQuestionRecord> _question;
        readonly IReadOnlyList<DnsResourceRecord> _answer;
        readonly IReadOnlyList<DnsResourceRecord> _authority;
        readonly IReadOnlyList<DnsResourceRecord> _additional;

        readonly Exception _parsingException;

        #endregion

        #region constructor

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

            if (_answer == null)
                _answer = Array.Empty<DnsResourceRecord>();

            if (_authority == null)
                _authority = Array.Empty<DnsResourceRecord>();

            if (_additional == null)
                _additional = Array.Empty<DnsResourceRecord>();
        }

        public DnsDatagram(Stream s)
        {
            try
            {
                _ID = ReadUInt16NetworkOrder(s);

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

                ushort QDCOUNT = ReadUInt16NetworkOrder(s);
                ushort ANCOUNT = ReadUInt16NetworkOrder(s);
                ushort NSCOUNT = ReadUInt16NetworkOrder(s);
                ushort ARCOUNT = ReadUInt16NetworkOrder(s);

                DnsQuestionRecord[] question = new DnsQuestionRecord[QDCOUNT];
                for (int i = 0; i < question.Length; i++)
                    question[i] = new DnsQuestionRecord(s);

                _question = question;

                DnsResourceRecord[] answer = new DnsResourceRecord[ANCOUNT];
                for (int i = 0; i < answer.Length; i++)
                    answer[i] = new DnsResourceRecord(s);

                _answer = answer;

                DnsResourceRecord[] authority = new DnsResourceRecord[NSCOUNT];
                for (int i = 0; i < authority.Length; i++)
                    authority[i] = new DnsResourceRecord(s);

                _authority = authority;

                DnsResourceRecord[] additional = new DnsResourceRecord[ARCOUNT];
                for (int i = 0; i < additional.Length; i++)
                    additional[i] = new DnsResourceRecord(s);

                _additional = additional;
            }
            catch (Exception ex)
            {
                _parsingException = ex;
            }

            if (_question == null)
                _question = Array.Empty<DnsQuestionRecord>();

            if (_answer == null)
                _answer = Array.Empty<DnsResourceRecord>();

            if (_authority == null)
                _authority = Array.Empty<DnsResourceRecord>();

            if (_additional == null)
                _additional = Array.Empty<DnsResourceRecord>();
        }

        public DnsDatagram(dynamic jsonResponse)
        {
            _QR = 1; //is response
            _OPCODE = DnsOpcode.StandardQuery;

            _TC = (byte)(jsonResponse.TC.Value ? 1 : 0);
            _RD = (byte)(jsonResponse.RD.Value ? 1 : 0);
            _RA = (byte)(jsonResponse.RA.Value ? 1 : 0);
            _AD = (byte)(jsonResponse.AD.Value ? 1 : 0);
            _CD = (byte)(jsonResponse.CD.Value ? 1 : 0);
            _RCODE = (DnsResponseCode)jsonResponse.Status;

            //question
            {
                ushort QDCOUNT = Convert.ToUInt16(jsonResponse.Question.Count);
                DnsQuestionRecord[] question = new DnsQuestionRecord[QDCOUNT];
                _question = question;
                int i = 0;

                foreach (dynamic jsonQuestionRecord in jsonResponse.Question)
                    question[i++] = new DnsQuestionRecord(jsonQuestionRecord);
            }

            //answer
            if (jsonResponse.Answer == null)
            {
                _answer = Array.Empty<DnsResourceRecord>();
            }
            else
            {
                ushort ANCOUNT = Convert.ToUInt16(jsonResponse.Answer.Count);
                DnsResourceRecord[] answer = new DnsResourceRecord[ANCOUNT];
                _answer = answer;
                int i = 0;

                foreach (dynamic jsonAnswerRecord in jsonResponse.Answer)
                    answer[i++] = new DnsResourceRecord(jsonAnswerRecord);
            }

            //authority
            if (jsonResponse.Authority == null)
            {
                _authority = Array.Empty<DnsResourceRecord>();
            }
            else
            {
                ushort NSCOUNT = Convert.ToUInt16(jsonResponse.Authority.Count);
                DnsResourceRecord[] authority = new DnsResourceRecord[NSCOUNT];
                _authority = authority;
                int i = 0;

                foreach (dynamic jsonAuthorityRecord in jsonResponse.Authority)
                    authority[i++] = new DnsResourceRecord(jsonAuthorityRecord);
            }

            //additional
            if (jsonResponse.Additional == null)
            {
                _additional = Array.Empty<DnsResourceRecord>();
            }
            else
            {
                ushort ARCOUNT = Convert.ToUInt16(jsonResponse.Additional.Count);
                DnsResourceRecord[] additional = new DnsResourceRecord[ARCOUNT];
                _additional = additional;
                int i = 0;

                foreach (dynamic jsonAdditionalRecord in jsonResponse.Additional)
                    additional[i++] = new DnsResourceRecord(jsonAdditionalRecord);
            }
        }

        #endregion

        #region static

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
            s.Write(b, 0, b.Length);
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
            s.Write(b, 0, b.Length);
        }

        internal static void SerializeDomainName(string domain, Stream s, List<DnsDomainOffset> domainEntries = null)
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

        internal static string DeserializeDomainName(Stream s, int maxDepth = 10)
        {
            if (maxDepth < 0)
                throw new DnsClientException("Error while reading domain name: max depth for decompression reached");

            StringBuilder domain = new StringBuilder();
            byte labelLength = s.ReadBytes(1)[0];
            byte[] buffer = null;

            while (labelLength > 0)
            {
                if ((labelLength & 0xC0) == 0xC0)
                {
                    short Offset = BitConverter.ToInt16(new byte[] { s.ReadBytes(1)[0], (byte)(labelLength & 0x3F) }, 0);
                    long CurrentPosition = s.Position;
                    s.Position = Offset;
                    domain.Append(DeserializeDomainName(s, maxDepth - 1));
                    domain.Append(".");
                    s.Position = CurrentPosition;
                    break;
                }
                else
                {
                    if (buffer == null)
                        buffer = new byte[255]; //late buffer init to avoid unnecessary allocation in most cases

                    s.ReadBytes(buffer, 0, labelLength);
                    domain.Append(Encoding.ASCII.GetString(buffer, 0, labelLength));
                    domain.Append(".");
                    labelLength = s.ReadBytes(1)[0];
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

        #region public

        public void SetMetadata(DnsDatagramMetadata metadata)
        {
            if (_metadata != null)
                throw new InvalidOperationException("Cannot overwrite existing Metadata.");

            _metadata = metadata;
        }

        public void SetIdentifier(ushort id)
        {
            _ID = id;
        }

        public void SetRandomIdentifier()
        {
            byte[] buffer = new byte[2];
            _rnd.GetBytes(buffer);

            _ID = BitConverter.ToUInt16(buffer, 0);
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

            for (int i = 0; i < _question.Count; i++)
                _question[i].WriteTo(s, domainEntries);

            for (int i = 0; i < _answer.Count; i++)
                _answer[i].WriteTo(s, domainEntries);

            for (int i = 0; i < _authority.Count; i++)
                _authority[i].WriteTo(s, domainEntries);

            for (int i = 0; i < _additional.Count; i++)
                _additional[i].WriteTo(s, domainEntries);
        }

        public void WriteTo(JsonTextWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WritePropertyName("Status");
            jsonWriter.WriteValue((int)_RCODE);

            jsonWriter.WritePropertyName("TC");
            jsonWriter.WriteValue(_TC);

            jsonWriter.WritePropertyName("RD");
            jsonWriter.WriteValue(_RD);

            jsonWriter.WritePropertyName("RA");
            jsonWriter.WriteValue(_RA);

            jsonWriter.WritePropertyName("AD");
            jsonWriter.WriteValue(_AD);

            jsonWriter.WritePropertyName("CD");
            jsonWriter.WriteValue(_CD);

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

        private void WriteSection(JsonTextWriter jsonWriter, IReadOnlyList<DnsResourceRecord> section, string sectionName)
        {
            jsonWriter.WritePropertyName(sectionName);
            jsonWriter.WriteStartArray();

            foreach (DnsResourceRecord record in section)
            {
                jsonWriter.WriteStartObject();

                jsonWriter.WritePropertyName("name");
                jsonWriter.WriteValue(record.Name + ".");

                jsonWriter.WritePropertyName("type");
                jsonWriter.WriteValue((int)record.Type);

                jsonWriter.WritePropertyName("TTL");
                jsonWriter.WriteValue(record.TtlValue);

                jsonWriter.WritePropertyName("data");
                jsonWriter.WriteValue(record.RDATA.ToString());

                jsonWriter.WriteEndObject();
            }

            jsonWriter.WriteEndArray();
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
        public Exception ParsingException
        { get { return _parsingException; } }

        [IgnoreDataMember]
        public object Tag { get; set; }

        #endregion
    }
}
