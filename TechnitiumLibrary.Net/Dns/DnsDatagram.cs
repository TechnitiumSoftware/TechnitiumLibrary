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

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns
{
    public class DnsDatagram
    {
        #region variables

        DnsDatagramMetadata _metadata;

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

            if (_answer == null)
                _answer = new DnsResourceRecord[] { };

            if (_authority == null)
                _authority = new DnsResourceRecord[] { };

            if (_additional == null)
                _additional = new DnsResourceRecord[] { };
        }

        public DnsDatagram(Stream s)
        {
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

        public DnsDatagram(dynamic jsonResponse)
        {
            _header = new DnsHeader(jsonResponse);

            {
                _question = new DnsQuestionRecord[_header.QDCOUNT];
                int i = 0;
                foreach (dynamic jsonQuestionRecord in jsonResponse.Question)
                    _question[i++] = new DnsQuestionRecord(jsonQuestionRecord);
            }

            if (jsonResponse.Answer == null)
            {
                _answer = new DnsResourceRecord[] { };
            }
            else
            {
                _answer = new DnsResourceRecord[_header.ANCOUNT];
                int i = 0;
                foreach (dynamic jsonAnswerRecord in jsonResponse.Answer)
                    _answer[i++] = new DnsResourceRecord(jsonAnswerRecord);
            }

            if (jsonResponse.Authority == null)
            {
                _authority = new DnsResourceRecord[] { };
            }
            else
            {
                _authority = new DnsResourceRecord[_header.NSCOUNT];
                int i = 0;
                foreach (dynamic jsonAuthorityRecord in jsonResponse.Authority)
                    _authority[i++] = new DnsResourceRecord(jsonAuthorityRecord);
            }

            if (jsonResponse.Additional == null)
            {
                _additional = new DnsResourceRecord[] { };
            }
            else
            {
                _additional = new DnsResourceRecord[_header.ARCOUNT];
                int i = 0;
                foreach (dynamic jsonAdditionalRecord in jsonResponse.Additional)
                    _additional[i++] = new DnsResourceRecord(jsonAdditionalRecord);
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

        internal static void SerializeDomainName(string domain, Stream s, List<DnsDomainOffset> domainEntries)
        {
            IsDomainNameValid(domain, true);

            while (!string.IsNullOrEmpty(domain))
            {
                if (domainEntries != null)
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

        internal static string DeserializeDomainName(Stream s)
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
                    domain.Append(DeserializeDomainName(s) + ".");
                    s.Position = CurrentPosition;
                    break;
                }
                else
                {
                    s.ReadBytes(buffer, 0, labelLength);
                    domain.Append(Encoding.ASCII.GetString(buffer, 0, labelLength) + ".");
                    labelLength = Convert.ToByte(s.ReadByte());
                }
            }

            if (domain.Length > 0)
                domain.Length--;

            string domainName = domain.ToString();
            IsDomainNameValid(domainName, true);

            return domainName;
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

        #endregion

        #region public

        public void SetMetadata(DnsDatagramMetadata metadata)
        {
            if (_metadata != null)
                throw new InvalidOperationException("Cannot overwrite existing Metadata.");

            _metadata = metadata;
        }

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

        public DnsDatagramMetadata Metadata
        { get { return _metadata; } }

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

        [IgnoreDataMember]
        public string Tag { get; set; }

        #endregion
    }
}
