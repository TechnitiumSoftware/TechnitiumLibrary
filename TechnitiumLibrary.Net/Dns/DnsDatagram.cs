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

        NameServerAddress _server;
        DnsClientProtocol _protocol;
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

        public DnsDatagram(Stream s, NameServerAddress server = null, DnsClientProtocol protocol = DnsClientProtocol.Udp, double rtt = 0)
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

        internal static void ConvertDomainToLabel(string domain, Stream s, List<DnsDomainOffset> domainEntries)
        {
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
                    s.ReadBytes(buffer, 0, labelLength);
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
        { get { return _server.ToString(); } }

        public DnsClientProtocol Protocol
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
}
