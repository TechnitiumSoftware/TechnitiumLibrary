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

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsNSECRecord : DnsResourceRecordData
    {
        #region variables

        string _nextDomainName;
        IReadOnlyList<DnsResourceRecordType> _types;

        byte[] _rData;

        #endregion

        #region constructor

        public DnsNSECRecord(string nextDomainName, IReadOnlyList<DnsResourceRecordType> types)
        {
            _nextDomainName = nextDomainName;
            _types = types;
        }

        public DnsNSECRecord(Stream s)
            : base(s)
        { }

        public DnsNSECRecord(dynamic jsonResourceRecord)
        {
            throw new NotSupportedException();
        }

        #endregion

        #region static

        public static int CanonicalComparison(string domain1, string domain2)
        {
            string[] labels1 = domain1.ToLower().Split('.');
            string[] labels2 = domain2.ToLower().Split('.');

            int minLength = labels1.Length;

            if (labels2.Length < minLength)
                minLength = labels2.Length;

            for (int i = 0; i < minLength; i++)
            {
                int value = CanonicalComparison(Encoding.ASCII.GetBytes(labels1[labels1.Length - 1 - i]), Encoding.ASCII.GetBytes(labels2[labels2.Length - 1 - i]));
                if (value != 0)
                    return value;
            }

            if (labels1.Length < labels2.Length)
                return -1;

            if (labels1.Length > labels2.Length)
                return 1;

            return 0;
        }

        public static int CanonicalComparison(byte[] x, byte[] y)
        {
            int minLength = x.Length;

            if (y.Length < minLength)
                minLength = y.Length;

            for (int i = 0; i < minLength; i++)
            {
                if (x[i] < y[i])
                    return -1;

                if (x[i] > y[i])
                    return 1;
            }

            if (x.Length < y.Length)
                return -1;

            if (x.Length > y.Length)
                return 1;

            return 0;
        }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _nextDomainName = DnsDatagram.DeserializeDomainName(s);

            List<DnsResourceRecordType> types = new List<DnsResourceRecordType>();
            int bytesRead = DnsDatagram.GetSerializeDomainNameLength(_nextDomainName);

            while (bytesRead < _rdLength)
            {
                int windowBlockNumber = s.ReadByte();
                if (windowBlockNumber < 0)
                    throw new EndOfStreamException();

                int bitmapLength = s.ReadByte();
                if (bitmapLength < 0)
                    throw new EndOfStreamException();

                byte[] bitmap = s.ReadBytes(bitmapLength);

                windowBlockNumber <<= 8;

                for (int i = 0; i < bitmapLength; i++)
                {
                    int currentByte = bitmap[i];
                    int currentPosition = i * 8;

                    for (int count = 0, bitMask = 0x80; count < 8; count++, bitMask >>= 1)
                    {
                        if ((currentByte & bitMask) > 0)
                            types.Add((DnsResourceRecordType)(windowBlockNumber | (currentPosition + count)));
                    }
                }

                bytesRead += 1 + 1 + bitmapLength;
            }

            _types = types;
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            if (_rData is null)
            {
                using (MemoryStream mS = new MemoryStream())
                {
                    DnsDatagram.SerializeDomainName(canonicalForm ? _nextDomainName.ToLower() : _nextDomainName, mS);

                    byte[] windowBlockSurvey = new byte[256];

                    foreach (DnsResourceRecordType type in _types)
                    {
                        int value = (int)type;
                        int windowBlockNumber = value >> 8;
                        byte bitNumber = (byte)(value & 0xff);

                        if (windowBlockSurvey[windowBlockNumber] < bitNumber)
                            windowBlockSurvey[windowBlockNumber] = bitNumber;
                    }

                    for (int currentWindowBlockNumber = 0; currentWindowBlockNumber < windowBlockSurvey.Length; currentWindowBlockNumber++)
                    {
                        int maxBits = windowBlockSurvey[currentWindowBlockNumber];
                        if (maxBits > 0)
                        {
                            int bitmapLength = (int)Math.Ceiling((maxBits + 1) / 8.0);
                            byte[] bitmap = new byte[bitmapLength];

                            foreach (DnsResourceRecordType type in _types)
                            {
                                int value = (int)type;
                                int windowBlockNumber = value >> 8;

                                if (windowBlockNumber == currentWindowBlockNumber)
                                {
                                    byte bitNumber = (byte)(value & 0xff);
                                    int i = bitNumber / 8;
                                    byte count = (byte)(0x80 >> (bitNumber % 8));

                                    bitmap[i] |= count;
                                }
                            }

                            mS.WriteByte((byte)currentWindowBlockNumber);
                            mS.WriteByte((byte)bitmapLength);
                            mS.Write(bitmap, 0, bitmapLength);
                        }
                    }

                    _rData = mS.ToArray();
                }
            }

            s.Write(_rData);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsNSECRecord other)
            {
                if (!_nextDomainName.Equals(other._nextDomainName, StringComparison.OrdinalIgnoreCase))
                    return false;

                if (_types.Count != other._types.Count)
                    return false;

                for (int i = 0; i < _types.Count; i++)
                {
                    if (_types[i] != other._types[i])
                        return false;
                }

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_nextDomainName, _types);
        }

        public override string ToString()
        {
            string str = _nextDomainName + " ( ";

            foreach (DnsResourceRecordType type in _types)
                str += type.ToString() + " ";

            str += " )";

            return str;
        }

        #endregion

        #region properties

        public string NextDomainName
        { get { return _nextDomainName; } }

        public IReadOnlyList<DnsResourceRecordType> Types
        { get { return _types; } }

        [IgnoreDataMember]
        public override ushort UncompressedLength
        { get { return Convert.ToUInt16(DnsDatagram.GetSerializeDomainNameLength(_nextDomainName) + 4); } }

        #endregion
    }
}
