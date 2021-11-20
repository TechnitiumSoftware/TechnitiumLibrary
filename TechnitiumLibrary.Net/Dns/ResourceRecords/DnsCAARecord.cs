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
    public class DnsCAARecord : DnsResourceRecordData
    {
        #region variables

        byte _flags;
        string _tag;
        string _value;

        #endregion

        #region constructor

        public DnsCAARecord(byte flags, string tag, string value)
        {
            if (tag.Length < 1)
                throw new InvalidDataException("CAA tag length must be at least 1.");

            _flags = flags;
            _tag = tag.ToLower();
            _value = value;
        }

        public DnsCAARecord(Stream s)
            : base(s)
        { }

        public DnsCAARecord(dynamic jsonResourceRecord)
        {
            _rdLength = Convert.ToUInt16(jsonResourceRecord.data.Value.Length);

            string[] parts = (jsonResourceRecord.data.Value as string).Split(new char[] { ' ' }, 3, StringSplitOptions.RemoveEmptyEntries);

            _flags = byte.Parse(parts[0]);
            _tag = parts[1];
            _value = DnsDatagram.DecodeCharacterString(parts[2]);
        }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            int flags = s.ReadByte();
            if (flags < 0)
                throw new EndOfStreamException();

            _flags = (byte)flags;

            int tagLength = s.ReadByte();
            if (tagLength < 0)
                throw new EndOfStreamException();

            if (tagLength < 1)
                throw new InvalidDataException("CAA tag length must be at least 1.");

            _tag = Encoding.ASCII.GetString(s.ReadBytes(tagLength)).ToLower();
            _value = Encoding.ASCII.GetString(s.ReadBytes(_rdLength - tagLength - 2));
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            s.WriteByte(_flags);
            s.WriteByte(Convert.ToByte(_tag.Length));
            s.Write(Encoding.ASCII.GetBytes(_tag));
            s.Write(Encoding.ASCII.GetBytes(_value));
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsCAARecord other)
            {
                if (_flags != other._flags)
                    return false;

                if (_tag != other._tag)
                    return false;

                if (_value != other._value)
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return _value.GetHashCode();
        }

        public override string ToString()
        {
            return _flags + " " + _tag + " " + DnsDatagram.EncodeCharacterString(_value);
        }

        #endregion

        #region properties

        public byte Flags
        { get { return _flags; } }

        public string Tag
        { get { return _tag; } }

        public string Value
        { get { return _value; } }

        [IgnoreDataMember]
        public override ushort UncompressedLength
        { get { return Convert.ToUInt16(1 + 1 + _tag.Length + _value.Length); } }

        #endregion
    }
}
