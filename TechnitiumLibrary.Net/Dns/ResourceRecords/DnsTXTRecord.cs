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
using System.Text;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsTXTRecord : DnsResourceRecordData
    {
        #region variables

        string _text;

        #endregion

        #region constructor

        public DnsTXTRecord(string text)
        {
            _text = text;
        }

        public DnsTXTRecord(Stream s)
            : base(s)
        { }

        public DnsTXTRecord(dynamic jsonResourceRecord)
        {
            _rdLength = Convert.ToUInt16(jsonResourceRecord.data.Value.Length);

            _text = DnsDatagram.DecodeCharacterString(jsonResourceRecord.data.Value);
        }

        #endregion

        #region protected

        protected override void Parse(Stream s)
        {
            int bytesRead = 0;
            int length;

            while (bytesRead < _rdLength)
            {
                length = s.ReadByte();
                if (length < 0)
                    throw new EndOfStreamException();

                if (_text == null)
                    _text = Encoding.ASCII.GetString(s.ReadBytes(length));
                else
                    _text += Encoding.ASCII.GetString(s.ReadBytes(length));

                bytesRead += length + 1;
            }
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries)
        {
            byte[] data = Encoding.ASCII.GetBytes(_text);
            int offset = 0;
            int length;

            do
            {
                length = data.Length - offset;
                if (length > 255)
                    length = 255;

                s.WriteByte(Convert.ToByte(length));
                s.Write(data, offset, length);

                offset += length;
            }
            while (offset < data.Length);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsTXTRecord other)
                return _text.Equals(other._text);

            return false;
        }

        public override int GetHashCode()
        {
            return _text.GetHashCode();
        }

        public override string ToString()
        {
            return DnsDatagram.EncodeCharacterString(_text);
        }

        #endregion

        #region properties

        public string Text
        { get { return _text; } }

        #endregion
    }
}
