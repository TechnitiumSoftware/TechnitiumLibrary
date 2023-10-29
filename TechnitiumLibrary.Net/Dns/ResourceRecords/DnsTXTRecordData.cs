/*
Technitium Library
Copyright (C) 2023  Shreyas Zare (shreyas@technitium.com)

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
using System.Text.Json;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsTXTRecordData : DnsResourceRecordData
    {
        #region variables

        string _text;

        byte[] _rData;

        #endregion

        #region constructor

        public DnsTXTRecordData(string text)
        {
            _text = text;
        }

        public DnsTXTRecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _rData = s.ReadBytes(_rdLength);

            using (MemoryStream mS = new MemoryStream(_rData))
            {
                int bytesRead = 0;
                int length;

                while (bytesRead < _rdLength)
                {
                    length = mS.ReadByte();
                    if (length < 0)
                        throw new EndOfStreamException();

                    if (_text == null)
                        _text = Encoding.ASCII.GetString(mS.ReadBytes(length));
                    else
                        _text += Encoding.ASCII.GetString(mS.ReadBytes(length));

                    bytesRead += length + 1;
                }
            }
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            if (_rData is null)
            {
                using (MemoryStream mS = new MemoryStream())
                {
                    byte[] data = Encoding.ASCII.GetBytes(_text);
                    int offset = 0;
                    int length;

                    do
                    {
                        length = data.Length - offset;
                        if (length > 255)
                            length = 255;

                        mS.WriteByte(Convert.ToByte(length));
                        mS.Write(data, offset, length);

                        offset += length;
                    }
                    while (offset < data.Length);

                    _rData = mS.ToArray();
                }
            }

            s.Write(_rData);
        }

        #endregion

        #region internal

        internal static async Task<DnsTXTRecordData> FromZoneFileEntryAsync(ZoneFile zoneFile)
        {
            Stream rdata = await zoneFile.GetRData();
            if (rdata is not null)
                return new DnsTXTRecordData(rdata);

            string text = null;

            do
            {
                string value = await zoneFile.PopItemAsync();
                if (value is null)
                    break;

                if (text is null)
                    text = value;
                else
                    text += value;
            }
            while (true);

            return new DnsTXTRecordData(text);
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            string value = null;

            int startIndex = 0;
            int length;

            do
            {
                length = _text.Length - startIndex;
                if (length > 255)
                    length = 255;

                string part = _text.Substring(startIndex, length);

                if (value is null)
                    value = DnsDatagram.EncodeCharacterString(part);
                else
                    value += " " + DnsDatagram.EncodeCharacterString(part);

                startIndex += length;
            }
            while (startIndex < _text.Length);

            return value;
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsTXTRecordData other)
                return _text.Equals(other._text);

            return false;
        }

        public override int GetHashCode()
        {
            return _text.GetHashCode();
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("Text", _text);

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public string Text
        { get { return _text; } }

        public override int UncompressedLength
        { get { return Convert.ToInt32(Math.Ceiling(_text.Length / 255d)) + _text.Length; } }

        #endregion
    }
}
