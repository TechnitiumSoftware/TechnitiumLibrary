/*
Technitium Library
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)

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

        IReadOnlyList<string> _characterStrings;

        byte[] _rData;

        #endregion

        #region constructor

        public DnsTXTRecordData(IReadOnlyList<string> characterStrings)
        {
            foreach (string characterString in characterStrings)
            {
                if (Encoding.ASCII.GetBytes(characterString).Length > 255)
                    throw new DnsClientException("TXT record character-string length cannot exceed 255 bytes.");
            }

            _characterStrings = characterStrings;

            Serialize();
        }

        public DnsTXTRecordData(string text)
        {
            byte[] data = Encoding.ASCII.GetBytes(text);
            string[] characterStrings = new string[Convert.ToInt32(Math.Ceiling(text.Length / 255d))];

            for (int i = 0; i < characterStrings.Length; i++)
            {
                int index = i * 255;
                int count = Math.Min(data.Length - index, 255);

                characterStrings[i] = Encoding.ASCII.GetString(data, index, count);
            }

            _characterStrings = characterStrings;

            Serialize();
        }

        public DnsTXTRecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region private

        private void Serialize()
        {
            using (MemoryStream mS = new MemoryStream(UncompressedLength))
            {
                byte[] buffer = new byte[255];
                int bytesWritten;

                foreach (string characterString in _characterStrings)
                {
                    if (!Encoding.ASCII.TryGetBytes(characterString, buffer, out bytesWritten))
                        throw new InvalidOperationException();

                    mS.WriteByte(Convert.ToByte(bytesWritten));
                    mS.Write(buffer, 0, bytesWritten);
                }

                _rData = mS.ToArray();
            }
        }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _rData = s.ReadExactly(_rdLength);

            List<string> characterStrings = new List<string>(1);

            using (MemoryStream mS = new MemoryStream(_rData))
            {
                int bytesRead = 0;
                int count;
                byte[] buffer = new byte[255];

                while (bytesRead < _rdLength)
                {
                    count = mS.ReadByte();
                    if (count < 0)
                        throw new EndOfStreamException();

                    mS.ReadExactly(buffer, 0, count);
                    characterStrings.Add(Encoding.ASCII.GetString(buffer, 0, count));

                    bytesRead += count + 1;
                }
            }

            _characterStrings = characterStrings;
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            s.Write(_rData);
        }

        #endregion

        #region internal

        internal static async Task<DnsTXTRecordData> FromZoneFileEntryAsync(ZoneFile zoneFile)
        {
            Stream rdata = await zoneFile.GetRData();
            if (rdata is not null)
                return new DnsTXTRecordData(rdata);

            List<string> characterStrings = new List<string>(1);

            do
            {
                string value = await zoneFile.PopItemAsync();
                if (value is null)
                    break;

                characterStrings.Add(value);
            }
            while (true);

            return new DnsTXTRecordData(characterStrings);
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            string value = null;

            foreach (string characterString in _characterStrings)
            {
                if (value is null)
                    value = DnsDatagram.EncodeCharacterString(characterString);
                else
                    value += " " + DnsDatagram.EncodeCharacterString(characterString);
            }

            return value;
        }

        #endregion

        #region public

        public string GetText()
        {
            string text = null;

            foreach (string characterString in _characterStrings)
            {
                if (text is null)
                    text = characterString;
                else
                    text += characterString;
            }

            return text;
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsTXTRecordData other)
                return _characterStrings.Equals<string>(other._characterStrings);

            return false;
        }

        public override int GetHashCode()
        {
            return _characterStrings.GetArrayHashCode();
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("Text", GetText());

            jsonWriter.WriteStartArray("CharacterStrings");

            foreach (string characterString in _characterStrings)
                jsonWriter.WriteStringValue(characterString);

            jsonWriter.WriteEndArray();

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public IReadOnlyList<string> CharacterStrings
        { get { return _characterStrings; } }

        public override int UncompressedLength
        {
            get
            {
                int length = 0;

                foreach (string characterString in _characterStrings)
                    length += 1 + characterString.Length;

                return length;
            }
        }

        #endregion
    }
}
