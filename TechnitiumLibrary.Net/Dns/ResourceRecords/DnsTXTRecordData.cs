/*
Technitium Library
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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

        IReadOnlyList<ArraySegment<byte>> _characterStrings;

        byte[] _rData;

        #endregion

        #region constructor

        public DnsTXTRecordData(IReadOnlyList<ArraySegment<byte>> characterStrings)
        {
            foreach (ArraySegment<byte> characterString in characterStrings)
            {
                if (characterString.Count > 255)
                    throw new DnsClientException("TXT record character-string length cannot exceed 255 bytes.");
            }

            _characterStrings = characterStrings;

            Serialize();
        }

        public DnsTXTRecordData(IReadOnlyList<string> characterStrings)
        {
            List<ArraySegment<byte>> cs = new List<ArraySegment<byte>>(characterStrings.Count);

            foreach (string characterString in characterStrings)
            {
                byte[] value = Encoding.UTF8.GetBytes(characterString);
                if (value.Length > 255)
                    throw new DnsClientException("TXT record character-string length cannot exceed 255 bytes.");

                cs.Add(value);
            }

            _characterStrings = cs;

            Serialize();
        }

        public DnsTXTRecordData(string text)
        {
            byte[] data = Encoding.UTF8.GetBytes(text);
            ArraySegment<byte>[] characterStrings = new ArraySegment<byte>[Convert.ToInt32(Math.Ceiling(data.Length / 255d))];

            for (int i = 0; i < characterStrings.Length; i++)
            {
                int offset = i * 255;
                int count = Math.Min(data.Length - offset, 255);

                characterStrings[i] = new ArraySegment<byte>(data, offset, count);
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
            using (MemoryStream mS = new MemoryStream(256))
            {
                foreach (ArraySegment<byte> characterString in _characterStrings)
                {
                    mS.WriteByte((byte)characterString.Count);
                    mS.Write(characterString);
                }

                _rData = mS.ToArray();
            }
        }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _rData = s.ReadExactly(_rdLength);

            List<ArraySegment<byte>> characterStrings = new List<ArraySegment<byte>>(Convert.ToInt32(Math.Ceiling(_rData.Length / 255d)));
            int offset = 0;
            int count;

            while (offset < _rdLength)
            {
                count = _rData[offset];
                offset++;

                characterStrings.Add(new ArraySegment<byte>(_rData, offset, count));
                offset += count;
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

            if (characterStrings.Count == 1)
                return new DnsTXTRecordData(characterStrings[0]);

            return new DnsTXTRecordData(characterStrings);
        }

        internal override string ToZoneFileEntry(string originDomain = null)
        {
            string value = null;

            foreach (ArraySegment<byte> characterString in _characterStrings)
            {
                string cs = DnsDatagram.EncodeCharacterString(Encoding.UTF8.GetString(characterString));

                if (value is null)
                    value = cs;
                else
                    value += " " + cs;
            }

            return value;
        }

        #endregion

        #region public

        public string GetText()
        {
            using (MemoryStream mS = new MemoryStream(256 * _characterStrings.Count))
            {
                foreach (ArraySegment<byte> characterString in _characterStrings)
                    mS.Write(characterString);

                return Encoding.UTF8.GetString(mS.ToArray());
            }
        }

        public IReadOnlyList<string> GetCharacterStrings()
        {
            List<string> characterStrings = new List<string>(_characterStrings.Count);

            foreach (ArraySegment<byte> characterString in _characterStrings)
                characterStrings.Add(Encoding.UTF8.GetString(characterString));

            return characterStrings;
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsTXTRecordData other)
            {
                return _characterStrings.ListEquals(other._characterStrings, delegate (ArraySegment<byte> a1, ArraySegment<byte> a2)
                {
                    return a1.ListEquals(a2);
                });
            }

            return false;
        }

        public override int GetHashCode()
        {
            int hashCode = 0;

            foreach (ArraySegment<byte> characterString in _characterStrings)
                hashCode ^= characterString.GetArrayHashCode();

            return hashCode;
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("Text", GetText());

            jsonWriter.WriteStartArray("CharacterStrings");

            foreach (ArraySegment<byte> characterString in _characterStrings)
                jsonWriter.WriteStringValue(Encoding.UTF8.GetString(characterString));

            jsonWriter.WriteEndArray();

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public IReadOnlyList<ArraySegment<byte>> CharacterStrings
        { get { return _characterStrings; } }

        public override int UncompressedLength
        { get { return _rData.Length; } }

        #endregion
    }
}
