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
using System.IO;
using System.Text.Json;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.EDnsOptions
{
    public class EDnsUnknownOptionData : EDnsOptionData
    {
        #region variables

        byte[] _data;

        #endregion

        #region constructor

        public EDnsUnknownOptionData(byte[] data)
        {
            _data = data;
        }

        public EDnsUnknownOptionData(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadOptionData(Stream s)
        {
            if (_length > 0)
                _data = s.ReadBytes(_length);
            else
                _data = Array.Empty<byte>();
        }

        protected override void WriteOptionData(Stream s)
        {
            s.Write(_data);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is EDnsUnknownOptionData other)
            {
                if (!BinaryNumber.Equals(_data, other._data))
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_data);
        }

        public override string ToString()
        {
            return string.Empty;
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("Data", Convert.ToBase64String(_data));

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public byte[] Data
        { get { return _data; } }

        public override int UncompressedLength
        { get { return _data.Length; } }

        #endregion
    }
}
