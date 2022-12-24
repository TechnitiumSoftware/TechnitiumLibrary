/*
Technitium Library
Copyright (C) 2022  Shreyas Zare (shreyas@technitium.com)

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
using System.Text.Json;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsUnknownRecordData : DnsResourceRecordData
    {
        #region variables

        byte[] _data;

        #endregion

        #region constructor

        public DnsUnknownRecordData(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadRecordData(Stream s)
        {
            _data = s.ReadBytes(_rdLength);
        }

        protected override void WriteRecordData(Stream s, List<DnsDomainOffset> domainEntries, bool canonicalForm)
        {
            s.Write(_data, 0, _data.Length);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is DnsUnknownRecordData other)
            {
                if (_data.Length != other._data.Length)
                    return false;

                for (int i = 0; i < _data.Length; i++)
                {
                    if (_data[i] != other._data[i])
                        return false;
                }

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return _data.GetHashCode();
        }

        public override string ToString()
        {
            return Convert.ToBase64String(_data);
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("Data", Convert.ToBase64String(_data));

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public byte[] DATA
        { get { return _data; } }

        public override ushort UncompressedLength
        { get { return Convert.ToUInt16(_data.Length); } }

        #endregion
    }
}
