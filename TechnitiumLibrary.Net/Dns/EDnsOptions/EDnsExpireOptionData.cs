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
using System.IO;
using System.Text.Json;

namespace TechnitiumLibrary.Net.Dns.EDnsOptions
{
    //RFC 7314 - Extension Mechanisms for DNS (EDNS) EXPIRE Option
    //https://www.rfc-editor.org/rfc/rfc7314.html
    public class EDnsExpireOptionData : EDnsOptionData
    {
        #region variables

        uint? _expire;

        #endregion

        #region constructor

        public EDnsExpireOptionData(uint? expire = null)
        {
            _expire = expire;
        }

        public EDnsExpireOptionData(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadOptionData(Stream s)
        {
            if (_length == 4)
                _expire = DnsDatagram.ReadUInt32NetworkOrder(s);
        }

        protected override void WriteOptionData(Stream s)
        {
            if (_expire is not null)
                DnsDatagram.WriteUInt32NetworkOrder(_expire.Value, s);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is EDnsExpireOptionData other)
                return _expire == other._expire;

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_expire);
        }

        public override string ToString()
        {
            return "[" + _expire.ToString() + "]";
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            if (_expire is null)
                jsonWriter.WriteNull("Expire");
            else
                jsonWriter.WriteNumber("Expire", _expire.Value);

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public uint? Expire
        { get { return _expire; } }

        public override int UncompressedLength
        { get { return _expire is null ? 0 : 4; } }

        #endregion
    }
}
