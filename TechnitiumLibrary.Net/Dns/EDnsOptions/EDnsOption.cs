/*
Technitium Library
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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
    public enum EDnsOptionCode : ushort
    {
        RESERVED = 0,
        LLQ = 1,
        UPDATE_LEASE = 2,
        NSID = 3,
        DAU = 5,
        DHU = 6,
        N3U = 7,
        EDNS_CLIENT_SUBNET = 8,
        EDNS_EXPIRE = 9,
        COOKIE = 10,
        EDNS_TCP_KEEPALIVE = 11,
        PADDING = 12,
        CHAIN = 13,
        EDNS_KEY_TAG = 14,
        EXTENDED_DNS_ERROR = 15,
        EDNS_CLIENT_TAG = 16,
        EDNS_SERVER_TAG = 17,
        REPORT_CHANNEL = 18,
        ZONEVERSION = 19,
        UMBRELLA_IDENT = 20292,
        DEVICE_ID = 26946
    }

    public class EDnsOption
    {
        #region variables

        readonly EDnsOptionCode _code;
        readonly EDnsOptionData _data;

        #endregion

        #region constructors

        public EDnsOption(EDnsOptionCode code, EDnsOptionData data)
        {
            _code = code;
            _data = data;
        }

        public EDnsOption(Stream s)
        {
            _code = (EDnsOptionCode)DnsDatagram.ReadUInt16NetworkOrder(s);
            switch (_code)
            {
                case EDnsOptionCode.EDNS_CLIENT_SUBNET:
                    _data = new EDnsClientSubnetOptionData(s);
                    break;

                case EDnsOptionCode.EXTENDED_DNS_ERROR:
                    _data = new EDnsExtendedDnsErrorOptionData(s);
                    break;

                default:
                    _data = new EDnsUnknownOptionData(s);
                    break;
            }
        }

        #endregion

        #region public

        public void WriteTo(Stream s)
        {
            DnsDatagram.WriteUInt16NetworkOrder((ushort)_code, s);

            _data.WriteTo(s);
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is EDnsOption other)
            {
                if (_code != other._code)
                    return false;

                return _data.Equals(other._data);
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_code, _data);
        }

        public override string ToString()
        {
            return _code.ToString() + " " + _data.ToString();
        }

        public void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("Code", _code.ToString());
            jsonWriter.WriteString("Length", _data.Length + " bytes");

            jsonWriter.WritePropertyName("Data");
            _data.SerializeTo(jsonWriter);

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public EDnsOptionCode Code
        { get { return _code; } }

        public EDnsOptionData Data
        { get { return _data; } }

        public int UncompressedLength
        { get { return 2 + 2 + _data.UncompressedLength; } }

        #endregion
    }
}
