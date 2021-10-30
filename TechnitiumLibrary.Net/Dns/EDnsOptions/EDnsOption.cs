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
using System.IO;
using System.Runtime.Serialization;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.EDnsOptions
{
    public enum EDnsOptionCode : ushort
    {
        LLQ = 1,
        UL = 2,
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
        UMBRELLA_IDENT = 20292,
        DEVICE_ID = 26946
    }

    public class EDnsOption
    {
        #region variables

        readonly EDnsOptionCode _code;
        readonly byte[] _data;

        #endregion

        #region constructors

        public EDnsOption(EDnsOptionCode code, byte[] data)
        {
            _code = code;
            _data = data;
        }

        public EDnsOption(Stream s)
        {
            _code = (EDnsOptionCode)DnsDatagram.ReadUInt16NetworkOrder(s);
            ushort length = DnsDatagram.ReadUInt16NetworkOrder(s);

            if (length > 0)
                _data = s.ReadBytes(length);
            else
                _data = Array.Empty<byte>();
        }

        #endregion

        #region public

        public void WriteTo(Stream s)
        {
            DnsDatagram.WriteUInt16NetworkOrder((ushort)_code, s);
            DnsDatagram.WriteUInt16NetworkOrder((ushort)_data.Length, s);
            s.Write(_data);
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

                if (!BinaryNumber.Equals(_data, other._data))
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_code, _data);
        }

        #endregion

        #region properties

        public EDnsOptionCode Code
        { get { return _code; } }

        public ushort Length
        { get { return (ushort)_data.Length; } }

        public byte[] Data
        { get { return _data; } }

        [IgnoreDataMember]
        public ushort UncompressedLength
        { get { return (ushort)(4 + _data.Length); } }

        #endregion
    }
}
