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
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Serialization;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Net.Dns.EDnsOptions
{
    public enum EDnsClientSubnetAddressFamily : ushort
    {
        IPv4 = 1,
        IPv6 = 2
    }

    public class EDnsClientSubnetOptionData : EDnsOptionData
    {
        #region variables

        EDnsClientSubnetAddressFamily _family;
        byte _sourcePrefixLength;
        byte _scopePrefixLength;
        IPAddress _address;

        #endregion

        #region constructor

        public EDnsClientSubnetOptionData(byte sourcePrefixLength, byte scopePrefixLength, IPAddress address)
        {
            switch (address.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    _family = EDnsClientSubnetAddressFamily.IPv4;
                    break;

                case AddressFamily.InterNetworkV6:
                    _family = EDnsClientSubnetAddressFamily.IPv6;
                    break;

                default:
                    throw new NotSupportedException("AddressFamily is not supported.");
            }

            _sourcePrefixLength = sourcePrefixLength;
            _scopePrefixLength = scopePrefixLength;
            _address = address;
        }

        public EDnsClientSubnetOptionData(Stream s)
            : base(s)
        { }

        #endregion

        #region static

        public static EDnsOption[] GetEDnsClientSubnetOption(byte sourcePrefixLength, byte scopePrefixLength, IPAddress address)
        {
            return new EDnsOption[] { new EDnsOption(EDnsOptionCode.EDNS_CLIENT_SUBNET, new EDnsClientSubnetOptionData(sourcePrefixLength, scopePrefixLength, address)) };
        }

        public static EDnsOption[] GetEDnsClientSubnetOption(NetworkAddress eDnsClientSubnet)
        {
            if (eDnsClientSubnet is null)
                return null;

            return new EDnsOption[] { new EDnsOption(EDnsOptionCode.EDNS_CLIENT_SUBNET, new EDnsClientSubnetOptionData(eDnsClientSubnet.PrefixLength, 0, eDnsClientSubnet.Address)) };
        }

        #endregion

        #region protected

        protected override void ReadOptionData(Stream s)
        {
            _family = (EDnsClientSubnetAddressFamily)DnsDatagram.ReadUInt16NetworkOrder(s);
            _sourcePrefixLength = s.ReadByteValue();
            _scopePrefixLength = s.ReadByteValue();

            int count = _sourcePrefixLength / 8;
            if ((count * 8) < _sourcePrefixLength)
                count++;

            byte[] buffer;

            switch (_family)
            {
                case EDnsClientSubnetAddressFamily.IPv4:
                    buffer = new byte[4];
                    break;

                case EDnsClientSubnetAddressFamily.IPv6:
                    buffer = new byte[16];
                    break;

                default:
                    throw new NotSupportedException("EDNS Client Subnet address family not supported: " + _family.ToString());
            }

            s.Read(buffer, 0, count);

            _address = new IPAddress(buffer);
        }

        protected override void WriteOptionData(Stream s)
        {
            DnsDatagram.WriteUInt16NetworkOrder((ushort)_family, s);
            s.WriteByte(_sourcePrefixLength);
            s.WriteByte(_scopePrefixLength);

            int count = _sourcePrefixLength / 8;
            if ((count * 8) < _sourcePrefixLength)
                count++;

            byte[] buffer = _address.GetAddressBytes();

            s.Write(buffer, 0, count);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is EDnsClientSubnetOptionData other)
            {
                if (_family != other._family)
                    return false;

                if (_sourcePrefixLength != other._sourcePrefixLength)
                    return false;

                if (_scopePrefixLength != other._scopePrefixLength)
                    return false;

                if (!_address.Equals(other._address))
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_family, _sourcePrefixLength, _scopePrefixLength, _address);
        }

        public override string ToString()
        {
            return "[" + _family.ToString() + " " + _sourcePrefixLength.ToString() + " " + _scopePrefixLength + " " + _address.ToString() + "]";
        }

        #endregion

        #region properties

        public EDnsClientSubnetAddressFamily Family
        { get { return _family; } }

        public byte SourcePrefixLength
        { get { return _sourcePrefixLength; } }

        public byte ScopePrefixLength
        { get { return _scopePrefixLength; } }

        public IPAddress Address
        { get { return _address; } }

        [IgnoreDataMember]
        public override ushort UncompressedLength
        { get { return Convert.ToUInt16(2 + 1 + 1 + (_family == EDnsClientSubnetAddressFamily.IPv4 ? 4 : 16)); } }

        #endregion
    }
}
