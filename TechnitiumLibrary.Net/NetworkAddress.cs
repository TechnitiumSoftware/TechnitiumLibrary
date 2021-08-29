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
using System.Net;
using System.Net.Sockets;

namespace TechnitiumLibrary.Net
{
    public class NetworkAddress : IEquatable<NetworkAddress>
    {
        #region variables

        readonly IPAddress _address;
        readonly int _prefixLength;

        #endregion

        #region constructor

        private NetworkAddress(IPAddress address, int prefixLength, bool validate)
        {
            if (validate)
            {
                if (prefixLength < 0)
                    throw new ArgumentOutOfRangeException(nameof(prefixLength));

                switch (address.AddressFamily)
                {
                    case AddressFamily.InterNetwork:
                        if (prefixLength > 32)
                            throw new ArgumentOutOfRangeException(nameof(prefixLength));

                        break;

                    case AddressFamily.InterNetworkV6:
                        if (prefixLength > 128)
                            throw new ArgumentOutOfRangeException(nameof(prefixLength));

                        break;

                    default:
                        throw new NotSupportedException("Address family not supported.");
                }
            }

            _address = address.GetNetworkAddress(prefixLength);
            _prefixLength = prefixLength;
        }

        public NetworkAddress(IPAddress address, int prefixLength)
            : this(address, prefixLength, true)
        { }

        #endregion

        #region static

        public static NetworkAddress Parse(string cidr)
        {
            if (TryParse(cidr, out NetworkAddress networkAddress))
                return networkAddress;

            throw new FormatException("CIDR value was not in expected format: " + cidr);
        }

        public static bool TryParse(string cidr, out NetworkAddress networkAddress)
        {
            string[] network = cidr.Split(new char[] { '/' }, 2);

            if (!IPAddress.TryParse(network[0], out IPAddress address))
            {
                networkAddress = null;
                return false;
            }

            int prefixLength = -1;

            if ((network.Length > 1) && (!int.TryParse(network[1], out prefixLength) || (prefixLength < 0)))
            {
                networkAddress = null;
                return false;
            }

            switch (address.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    if (prefixLength == -1)
                    {
                        prefixLength = 32;
                    }
                    else if (prefixLength > 32)
                    {
                        networkAddress = null;
                        return false;
                    }

                    break;

                case AddressFamily.InterNetworkV6:
                    if (prefixLength == -1)
                    {
                        prefixLength = 128;
                    }
                    else if (prefixLength > 128)
                    {
                        networkAddress = null;
                        return false;
                    }

                    break;

                default:
                    networkAddress = null;
                    return false;
            }

            networkAddress = new NetworkAddress(address, prefixLength, false);
            return true;
        }

        public static NetworkAddress Parse(BinaryReader bR)
        {
            IPAddress address = IPAddressExtension.Parse(bR);
            int prefixLength = bR.ReadByte();

            return new NetworkAddress(address, prefixLength, false);
        }

        #endregion

        #region public

        public bool Contains(IPAddress address)
        {
            if (_address.AddressFamily != address.AddressFamily)
                return false;

            return _address.Equals(address.GetNetworkAddress(_prefixLength));
        }

        public void WriteTo(BinaryWriter bW)
        {
            _address.WriteTo(bW);
            bW.Write(Convert.ToByte(_prefixLength));
        }

        public bool Equals(NetworkAddress other)
        {
            if (other is null)
                return false;

            if (_prefixLength != other._prefixLength)
                return false;

            if (!_address.Equals(other._address))
                return false;

            return true;
        }

        public override bool Equals(object obj)
        {
            if (obj is NetworkAddress other)
                return Equals(other);

            return base.Equals(obj);
        }

        public override string ToString()
        {
            return _address.ToString() + "/" + _prefixLength;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_address, _prefixLength);
        }

        #endregion

        #region properties

        public IPAddress Address
        { get { return _address; } }

        public int PrefixLength
        { get { return _prefixLength; } }

        #endregion
    }
}
