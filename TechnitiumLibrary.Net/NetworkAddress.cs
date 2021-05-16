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
        readonly int _subnetMaskWidth;

        #endregion

        #region constructor

        private NetworkAddress(IPAddress address, int subnetMaskWidth, bool validate)
        {
            if (validate)
            {
                if (subnetMaskWidth < 0)
                    throw new ArgumentOutOfRangeException(nameof(subnetMaskWidth));

                switch (address.AddressFamily)
                {
                    case AddressFamily.InterNetwork:
                        if (subnetMaskWidth > 32)
                            throw new ArgumentOutOfRangeException(nameof(subnetMaskWidth));

                        break;

                    case AddressFamily.InterNetworkV6:
                        if (subnetMaskWidth > 128)
                            throw new ArgumentOutOfRangeException(nameof(subnetMaskWidth));

                        break;

                    default:
                        throw new NotSupportedException("Address family not supported.");
                }
            }

            _address = address.GetNetworkAddress(subnetMaskWidth);
            _subnetMaskWidth = subnetMaskWidth;
        }

        public NetworkAddress(IPAddress address, int subnetMaskWidth)
            : this(address, subnetMaskWidth, true)
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

            if ((network.Length != 2) || !IPAddress.TryParse(network[0], out IPAddress address) || !int.TryParse(network[1], out int subnetMaskWidth) || (subnetMaskWidth < 0))
            {
                networkAddress = null;
                return false;
            }

            switch (address.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    if (subnetMaskWidth > 32)
                    {
                        networkAddress = null;
                        return false;
                    }

                    break;

                case AddressFamily.InterNetworkV6:
                    if (subnetMaskWidth > 128)
                    {
                        networkAddress = null;
                        return false;
                    }

                    break;

                default:
                    networkAddress = null;
                    return false;
            }

            networkAddress = new NetworkAddress(address, subnetMaskWidth, false);
            return true;
        }

        public static NetworkAddress Parse(BinaryReader bR)
        {
            IPAddress address = IPAddressExtension.Parse(bR);
            int subnetMaskWidth = bR.ReadByte();

            return new NetworkAddress(address, subnetMaskWidth, false);
        }

        #endregion

        #region public

        public bool Contains(IPAddress address)
        {
            if (_address.AddressFamily != address.AddressFamily)
                return false;

            return _address.Equals(address.GetNetworkAddress(_subnetMaskWidth));
        }

        public void WriteTo(BinaryWriter bW)
        {
            _address.WriteTo(bW);
            bW.Write(Convert.ToByte(_subnetMaskWidth));
        }

        public bool Equals(NetworkAddress other)
        {
            if (other is null)
                return false;

            if (_subnetMaskWidth != other._subnetMaskWidth)
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
            return _address.ToString() + "/" + _subnetMaskWidth;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_address, _subnetMaskWidth);
        }

        #endregion

        #region properties

        public IPAddress Address
        { get { return _address; } }

        public int SubnetMaskWidth
        { get { return _subnetMaskWidth; } }

        #endregion
    }
}
