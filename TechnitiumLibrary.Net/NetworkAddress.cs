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
using System.Net;
using System.Net.Sockets;

namespace TechnitiumLibrary.Net
{
    public class NetworkAddress : IEquatable<NetworkAddress>
    {
        #region variables

        readonly IPAddress _address;
        readonly byte _prefixLength;

        #endregion

        #region constructor

        private NetworkAddress(IPAddress address, byte prefixLength, bool validate)
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

        public NetworkAddress(IPAddress address, byte prefixLength)
            : this(address, prefixLength, true)
        { }

        #endregion

        #region static

        public static NetworkAddress Parse(string network)
        {
            if (TryParse(network, out NetworkAddress networkAddress))
                return networkAddress;

            throw new FormatException("Invalid network address was specified: " + network);
        }

        public static bool TryParse(string network, out NetworkAddress networkAddress)
        {
            string[] parts = network.Split(new char[] { '/' }, 2);

            if (!IPAddress.TryParse(parts[0], out IPAddress address))
            {
                networkAddress = null;
                return false;
            }

            byte prefixLength = 255;

            if ((parts.Length > 1) && !byte.TryParse(parts[1], out prefixLength))
            {
                networkAddress = null;
                return false;
            }

            switch (address.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    if (prefixLength == 255)
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
                    if (prefixLength == 255)
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

        public static NetworkAddress ReadFrom(BinaryReader bR)
        {
            IPAddress address = IPAddressExtensions.ReadFrom(bR);
            byte prefixLength = bR.ReadByte();

            return new NetworkAddress(address, prefixLength, false);
        }

        #endregion

        #region public

        public IPAddress GetLastAddress()
        {
            switch (_address.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    {
                        uint addr = _address.ConvertIpToNumber();
                        uint hostMask = ~(0xFFFFFFFFu << (32 - _prefixLength));
                        uint broadcast = addr | hostMask;

                        return IPAddressExtensions.ConvertNumberToIp(broadcast);
                    }

                case AddressFamily.InterNetworkV6:
                    {
                        byte[] network = _address.GetAddressBytes();
                        byte[] broadcast = new byte[16];
                        int copyBytes = _prefixLength / 8;
                        int balanceBits = _prefixLength - (copyBytes * 8);

                        Buffer.BlockCopy(network, 0, broadcast, 0, copyBytes);

                        if (balanceBits > 0)
                        {
                            broadcast[copyBytes] = (byte)(network[copyBytes] | ~(0xFF << (8 - balanceBits)));
                            copyBytes++;
                        }

                        for (int i = copyBytes; i < 16; i++)
                            broadcast[i] = 0xFF;

                        return new IPAddress(broadcast);
                    }

                default:
                    throw new NotSupportedException();
            }
        }

        public bool Contains(IPAddress address)
        {
            if (_address.AddressFamily != address.AddressFamily)
                return false;

            return _address.Equals(address.GetNetworkAddress(_prefixLength));
        }

        public void WriteTo(BinaryWriter bW)
        {
            _address.WriteTo(bW);
            bW.Write(_prefixLength);
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
            switch (_address.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    if (_prefixLength == 32)
                        return _address.ToString();

                    break;

                case AddressFamily.InterNetworkV6:
                    if (_prefixLength == 128)
                        return _address.ToString();

                    break;
            }

            return _address.ToString() + "/" + _prefixLength;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_address, _prefixLength);
        }

        #endregion

        #region properties

        public AddressFamily AddressFamily
        { get { return _address.AddressFamily; } }

        public IPAddress Address
        { get { return _address; } }

        public byte PrefixLength
        { get { return _prefixLength; } }

        #endregion
    }
}
