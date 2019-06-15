/*
Technitium Library
Copyright (C) 2019  Shreyas Zare (shreyas@technitium.com)

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
    public static class IPAddressExtension
    {
        #region static

        public static IPAddress Parse(BinaryReader bR)
        {
            switch (bR.ReadByte())
            {
                case 1:
                    return new IPAddress(bR.ReadBytes(4));

                case 2:
                    return new IPAddress(bR.ReadBytes(16));

                default:
                    throw new NotSupportedException("AddressFamily not supported.");
            }
        }

        public static void WriteTo(this IPAddress address, BinaryWriter bW)
        {
            switch (address.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    bW.Write((byte)1);
                    break;

                case AddressFamily.InterNetworkV6:
                    bW.Write((byte)2);
                    break;

                default:
                    throw new NotSupportedException("AddressFamily not supported.");
            }

            bW.Write(address.GetAddressBytes());
        }

        public static uint ConvertIpToNumber(this IPAddress address)
        {
            if (address.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Address family not supported.");

            byte[] addr = address.GetAddressBytes();
            Array.Reverse(addr);
            return BitConverter.ToUInt32(addr, 0);
        }

        public static IPAddress ConvertNumberToIp(uint address)
        {
            byte[] addr = BitConverter.GetBytes(address);
            Array.Reverse(addr);
            return new IPAddress(addr);
        }

        public static int GetSubnetMaskWidth(this IPAddress address)
        {
            if (address.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("Address family not supported.");

            uint subnetMaskNumber = address.ConvertIpToNumber();
            int subnetMaskWidth = 0;

            while (subnetMaskNumber > 0u)
            {
                subnetMaskNumber <<= 1;
                subnetMaskWidth++;
            }

            return subnetMaskWidth;
        }

        public static IPAddress GetSubnetMask(int subnetMaskWidth)
        {
            if (subnetMaskWidth > 32)
                throw new ArgumentOutOfRangeException("Invalid subnet mask width.");

            byte[] subnetMaskBuffer = BitConverter.GetBytes(0xFFFFFFFFu << (32 - subnetMaskWidth));
            Array.Reverse(subnetMaskBuffer);

            return new IPAddress(subnetMaskBuffer);
        }

        #endregion
    }
}
