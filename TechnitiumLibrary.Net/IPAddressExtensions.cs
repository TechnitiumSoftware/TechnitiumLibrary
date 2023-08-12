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
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace TechnitiumLibrary.Net
{
    public static class IPAddressExtensions
    {
        #region static

        public static IPAddress ReadFrom(BinaryReader bR)
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

        public static IPAddress GetSubnetMask(int prefixLength)
        {
            if (prefixLength > 32)
                throw new ArgumentOutOfRangeException(nameof(prefixLength), "Invalid prefix length.");

            if (prefixLength == 0)
                return IPAddress.Any;

            byte[] subnetMaskBuffer = BitConverter.GetBytes(0xFFFFFFFFu << (32 - prefixLength));
            Array.Reverse(subnetMaskBuffer);

            return new IPAddress(subnetMaskBuffer);
        }

        public static IPAddress GetNetworkAddress(this IPAddress address, int prefixLength)
        {
            switch (address.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    {
                        if (prefixLength == 32)
                            return address;

                        if (prefixLength > 32)
                            throw new ArgumentOutOfRangeException(nameof(prefixLength), "Invalid prefix length.");

                        byte[] addressBytes = address.GetAddressBytes();
                        byte[] networkAddress = new byte[4];
                        int copyBytes = prefixLength / 8;
                        int balanceBits = prefixLength - (copyBytes * 8);

                        Buffer.BlockCopy(addressBytes, 0, networkAddress, 0, copyBytes);

                        if (balanceBits > 0)
                            networkAddress[copyBytes] = (byte)(addressBytes[copyBytes] & (0xFF << (8 - balanceBits)));

                        return new IPAddress(networkAddress);
                    }

                case AddressFamily.InterNetworkV6:
                    {
                        if (prefixLength == 128)
                            return address;

                        if (prefixLength > 128)
                            throw new ArgumentOutOfRangeException(nameof(prefixLength), "Invalid prefix length.");

                        byte[] addressBytes = address.GetAddressBytes();
                        byte[] networkAddress = new byte[16];
                        int copyBytes = prefixLength / 8;
                        int balanceBits = prefixLength - (copyBytes * 8);

                        Buffer.BlockCopy(addressBytes, 0, networkAddress, 0, copyBytes);

                        if (balanceBits > 0)
                            networkAddress[copyBytes] = (byte)(addressBytes[copyBytes] & (0xFF << (8 - balanceBits)));

                        return new IPAddress(networkAddress);
                    }

                default:
                    throw new NotSupportedException("AddressFamily not supported.");
            }
        }

        public static IPAddress MapToIPv6(this IPAddress address, NetworkAddress ipv6Prefix)
        {
            if (address.AddressFamily == AddressFamily.InterNetworkV6)
                return address;

            switch (ipv6Prefix.PrefixLength)
            {
                case 32:
                    {
                        byte[] ipv4Buffer = address.GetAddressBytes();
                        byte[] ipv6Buffer = ipv6Prefix.Address.GetAddressBytes();

                        Buffer.BlockCopy(ipv4Buffer, 0, ipv6Buffer, 4, 4);

                        return new IPAddress(ipv6Buffer);
                    }

                case 40:
                    {
                        byte[] ipv4Buffer = address.GetAddressBytes();
                        byte[] ipv6Buffer = ipv6Prefix.Address.GetAddressBytes();

                        Buffer.BlockCopy(ipv4Buffer, 0, ipv6Buffer, 5, 3);
                        Buffer.BlockCopy(ipv4Buffer, 3, ipv6Buffer, 9, 1);

                        return new IPAddress(ipv6Buffer);
                    }

                case 48:
                    {
                        byte[] ipv4Buffer = address.GetAddressBytes();
                        byte[] ipv6Buffer = ipv6Prefix.Address.GetAddressBytes();

                        Buffer.BlockCopy(ipv4Buffer, 0, ipv6Buffer, 6, 2);
                        Buffer.BlockCopy(ipv4Buffer, 2, ipv6Buffer, 9, 2);

                        return new IPAddress(ipv6Buffer);
                    }

                case 56:
                    {
                        byte[] ipv4Buffer = address.GetAddressBytes();
                        byte[] ipv6Buffer = ipv6Prefix.Address.GetAddressBytes();

                        Buffer.BlockCopy(ipv4Buffer, 0, ipv6Buffer, 7, 1);
                        Buffer.BlockCopy(ipv4Buffer, 1, ipv6Buffer, 9, 3);

                        return new IPAddress(ipv6Buffer);
                    }

                case 64:
                    {
                        byte[] ipv4Buffer = address.GetAddressBytes();
                        byte[] ipv6Buffer = ipv6Prefix.Address.GetAddressBytes();

                        Buffer.BlockCopy(ipv4Buffer, 0, ipv6Buffer, 9, 4);

                        return new IPAddress(ipv6Buffer);
                    }

                case 96:
                    {
                        byte[] ipv4Buffer = address.GetAddressBytes();
                        byte[] ipv6Buffer = ipv6Prefix.Address.GetAddressBytes();

                        Buffer.BlockCopy(ipv4Buffer, 0, ipv6Buffer, 12, 4);

                        return new IPAddress(ipv6Buffer);
                    }

                default:
                    throw new NotSupportedException("IPv6-embedded IPv6 address format supports only the following prefixes: 32, 40, 48, 56, 64, or 96.");
            }
        }

        public static IPAddress MapToIPv4(this IPAddress address, int prefixLength)
        {
            if (address.AddressFamily == AddressFamily.InterNetwork)
                return address;

            switch (prefixLength)
            {
                case 32:
                    {
                        byte[] ipv6Buffer = address.GetAddressBytes();
                        byte[] ipv4Buffer = new byte[4];

                        Buffer.BlockCopy(ipv6Buffer, 4, ipv4Buffer, 0, 4);

                        return new IPAddress(ipv4Buffer);
                    }

                case 40:
                    {
                        byte[] ipv6Buffer = address.GetAddressBytes();
                        byte[] ipv4Buffer = new byte[4];

                        Buffer.BlockCopy(ipv6Buffer, 5, ipv4Buffer, 0, 3);
                        Buffer.BlockCopy(ipv6Buffer, 9, ipv4Buffer, 3, 1);

                        return new IPAddress(ipv4Buffer);
                    }

                case 48:
                    {
                        byte[] ipv6Buffer = address.GetAddressBytes();
                        byte[] ipv4Buffer = new byte[4];

                        Buffer.BlockCopy(ipv6Buffer, 6, ipv4Buffer, 0, 2);
                        Buffer.BlockCopy(ipv6Buffer, 9, ipv4Buffer, 2, 2);

                        return new IPAddress(ipv4Buffer);
                    }

                case 56:
                    {
                        byte[] ipv6Buffer = address.GetAddressBytes();
                        byte[] ipv4Buffer = new byte[4];

                        Buffer.BlockCopy(ipv6Buffer, 7, ipv4Buffer, 0, 1);
                        Buffer.BlockCopy(ipv6Buffer, 9, ipv4Buffer, 1, 3);

                        return new IPAddress(ipv4Buffer);
                    }

                case 64:
                    {
                        byte[] ipv6Buffer = address.GetAddressBytes();
                        byte[] ipv4Buffer = new byte[4];

                        Buffer.BlockCopy(ipv6Buffer, 9, ipv4Buffer, 0, 4);

                        return new IPAddress(ipv4Buffer);
                    }

                case 96:
                    {
                        byte[] ipv6Buffer = address.GetAddressBytes();
                        byte[] ipv4Buffer = new byte[4];

                        Buffer.BlockCopy(ipv6Buffer, 12, ipv4Buffer, 0, 4);

                        return new IPAddress(ipv4Buffer);
                    }

                default:
                    throw new NotSupportedException("IPv6-embedded IPv6 address format supports only the following prefixes: 32, 40, 48, 56, 64, or 96.");
            }
        }

        public static string GetReverseDomain(this IPAddress address)
        {
            byte[] ipBytes = address.GetAddressBytes();
            string name = "";

            switch (address.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    for (int i = ipBytes.Length - 1; i >= 0; i--)
                        name += ipBytes[i] + ".";

                    name += "in-addr.arpa";
                    break;

                case AddressFamily.InterNetworkV6:
                    for (int i = ipBytes.Length - 1; i >= 0; i--)
                        name += (ipBytes[i] & 0x0F).ToString("X") + "." + (ipBytes[i] >> 4).ToString("X") + ".";

                    name += "ip6.arpa";
                    break;

                default:
                    throw new NotSupportedException("IP address family not supported: " + address.AddressFamily.ToString());
            }

            return name;
        }

        public static IPAddress ParseReverseDomain(string ptrDomain)
        {
            if (TryParseReverseDomain(ptrDomain, out IPAddress address))
                return address;

            throw new NotSupportedException("Invalid reverse domain: " + ptrDomain);
        }

        public static bool TryParseReverseDomain(string ptrDomain, out IPAddress address)
        {
            if (ptrDomain.EndsWith(".in-addr.arpa", StringComparison.OrdinalIgnoreCase))
            {
                //1.10.168.192.in-addr.arpa
                //192.168.10.1

                string[] parts = ptrDomain.Split('.');
                byte[] buffer = new byte[4];

                for (int i = 0, j = parts.Length - 3; (i < 4) && (j > -1); i++, j--)
                {
                    if (!byte.TryParse(parts[j], out buffer[i]))
                    {
                        address = null;
                        return false;
                    }
                }

                address = new IPAddress(buffer);
                return true;
            }
            else if (ptrDomain.EndsWith(".ip6.arpa", StringComparison.OrdinalIgnoreCase))
            {
                //B.E.3.0.B.3.B.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.B.9.F.F.4.6.0.0.ip6.arpa
                //64:ff9b::8b3b:3eb

                string[] parts = ptrDomain.Split('.');
                byte[] buffer = new byte[16];
                byte p1, p2;

                for (int i = 0, j = parts.Length - 3; (i < 16) && (j > 0); i++, j -= 2)
                {
                    if (!byte.TryParse(parts[j], NumberStyles.HexNumber, null, out p1) || !byte.TryParse(parts[j - 1], NumberStyles.HexNumber, null, out p2))
                    {
                        address = null;
                        return false;
                    }

                    buffer[i] = (byte)(p1 << 4 | p2);
                }

                address = new IPAddress(buffer);
                return true;
            }
            else
            {
                address = null;
                return false;
            }
        }

        #endregion
    }
}
