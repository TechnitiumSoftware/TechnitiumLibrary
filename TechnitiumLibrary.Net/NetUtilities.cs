/*
Technitium Library
Copyright (C) 2015  Shreyas Zare (shreyas@technitium.com)

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
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace TechnitiumLibrary.Net
{
    public class NetUtilities
    {
        #region static

        public static bool IsPrivateIPv4(IPAddress address)
        {
            //127.0.0.0 - 127.255.255.255
            //10.0.0.0 - 10.255.255.255
            //169.254.0.0 - 169.254.255.255
            //172.16.0.0 - 172.16.31.255
            //192.168.0.0 - 192.168.255.255

            byte[] ip = address.GetAddressBytes();

            switch (ip[0])
            {
                case 127:
                case 10:
                    return true;

                case 169:
                    if (ip[1] == 254)
                        return true;

                    return false;

                case 172:
                    if ((ip[1] == 16) && (ip[2] >= 16) && (ip[2] <= 31))
                        return true;

                    return false;

                case 192:
                    if (ip[1] == 168)
                        return true;

                    return false;

                default:
                    return false;
            }
        }

        public static NetworkInfo GetDefaultNetworkInfo()
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;

                if (!nic.Supports(NetworkInterfaceComponent.IPv4))
                    continue;

                IPInterfaceProperties ipInterface = nic.GetIPProperties();

                foreach (UnicastIPAddressInformation ip in ipInterface.UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        byte[] addr = ip.Address.GetAddressBytes();
                        byte[] mask;

                        try
                        {
                            mask = ip.IPv4Mask.GetAddressBytes();
                        }
                        catch (NotImplementedException)
                        {
                            //method not implemented in mono framework for Linux
                            if (addr[0] == 10)
                            {
                                mask = new byte[] { 255, 0, 0, 0 };
                            }
                            else if ((addr[0] == 192) && (addr[1] == 168))
                            {
                                mask = new byte[] { 255, 255, 255, 0 };
                            }
                            else if ((addr[0] == 169) && (addr[1] == 254))
                            {
                                mask = new byte[] { 255, 255, 0, 0 };
                            }
                            else if ((addr[0] == 172) && (addr[1] > 15) && (addr[1] < 32))
                            {
                                mask = new byte[] { 255, 240, 0, 0 };
                            }
                            else
                            {
                                mask = new byte[] { 255, 255, 255, 0 };
                            }
                        }
                        catch
                        {
                            continue;
                        }

                        foreach (GatewayIPAddressInformation gateway in ipInterface.GatewayAddresses)
                        {
                            if (gateway.Address.AddressFamily == AddressFamily.InterNetwork)
                            {
                                byte[] gatewayAddr = gateway.Address.GetAddressBytes();
                                byte[] broadcast = new byte[4];
                                bool isDefaultRoute = true;
                                bool isInSameNetwork = true;

                                for (int i = 0; i < 4; i++)
                                    broadcast[i] = (byte)(addr[i] | ~mask[i]);

                                for (int i = 0; i < 4; i++)
                                {
                                    if (gatewayAddr[i] != 0)
                                    {
                                        isDefaultRoute = false;
                                        break;
                                    }
                                }

                                if (isDefaultRoute)
                                    return new NetworkInfo(nic.NetworkInterfaceType, ip.Address, new IPAddress(mask), new IPAddress(broadcast));

                                for (int i = 0; i < 4; i++)
                                {
                                    if ((addr[i] & mask[i]) != (gatewayAddr[i] & mask[i]))
                                    {
                                        isInSameNetwork = false;
                                        break;
                                    }
                                }

                                if (isInSameNetwork)
                                    return new NetworkInfo(nic.NetworkInterfaceType, ip.Address, new IPAddress(mask), new IPAddress(broadcast));
                            }
                        }
                    }
                }
            }

            return null;
        }

        public static List<NetworkInfo> GetNetworkInfo()
        {
            List<NetworkInfo> networkInfoList = new List<NetworkInfo>(2);

            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;

                if (!nic.Supports(NetworkInterfaceComponent.IPv4))
                    continue;

                foreach (UnicastIPAddressInformation ip in nic.GetIPProperties().UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        byte[] addr = ip.Address.GetAddressBytes();
                        byte[] mask;

                        try
                        {
                            mask = ip.IPv4Mask.GetAddressBytes();
                        }
                        catch (NotImplementedException)
                        {
                            //method not implemented in mono framework for Linux
                            if (addr[0] == 10)
                            {
                                mask = new byte[] { 255, 0, 0, 0 };
                            }
                            else if ((addr[0] == 192) && (addr[1] == 168))
                            {
                                mask = new byte[] { 255, 255, 255, 0 };
                            }
                            else if ((addr[0] == 169) && (addr[1] == 254))
                            {
                                mask = new byte[] { 255, 255, 0, 0 };
                            }
                            else if ((addr[0] == 172) && (addr[1] > 15) && (addr[1] < 32))
                            {
                                mask = new byte[] { 255, 240, 0, 0 };
                            }
                            else
                            {
                                mask = new byte[] { 255, 255, 255, 0 };
                            }
                        }
                        catch
                        {
                            continue;
                        }

                        int ip_bytes = BitConverter.ToInt32(addr, 0);
                        int mask_bytes = BitConverter.ToInt32(mask, 0); ;

                        networkInfoList.Add(new NetworkInfo(nic.NetworkInterfaceType, ip.Address, new IPAddress(mask), new IPAddress(BitConverter.GetBytes(ip_bytes | (~mask_bytes)))));
                    }
                }
            }

            return networkInfoList;
        }

        public static NetworkInfo GetNetworkInfo(IPAddress destinationIP)
        {
            byte[] destination = destinationIP.GetAddressBytes();

            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;

                if (!nic.Supports(NetworkInterfaceComponent.IPv4))
                    continue;

                IPInterfaceProperties ipInterface = nic.GetIPProperties();

                foreach (UnicastIPAddressInformation ip in ipInterface.UnicastAddresses)
                {
                    if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        byte[] addr = ip.Address.GetAddressBytes();
                        byte[] mask;

                        try
                        {
                            mask = ip.IPv4Mask.GetAddressBytes();
                        }
                        catch (NotImplementedException)
                        {
                            //method not implemented in mono framework for Linux
                            if (addr[0] == 10)
                            {
                                mask = new byte[] { 255, 0, 0, 0 };
                            }
                            else if ((addr[0] == 192) && (addr[1] == 168))
                            {
                                mask = new byte[] { 255, 255, 255, 0 };
                            }
                            else if ((addr[0] == 169) && (addr[1] == 254))
                            {
                                mask = new byte[] { 255, 255, 0, 0 };
                            }
                            else if ((addr[0] == 172) && (addr[1] > 15) && (addr[1] < 32))
                            {
                                mask = new byte[] { 255, 240, 0, 0 };
                            }
                            else
                            {
                                mask = new byte[] { 255, 255, 255, 0 };
                            }
                        }
                        catch
                        {
                            continue;
                        }

                        byte[] broadcast = new byte[4];
                        bool isInSameNetwork = true;

                        for (int i = 0; i < 4; i++)
                        {
                            if ((addr[i] & mask[i]) != (destination[i] & mask[i]))
                            {
                                isInSameNetwork = false;
                                break;
                            }

                            broadcast[i] = (byte)(addr[i] | ~mask[i]);
                        }

                        if (isInSameNetwork)
                            return new NetworkInfo(nic.NetworkInterfaceType, ip.Address, new IPAddress(mask), new IPAddress(broadcast));
                    }
                }
            }

            return GetDefaultNetworkInfo();
        }

        #endregion
    }

    public class NetworkInfo
    {
        #region variables

        NetworkInterfaceType _type;
        IPAddress _localIP;
        IPAddress _subnetMask;
        IPAddress _broadcastIP;
        bool _isPublicIP;

        #endregion

        #region constructor

        public NetworkInfo(NetworkInterfaceType type, IPAddress localIP, IPAddress subnetMask, IPAddress broadcastIP)
        {
            _type = type;
            _localIP = localIP;
            _subnetMask = subnetMask;
            _broadcastIP = broadcastIP;
            _isPublicIP = !NetUtilities.IsPrivateIPv4(localIP);
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            return Equals(obj as NetworkInfo);
        }

        public bool Equals(NetworkInfo obj)
        {
            if (ReferenceEquals(null, obj))
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (_type != obj._type)
                return false;

            if (!_localIP.Equals(obj._localIP))
                return false;

            if (!_broadcastIP.Equals(obj._broadcastIP))
                return false;

            return true;
        }

        public override int GetHashCode()
        {
            return BitConverter.ToInt32(_localIP.GetAddressBytes(), 0);
        }

        #endregion

        #region properties

        public NetworkInterfaceType InterfaceType
        { get { return _type; } }

        public IPAddress LocalIP
        { get { return _localIP; } }

        public IPAddress SubnetMask
        { get { return _subnetMask; } }

        public IPAddress BroadcastIP
        { get { return _broadcastIP; } }

        public bool IsPublicIP
        { get { return _isPublicIP; } }

        #endregion
    }
}
