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

        public static DefaultNetworkInfo GetDefaultNetworkInfo()
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;

                if (!nic.Supports(NetworkInterfaceComponent.IPv4))
                    continue;

                switch (nic.NetworkInterfaceType)
                {
                    case NetworkInterfaceType.Ethernet:
                    case NetworkInterfaceType.Ethernet3Megabit:
                    case NetworkInterfaceType.FastEthernetT:
                    case NetworkInterfaceType.FastEthernetFx:
                    case NetworkInterfaceType.Wireless80211:
                    case NetworkInterfaceType.GigabitEthernet:
                        //for all broadcast type network
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

                                foreach (GatewayIPAddressInformation gateway in ipInterface.GatewayAddresses)
                                {
                                    if (gateway.Address.AddressFamily == AddressFamily.InterNetwork)
                                    {
                                        byte[] route = gateway.Address.GetAddressBytes();
                                        byte[] broadcast = new byte[4];
                                        bool isInSameNetwork = true;

                                        for (int i = 0; i < 4; i++)
                                        {
                                            if ((addr[i] & mask[i]) != (route[i] & mask[i]))
                                            {
                                                isInSameNetwork = false;
                                                break;
                                            }

                                            broadcast[i] = (byte)(addr[i] | ~mask[i]);
                                        }

                                        if (isInSameNetwork)
                                            return new DefaultNetworkInfo(ip.Address, new IPAddress(broadcast));
                                    }
                                }
                            }
                        }

                        break;
                }
            }

            return null;
        }

        public static List<IPAddress> GetBroadcastIPList()
        {
            List<IPAddress> broadcastIPList = new List<IPAddress>(2);

            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;

                if (!nic.Supports(NetworkInterfaceComponent.IPv4))
                    continue;

                switch (nic.NetworkInterfaceType)
                {
                    case NetworkInterfaceType.Ethernet:
                    case NetworkInterfaceType.Ethernet3Megabit:
                    case NetworkInterfaceType.FastEthernetT:
                    case NetworkInterfaceType.FastEthernetFx:
                    case NetworkInterfaceType.Wireless80211:
                    case NetworkInterfaceType.GigabitEthernet:
                        //for all broadcast type network
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

                                int ip_bytes = BitConverter.ToInt32(addr, 0);
                                int mask_bytes = BitConverter.ToInt32(mask, 0); ;

                                broadcastIPList.Add(new IPAddress(BitConverter.GetBytes(ip_bytes | (~mask_bytes))));
                            }
                        }
                        break;
                }
            }

            return broadcastIPList;
        }

        #endregion
    }

    public class DefaultNetworkInfo
    {
        #region variables

        IPAddress _localIP;
        IPAddress _broadcastIP;
        bool _isPublicIP;

        #endregion

        #region constructor

        public DefaultNetworkInfo(IPAddress localIP, IPAddress broadcastIP)
        {
            _localIP = localIP;
            _broadcastIP = broadcastIP;
            _isPublicIP = !NetUtilities.IsPrivateIPv4(localIP);
        }

        #endregion

        #region properties

        public IPAddress LocalIP
        { get { return _localIP; } }

        public IPAddress BroadcastIP
        { get { return _broadcastIP; } }

        public bool IsPublicIP
        { get { return _isPublicIP; } }

        #endregion
    }
}
