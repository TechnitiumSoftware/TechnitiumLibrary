using System.Collections.Generic;
using System.Net;
using System.Reflection;
using TechnitiumLibrary.Net.BitTorrent;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.BitTorrent
{
    public class UdpTrackerClientTests
    {
        [Fact]
        public void ParsePeersIPv4AddsValidPeersAndSkipsUnusableAddresses()
        {
            List<IPEndPoint> peers = new List<IPEndPoint>();
            byte[] response = new byte[38];
            WriteUdpIPv4(response, 20, IPAddress.Any, 6881);
            WriteUdpIPv4(response, 26, IPAddress.Loopback, 6881);
            WriteUdpIPv4(response, 32, IPAddress.Parse("192.0.2.10"), 6881);

            InvokeParser("ParsePeersIPv4", response, response.Length, peers);

            IPEndPoint peer = Assert.Single(peers);
            Assert.Equal(IPAddress.Parse("192.0.2.10"), peer.Address);
            Assert.Equal(6881, peer.Port);
        }

        [Fact]
        public void ParsePeersIPv6AddsValidPeersAndSkipsUnusableAddresses()
        {
            List<IPEndPoint> peers = new List<IPEndPoint>();
            byte[] response = new byte[74];
            WriteUdpIPv6(response, 20, IPAddress.IPv6Any, 6881);
            WriteUdpIPv6(response, 38, IPAddress.IPv6Loopback, 6881);
            WriteUdpIPv6(response, 56, IPAddress.Parse("2001:db8::10"), 6881);

            InvokeParser("ParsePeersIPv6", response, response.Length, peers);

            IPEndPoint peer = Assert.Single(peers);
            Assert.Equal(IPAddress.Parse("2001:db8::10"), peer.Address);
            Assert.Equal(6881, peer.Port);
        }

        private static void InvokeParser(string methodName, byte[] response, int responseLength, List<IPEndPoint> peers)
        {
            Type type = typeof(TrackerClient).Assembly.GetType("TechnitiumLibrary.Net.BitTorrent.UdpTrackerClient")!;
            MethodInfo method = type.GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Static)!;

            method.Invoke(null, [response, responseLength, peers]);
        }

        private static void WriteUdpIPv4(byte[] buffer, int offset, IPAddress address, ushort port)
        {
            address.GetAddressBytes().CopyTo(buffer, offset);
            buffer[offset + 4] = (byte)(port >> 8);
            buffer[offset + 5] = (byte)port;
        }

        private static void WriteUdpIPv6(byte[] buffer, int offset, IPAddress address, ushort port)
        {
            address.GetAddressBytes().CopyTo(buffer, offset);
            buffer[offset + 16] = (byte)(port >> 8);
            buffer[offset + 17] = (byte)port;
        }
    }
}
