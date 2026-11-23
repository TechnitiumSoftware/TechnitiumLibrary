using System.Collections.Generic;
using System.Net;
using System.Reflection;
using TechnitiumLibrary.Net.BitTorrent;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.BitTorrent
{
    public class HttpTrackerClientTests
    {
        [Fact]
        public void ParseCompactPeersIPv4AddsValidPeersAndSkipsUnusableAddresses()
        {
            List<IPEndPoint> peers = new List<IPEndPoint>();
            byte[] data =
            [
                0, 0, 0, 0, 0x1A, 0xE1,
                127, 0, 0, 1, 0x1A, 0xE1,
                192, 0, 2, 10, 0x1A, 0xE1
            ];

            InvokeParser("ParseCompactPeersIPv4", data, peers);

            IPEndPoint peer = Assert.Single(peers);
            Assert.Equal(IPAddress.Parse("192.0.2.10"), peer.Address);
            Assert.Equal(6881, peer.Port);
        }

        [Fact]
        public void ParseCompactPeersIPv6AddsValidPeersAndSkipsUnusableAddresses()
        {
            List<IPEndPoint> peers = new List<IPEndPoint>();
            byte[] data = new byte[54];
            WriteCompactIPv6(data, 0, IPAddress.IPv6Any, 6881);
            WriteCompactIPv6(data, 18, IPAddress.IPv6Loopback, 6881);
            WriteCompactIPv6(data, 36, IPAddress.Parse("2001:db8::10"), 6881);

            InvokeParser("ParseCompactPeersIPv6", data, peers);

            IPEndPoint peer = Assert.Single(peers);
            Assert.Equal(IPAddress.Parse("2001:db8::10"), peer.Address);
            Assert.Equal(6881, peer.Port);
        }

        private static void InvokeParser(string methodName, byte[] data, List<IPEndPoint> peers)
        {
            Type type = typeof(TrackerClient).Assembly.GetType("TechnitiumLibrary.Net.BitTorrent.HttpTrackerClient")!;
            MethodInfo method = type.GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Static)!;

            method.Invoke(null, [data, peers]);
        }

        private static void WriteCompactIPv6(byte[] buffer, int offset, IPAddress address, ushort port)
        {
            address.GetAddressBytes().CopyTo(buffer, offset);
            buffer[offset + 16] = (byte)(port >> 8);
            buffer[offset + 17] = (byte)port;
        }
    }
}
