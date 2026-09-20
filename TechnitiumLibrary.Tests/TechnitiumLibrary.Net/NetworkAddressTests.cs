using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Net;
using TechnitiumLibrary.Net;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net
{
    [TestClass]
    public class NetworkAddressTests
    {
        [TestMethod]
        public void Constructor_ShouldNormalizeToNetworkBoundary_IPv4()
        {
            NetworkAddress addr = new NetworkAddress(IPAddress.Parse("10.1.2.99"), 24);

            Assert.AreEqual("10.1.2.0", addr.Address.ToString(),
                "NetworkAddress constructor must mask host bits.");
            Assert.AreEqual((byte)24, addr.PrefixLength);
        }

        [TestMethod]
        public void Constructor_ShouldNormalizeToNetworkBoundary_IPv6()
        {
            NetworkAddress addr = new NetworkAddress(IPAddress.Parse("2001:db8::1234"), 64);

            Assert.AreEqual("2001:db8::", addr.Address.ToString(),
                "NetworkAddress must enforce network mask.");
            Assert.AreEqual((byte)64, addr.PrefixLength);
        }

        [TestMethod]
        public void Constructor_ShouldReject_InvalidPrefix_IPv4()
        {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => new NetworkAddress(IPAddress.Parse("1.2.3.4"), 33),
                "IPv4 prefix >32 must be rejected.");
        }

        [TestMethod]
        public void Constructor_ShouldReject_InvalidPrefix_IPv6()
        {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(
                () => new NetworkAddress(IPAddress.Parse("2001::1"), 129),
                "IPv6 prefix >128 must be rejected.");
        }

        [TestMethod]
        public void Parse_ShouldSupportNoPrefix_IPv4_DefaultsTo32Bits()
        {
            NetworkAddress n = NetworkAddress.Parse("8.8.8.8");

            Assert.AreEqual("8.8.8.8", n.Address.ToString());
            Assert.AreEqual((byte)32, n.PrefixLength);
            Assert.IsTrue(n.IsHostAddress);
        }

        [TestMethod]
        public void Parse_ShouldSupportPrefix_IPv4()
        {
            NetworkAddress n = NetworkAddress.Parse("10.0.0.123/8");

            Assert.AreEqual("10.0.0.0", n.Address.ToString());
            Assert.AreEqual((byte)8, n.PrefixLength);
        }

        [TestMethod]
        public void Parse_ShouldFail_IfBaseAddressInvalid()
        {
            Assert.ThrowsExactly<FormatException>(
                () => NetworkAddress.Parse("notAnIP/16"),
                "Invalid IP should fail parsing.");
        }

        [TestMethod]
        public void Parse_ShouldFail_IfPrefixInvalid()
        {
            Assert.ThrowsExactly<FormatException>(
                () => NetworkAddress.Parse("10.0.0.1/notanumber"),
                "Prefix must be numeric.");
        }

        [TestMethod]
        public void TryParse_ShouldReturnFalse_OnMalformedInput()
        {
            bool ok = NetworkAddress.TryParse("hello", out NetworkAddress? result);

            Assert.IsFalse(ok);
            Assert.IsNull(result);
        }

        [TestMethod]
        public void Contains_ShouldReturnTrue_ForMatchingAddress()
        {
            NetworkAddress net = new NetworkAddress(IPAddress.Parse("192.168.10.0"), 24);

            Assert.IsTrue(net.Contains(IPAddress.Parse("192.168.10.55")));
        }

        [TestMethod]
        public void Contains_ShouldReturnFalse_ForDifferentNetwork()
        {
            NetworkAddress net = new NetworkAddress(IPAddress.Parse("192.168.10.0"), 24);

            Assert.IsFalse(net.Contains(IPAddress.Parse("192.168.11.1")));
        }

        [TestMethod]
        public void Contains_ShouldReturnFalse_WhenAddressFamilyDiffers()
        {
            NetworkAddress net = new NetworkAddress(IPAddress.Parse("10.0.0.0"), 8);

            Assert.IsFalse(net.Contains(IPAddress.IPv6Loopback));
        }

        [TestMethod]
        public void GetLastAddress_ShouldReturnBroadcastIPv4()
        {
            NetworkAddress net = new NetworkAddress(IPAddress.Parse("192.168.50.0"), 24);

            IPAddress last = net.GetLastAddress();

            Assert.AreEqual("192.168.50.255", last.ToString());
        }
        [TestMethod]
        public void GetLastAddress_ShouldReturnBroadcastIPv6()
        {
            NetworkAddress net = new NetworkAddress(IPAddress.Parse("2001:db8::"), 64);

            IPAddress last = net.GetLastAddress();

            IPAddress expected = IPAddress.Parse("2001:db8:0:0:ffff:ffff:ffff:ffff");

            Assert.AreEqual(expected, last,
                "Last IPv6 address must have all host bits set.");
        }

        [TestMethod]
        public void ToString_ShouldOmitPrefix_WhenHostAddressIPv4()
        {
            NetworkAddress net = new NetworkAddress(IPAddress.Parse("9.9.9.9"), 32);

            Assert.AreEqual("9.9.9.9", net.ToString(),
                "Full host prefix must not show /32");
        }

        [TestMethod]
        public void ToString_ShouldIncludePrefix_WhenNotHostIPv4()
        {
            NetworkAddress net = new NetworkAddress(IPAddress.Parse("9.9.9.0"), 24);

            Assert.AreEqual("9.9.9.0/24", net.ToString());
        }

        [TestMethod]
        public void ToString_ShouldOmitPrefix_WhenHostAddressIPv6()
        {
            NetworkAddress net = new NetworkAddress(IPAddress.Parse("2001::1"), 128);

            Assert.AreEqual("2001::1", net.ToString());
        }

        [TestMethod]
        public void Roundtrip_BinarySerialization_Works()
        {
            NetworkAddress original = new NetworkAddress(IPAddress.Parse("10.20.30.40"), 20);

            using MemoryStream ms = new MemoryStream();
            using (BinaryWriter bw = new BinaryWriter(ms, System.Text.Encoding.UTF8, leaveOpen: true))
                original.WriteTo(bw);

            ms.Position = 0;

            using BinaryReader br = new BinaryReader(ms);
            NetworkAddress roundtrip = NetworkAddress.ReadFrom(br);

            Assert.AreEqual(original, roundtrip);
        }

        [TestMethod]
        public void Equals_ShouldReturnTrue_ForSameValue()
        {
            NetworkAddress a = new NetworkAddress(IPAddress.Parse("10.0.0.0"), 8);
            NetworkAddress b = new NetworkAddress(IPAddress.Parse("10.0.0.0"), 8);

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void Equals_ShouldReturnFalse_WhenPrefixDiffers()
        {
            NetworkAddress a = new NetworkAddress(IPAddress.Parse("10.0.0.0"), 8);
            NetworkAddress b = new NetworkAddress(IPAddress.Parse("10.0.0.0"), 16);

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void Equals_ShouldReturnFalse_WhenAddressDiffers()
        {
            NetworkAddress a = new NetworkAddress(IPAddress.Parse("192.168.0.0"), 24);
            NetworkAddress b = new NetworkAddress(IPAddress.Parse("192.168.1.0"), 24);

            Assert.IsFalse(a.Equals(b));
        }
    }
}
