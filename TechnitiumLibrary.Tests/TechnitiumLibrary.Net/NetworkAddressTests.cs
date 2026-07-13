using System.IO;
using System.Net;
using TechnitiumLibrary.Net;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net
{
    public class NetworkAddressTests
    {
        [Fact]
        public void ParseNormalizesAndContainsIPv4Addresses()
        {
            NetworkAddress network = NetworkAddress.Parse("192.168.1.123/24");

            Assert.Equal(IPAddress.Parse("192.168.1.0"), network.Address);
            Assert.Equal((byte)24, network.PrefixLength);
            Assert.Equal(System.Net.Sockets.AddressFamily.InterNetwork, network.AddressFamily);
            Assert.False(network.IsHostAddress);
            Assert.True(network.Contains(IPAddress.Parse("192.168.1.200")));
            Assert.False(network.Contains(IPAddress.Parse("192.168.2.1")));
            Assert.False(network.Contains(IPAddress.Parse("2001:db8::1")));
            Assert.Equal("192.168.1.0/24", network.ToString());
            Assert.Equal(IPAddress.Parse("192.168.1.255"), network.GetLastAddress());
        }

        [Fact]
        public void ParseWithoutPrefixCreatesHostAddress()
        {
            NetworkAddress ipv4 = NetworkAddress.Parse("192.0.2.10");
            NetworkAddress ipv6 = NetworkAddress.Parse("2001:db8::10");

            Assert.True(ipv4.IsHostAddress);
            Assert.True(ipv6.IsHostAddress);
            Assert.Equal((byte)32, ipv4.PrefixLength);
            Assert.Equal((byte)128, ipv6.PrefixLength);
            Assert.Equal("192.0.2.10", ipv4.ToString());
            Assert.Equal("2001:db8::10", ipv6.ToString());
        }

        [Fact]
        public void GetLastAddressHandlesIPv6Networks()
        {
            NetworkAddress network = NetworkAddress.Parse("2001:db8:abcd:1200::1/56");

            Assert.Equal(IPAddress.Parse("2001:db8:abcd:12ff:ffff:ffff:ffff:ffff"), network.GetLastAddress());
            Assert.True(network.Contains(IPAddress.Parse("2001:db8:abcd:12aa::5")));
            Assert.False(network.Contains(IPAddress.Parse("2001:db8:abcd:1300::1")));
        }

        [Fact]
        public void WriteAndReadRoundtrips()
        {
            NetworkAddress expected = NetworkAddress.Parse("2001:db8::1/64");
            using MemoryStream stream = new MemoryStream();

            expected.WriteTo(stream);
            stream.Position = 0;

            NetworkAddress actual = NetworkAddress.ReadFrom(stream);

            Assert.Equal(expected, actual);
            Assert.Equal(expected.GetHashCode(), actual.GetHashCode());
            Assert.Equal("2001:db8::/64", actual.ToString());
        }

        [Fact]
        public void BinaryWriterAndReaderOverloadsRoundtrip()
        {
            NetworkAddress expected = NetworkAddress.Parse("192.0.2.128/25");
            using MemoryStream stream = new MemoryStream();
            using BinaryWriter writer = new BinaryWriter(stream);

            expected.WriteTo(writer);
            stream.Position = 0;

            NetworkAddress actual = NetworkAddress.ReadFrom(new BinaryReader(stream));

            Assert.Equal(expected, actual);
        }

        [Fact]
        public void ConstructorRejectsInvalidIPv4Prefix()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new NetworkAddress(IPAddress.Loopback, 33));
        }

        [Fact]
        public void TryParseRejectsInvalidValues()
        {
            Assert.False(NetworkAddress.TryParse("not-an-ip/24", out _));
            Assert.False(NetworkAddress.TryParse("192.0.2.1/not-a-prefix", out _));
            Assert.False(NetworkAddress.TryParse("192.0.2.1/33", out _));
            Assert.False(NetworkAddress.TryParse("2001:db8::1/129", out _));
            Assert.Throws<FormatException>(() => NetworkAddress.Parse("192.0.2.1/33"));
        }

        [Fact]
        public void EqualsHandlesNullReferenceAndDifferentValues()
        {
            NetworkAddress network = NetworkAddress.Parse("192.0.2.0/24");

            Assert.True(network.Equals((object)network));
            Assert.False(network.Equals(null));
            Assert.False(network.Equals((object)"192.0.2.0/24"));
            Assert.False(network.Equals(NetworkAddress.Parse("192.0.3.0/24")));
            Assert.False(network.Equals(NetworkAddress.Parse("192.0.2.0/25")));
        }
    }
}
