using System.IO;
using System.Net;
using TechnitiumLibrary.Net;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net
{
    public class IPAddressExtensionsTests
    {
        [Theory]
        [InlineData("192.0.2.1")]
        [InlineData("2001:db8::1")]
        public void WriteAndReadRoundtrips(string addressValue)
        {
            IPAddress expected = IPAddress.Parse(addressValue);
            using MemoryStream stream = new MemoryStream();

            expected.WriteTo(stream);
            stream.Position = 0;

            Assert.Equal(expected, IPAddressExtensions.ReadFrom(stream));
        }

        [Fact]
        public void BinaryWriterAndReaderOverloadsRoundtrip()
        {
            IPAddress expected = IPAddress.Parse("192.0.2.1");
            using MemoryStream stream = new MemoryStream();
            using BinaryWriter writer = new BinaryWriter(stream);

            expected.WriteTo(writer);
            stream.Position = 0;

            Assert.Equal(expected, IPAddressExtensions.ReadFrom(new BinaryReader(stream)));
        }

        [Fact]
        public void ReadFromRejectsUnsupportedMarkerAndEndOfStream()
        {
            Assert.Throws<NotSupportedException>(() => IPAddressExtensions.ReadFrom(new MemoryStream(new byte[] { 99 })));
            Assert.Throws<EndOfStreamException>(() => IPAddressExtensions.ReadFrom(new MemoryStream()));
        }

        [Fact]
        public void ConvertsIPv4AddressToAndFromNumber()
        {
            IPAddress address = IPAddress.Parse("192.0.2.1");

            uint number = address.ConvertIpToNumber();

            Assert.Equal(0xC0000201u, number);
            Assert.Equal(address, IPAddressExtensions.ConvertNumberToIp(number));
            Assert.Throws<ArgumentException>(() => IPAddress.Parse("2001:db8::1").ConvertIpToNumber());
        }

        [Fact]
        public void SubnetMaskHelpersHandleValidAndInvalidPrefixes()
        {
            Assert.Equal(IPAddress.Any, IPAddressExtensions.GetSubnetMask(0));
            Assert.Equal(IPAddress.Parse("255.255.255.0"), IPAddressExtensions.GetSubnetMask(24));
            Assert.Equal(24, IPAddress.Parse("255.255.255.0").GetSubnetMaskWidth());
            Assert.Throws<ArgumentOutOfRangeException>(() => IPAddressExtensions.GetSubnetMask(33));
            Assert.Throws<ArgumentException>(() => IPAddress.Parse("ffff:ffff::").GetSubnetMaskWidth());
        }

        [Fact]
        public void GetNetworkAddressHandlesIPv4AndIPv6()
        {
            Assert.Equal(IPAddress.Parse("192.0.2.128"), IPAddress.Parse("192.0.2.200").GetNetworkAddress(25));
            Assert.Same(IPAddress.Loopback, IPAddress.Loopback.GetNetworkAddress(32));
            Assert.Equal(IPAddress.Parse("2001:db8:abcd:1200::"), IPAddress.Parse("2001:db8:abcd:1234::1").GetNetworkAddress(56));
            Assert.Equal(IPAddress.Parse("2001:db8:abcd:1280::"), IPAddress.Parse("2001:db8:abcd:12ff::1").GetNetworkAddress(57));

            IPAddress ipv6 = IPAddress.Parse("2001:db8::1");
            Assert.Same(ipv6, ipv6.GetNetworkAddress(128));
            Assert.Throws<ArgumentOutOfRangeException>(() => IPAddress.Loopback.GetNetworkAddress(33));
            Assert.Throws<ArgumentOutOfRangeException>(() => ipv6.GetNetworkAddress(129));
        }

        [Theory]
        [InlineData(32)]
        [InlineData(40)]
        [InlineData(48)]
        [InlineData(56)]
        [InlineData(64)]
        [InlineData(96)]
        public void MapToIPv6AndMapToIPv4RoundtripForSupportedPrefixes(byte prefixLength)
        {
            IPAddress ipv4 = IPAddress.Parse("192.0.2.33");
            NetworkAddress prefix = new NetworkAddress(IPAddress.Parse("2001:db8:1234:5678::"), prefixLength);

            IPAddress mapped = ipv4.MapToIPv6(prefix);

            Assert.Equal(System.Net.Sockets.AddressFamily.InterNetworkV6, mapped.AddressFamily);
            Assert.Equal(ipv4, mapped.MapToIPv4(prefixLength));
        }

        [Fact]
        public void MappingHelpersReturnAlreadyMatchingFamilyAndRejectUnsupportedPrefix()
        {
            IPAddress ipv4 = IPAddress.Parse("192.0.2.33");
            IPAddress ipv6 = IPAddress.Parse("2001:db8::c000:221");

            Assert.Same(ipv6, ipv6.MapToIPv6(NetworkAddress.Parse("64:ff9b::/96")));
            Assert.Same(ipv4, ipv4.MapToIPv4(96));
            Assert.Throws<NotSupportedException>(() => ipv4.MapToIPv6(NetworkAddress.Parse("2001:db8::/65")));
            Assert.Throws<NotSupportedException>(() => ipv6.MapToIPv4(65));
        }

        [Fact]
        public void ReverseDomainRoundtripsIPv4AndIPv6()
        {
            IPAddress ipv4 = IPAddress.Parse("192.0.2.1");
            IPAddress ipv6 = IPAddress.Parse("2001:db8::1");

            Assert.Equal("1.2.0.192.in-addr.arpa", ipv4.GetReverseDomain());
            Assert.Equal(ipv4, IPAddressExtensions.ParseReverseDomain(ipv4.GetReverseDomain()));
            Assert.Equal(ipv6, IPAddressExtensions.ParseReverseDomain(ipv6.GetReverseDomain()));
        }

        [Fact]
        public void TryParseReverseDomainRejectsInvalidDomains()
        {
            Assert.False(IPAddressExtensions.TryParseReverseDomain("not-a-reverse.example", out _));
            Assert.False(IPAddressExtensions.TryParseReverseDomain("x.2.0.192.in-addr.arpa", out _));
            Assert.False(IPAddressExtensions.TryParseReverseDomain("x.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", out _));
            Assert.Throws<NotSupportedException>(() => IPAddressExtensions.ParseReverseDomain("not-a-reverse.example"));
        }
    }
}
