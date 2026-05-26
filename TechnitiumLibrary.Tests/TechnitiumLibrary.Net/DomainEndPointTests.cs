using TechnitiumLibrary.Net;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net
{
    public class DomainEndPointTests
    {
        [Fact]
        public void TryParseRejectsIpAddressAndParsesDomain()
        {
            Assert.False(DomainEndPoint.TryParse("127.0.0.1:53", out _));
            Assert.True(DomainEndPoint.TryParse("example.com:853", out DomainEndPoint endpoint));

            Assert.Equal("example.com", endpoint.Address);
            Assert.Equal(853, endpoint.Port);
            Assert.Equal(System.Net.Sockets.AddressFamily.Unspecified, endpoint.AddressFamily);
            Assert.Equal("example.com:853", endpoint.ToString());
        }

        [Fact]
        public void TryParseUsesZeroPortWhenPortIsOmitted()
        {
            Assert.True(DomainEndPoint.TryParse("example.com", out DomainEndPoint endpoint));

            Assert.Equal("example.com", endpoint.Address);
            Assert.Equal(0, endpoint.Port);
        }

        [Fact]
        public void TryParseRejectsInvalidDomainAndPort()
        {
            Assert.False(DomainEndPoint.TryParse("bad domain:53", out _));
            Assert.False(DomainEndPoint.TryParse("example.com:not-a-port", out _));
            Assert.False(DomainEndPoint.TryParse("example.com:53:extra", out _));
        }

        [Fact]
        public void ConstructorRejectsIpAddressAndNormalizesUnicodeDomain()
        {
            Assert.Throws<ArgumentException>(() => new DomainEndPoint("127.0.0.1", 53));

            DomainEndPoint endpoint = new DomainEndPoint("bücher.example", 443);

            Assert.Equal("xn--bcher-kva.example", endpoint.Address);
            Assert.Equal(443, endpoint.Port);
        }

        [Fact]
        public void GetAddressBytesUsesLengthPrefixedAsciiDomain()
        {
            DomainEndPoint endpoint = new DomainEndPoint("example.com", 53);

            byte[] address = endpoint.GetAddressBytes();

            Assert.Equal(12, address.Length);
            Assert.Equal(11, address[0]);
            Assert.Equal("example.com", System.Text.Encoding.ASCII.GetString(address, 1, address.Length - 1));
        }

        [Fact]
        public void EqualsComparesAddressCaseInsensitivelyAndPort()
        {
            DomainEndPoint endpoint = new DomainEndPoint("Example.com", 53);

            Assert.True(endpoint.Equals(endpoint));
            Assert.True(endpoint.Equals(new DomainEndPoint("example.com", 53)));
            Assert.False(endpoint.Equals(null));
            Assert.False(endpoint.Equals("example.com:53"));
            Assert.False(endpoint.Equals(new DomainEndPoint("example.net", 53)));
            Assert.False(endpoint.Equals(new DomainEndPoint("example.com", 853)));
        }
    }
}
