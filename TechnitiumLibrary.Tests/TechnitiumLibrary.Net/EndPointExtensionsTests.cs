using System.IO;
using System.Net;
using System.Net.Sockets;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Tests.Simulators.TechnitiumLibrary.Net;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net
{
    public class EndPointExtensionsTests
    {
        [Theory]
        [InlineData("192.0.2.1", 53)]
        [InlineData("2001:db8::1", 853)]
        public void WriteAndReadRoundtripsIpEndPoints(string address, int port)
        {
            IPEndPoint expected = new IPEndPoint(IPAddress.Parse(address), port);
            using MemoryStream stream = new MemoryStream();
            using BinaryWriter writer = new BinaryWriter(stream);

            expected.WriteTo(writer);
            stream.Position = 0;

            Assert.Equal(expected, EndPointExtensions.ReadFrom(new BinaryReader(stream)));
        }

        [Fact]
        public void WriteAndReadRoundtripsDomainEndPoint()
        {
            DomainEndPoint expected = new DomainEndPoint("example.com", 853);
            using MemoryStream stream = new MemoryStream();
            using BinaryWriter writer = new BinaryWriter(stream);

            expected.WriteTo(writer);
            stream.Position = 0;

            EndPoint actual = EndPointExtensions.ReadFrom(new BinaryReader(stream));

            Assert.True(expected.Equals(actual));
        }

        [Fact]
        public void ReadFromRejectsUnsupportedMarker()
        {
            using MemoryStream stream = new MemoryStream(new byte[] { 99 });

            Assert.Throws<NotSupportedException>(() => EndPointExtensions.ReadFrom(new BinaryReader(stream)));
        }

        [Fact]
        public void AddressAndPortHelpersHandleIpAndDomainEndPoints()
        {
            EndPoint ip = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 53);
            EndPoint domain = new DomainEndPoint("example.com", 853);

            Assert.Equal("192.0.2.1", ip.GetAddress());
            Assert.Equal(53, ip.GetPort());
            ip.SetPort(54);
            Assert.Equal(54, ip.GetPort());

            Assert.Equal("example.com", domain.GetAddress());
            Assert.Equal(853, domain.GetPort());
            domain.SetPort(443);
            Assert.Equal(443, domain.GetPort());
        }

        [Fact]
        public void GetEndPointCreatesIpOrDomainEndPoint()
        {
            Assert.IsType<IPEndPoint>(EndPointExtensions.GetEndPoint("192.0.2.1", 53));
            Assert.IsType<DomainEndPoint>(EndPointExtensions.GetEndPoint("example.com", 53));
        }

        [Fact]
        public void ParseAndTryParseHandleIpDomainAndInvalidValues()
        {
            Assert.IsType<IPEndPoint>(EndPointExtensions.Parse("192.0.2.1:53"));
            Assert.IsType<DomainEndPoint>(EndPointExtensions.Parse("example.com:853"));
            Assert.True(EndPointExtensions.TryParse("example.com:853", out EndPoint endpoint));
            Assert.Equal(853, endpoint.GetPort());
            Assert.False(EndPointExtensions.TryParse("bad domain:not-a-port", out _));
            Assert.Throws<FormatException>(() => EndPointExtensions.Parse("bad domain:not-a-port"));
        }

        [Fact]
        public void IsEqualsHandlesNullReferenceFamilyAndValueComparison()
        {
            EndPoint ip = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 53);
            EndPoint matchingIp = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 53);
            EndPoint differentFamily = new DomainEndPoint("example.com", 53);

            Assert.True(ip.IsEquals(ip));
            Assert.True(ip.IsEquals(matchingIp));
            Assert.False(ip.IsEquals(null));
            Assert.False(ip.IsEquals(differentFamily));
            Assert.True(differentFamily.IsEquals(new DomainEndPoint("EXAMPLE.com", 53)));
        }

        [Fact]
        public async Task GetIPEndPointAsyncReturnsExistingIpEndPointWithoutDnsLookup()
        {
            IPEndPoint expected = new IPEndPoint(IPAddress.Loopback, 53);

            IPEndPoint actual = await expected.GetIPEndPointAsync();

            Assert.Same(expected, actual);
        }

        [Fact]
        public async Task UnsupportedEndPointFamilyThrows()
        {
            EndPoint unsupported = new UnsupportedEndPoint(AddressFamily.Unknown);

            Assert.Throws<NotSupportedException>(() => unsupported.WriteTo(new BinaryWriter(new MemoryStream())));
            Assert.Throws<NotSupportedException>(() => unsupported.GetAddress());
            Assert.Throws<NotSupportedException>(() => unsupported.GetPort());
            Assert.Throws<NotSupportedException>(() => unsupported.SetPort(53));
            Assert.Throws<NotSupportedException>(() => unsupported.IsEquals(new UnsupportedEndPoint(AddressFamily.Unknown)));
            await Assert.ThrowsAsync<NotSupportedException>(() => unsupported.GetIPEndPointAsync());
        }

        [Fact]
        public async Task UnspecifiedNonDomainEndPointThrowsWhenResolving()
        {
            await Assert.ThrowsAsync<NotSupportedException>(() => new UnsupportedEndPoint(AddressFamily.Unspecified).GetIPEndPointAsync());
        }
    }
}
