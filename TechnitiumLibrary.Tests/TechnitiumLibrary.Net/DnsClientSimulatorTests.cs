using System.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Tests.Simulators.TechnitiumLibrary.Net;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net
{
    public class DnsClientSimulatorTests
    {
        [Fact]
        public async Task ResolveAsyncUsesUdpSimulatorAndParsesARecord()
        {
            using DnsTestServer server = new DnsTestServer();
            server.AddAddress("example.test", IPAddress.Parse("192.0.2.10"));
            server.Start();
            DnsClient client = CreateClient(server, DnsTransportProtocol.Udp);

            DnsDatagram response = await client.ResolveAsync("example.test", DnsResourceRecordType.A);
            IReadOnlyList<IPAddress> addresses = DnsClient.ParseResponseA(response);

            IPAddress address = Assert.Single(addresses);
            Assert.Equal(IPAddress.Parse("192.0.2.10"), address);
            Assert.True(server.UdpQueryCount >= 1);
            Assert.Equal(0, server.TcpQueryCount);
        }

        [Fact]
        public async Task ResolveIPAsyncCombinesAAndAAAAResponsesFromSimulator()
        {
            using DnsTestServer server = new DnsTestServer();
            server.AddAddress("dual.example.test", IPAddress.Parse("192.0.2.20"));
            server.AddAddress("dual.example.test", IPAddress.Parse("2001:db8::20"));
            server.Start();
            DnsClient client = CreateClient(server, DnsTransportProtocol.Udp);

            IReadOnlyList<IPAddress> addresses = await DnsClient.ResolveIPAsync(client, "dual.example.test", IPv6Mode.Enabled);

            Assert.Contains(IPAddress.Parse("192.0.2.20"), addresses);
            Assert.Contains(IPAddress.Parse("2001:db8::20"), addresses);
            Assert.Equal(2, addresses.Count);
        }

        [Fact]
        public async Task TruncatedUdpResponseFallsBackToTcpOnSameSimulator()
        {
            using DnsTestServer server = new DnsTestServer();
            server.AddAddress("fallback.example.test", IPAddress.Parse("192.0.2.30"));
            server.TruncateUdpResponses = true;
            server.Start();
            DnsClient client = CreateClient(server, DnsTransportProtocol.Udp);

            DnsDatagram response = await client.ResolveAsync("fallback.example.test", DnsResourceRecordType.A);

            Assert.Equal(IPAddress.Parse("192.0.2.30"), Assert.Single(DnsClient.ParseResponseA(response)));
            Assert.Equal(1, server.UdpQueryCount);
            Assert.True(server.TcpQueryCount >= 1);
        }

        [Fact]
        public async Task TcpSimulatorSupportsMxResolution()
        {
            using DnsTestServer server = new DnsTestServer();
            server.AddMx("example.test", 10, "mail.example.test");
            server.Start();
            DnsClient client = CreateClient(server, DnsTransportProtocol.Tcp);

            IReadOnlyList<string> exchanges = await DnsClient.ResolveMXAsync(client, "example.test");

            Assert.Equal("mail.example.test", Assert.Single(exchanges));
            Assert.Equal(0, server.UdpQueryCount);
            Assert.True(server.TcpQueryCount >= 1);
        }

        [Fact]
        public async Task CNameChainFromSimulatorIsParsedForAResponse()
        {
            using DnsTestServer server = new DnsTestServer();
            server.AddCNameAddress("alias.example.test", "target.example.test", IPAddress.Parse("192.0.2.40"));
            server.Start();
            DnsClient client = CreateClient(server, DnsTransportProtocol.Udp);

            DnsDatagram response = await client.ResolveAsync("alias.example.test", DnsResourceRecordType.A);

            Assert.Equal(IPAddress.Parse("192.0.2.40"), Assert.Single(DnsClient.ParseResponseA(response)));
        }

        [Fact]
        public async Task NxDomainResponseFromSimulatorIsReturnedAndParsedAsException()
        {
            using DnsTestServer server = new DnsTestServer();
            server.SetResponseCode("missing.example.test", DnsResourceRecordType.A, DnsResponseCode.NxDomain);
            server.Start();
            DnsClient client = CreateClient(server, DnsTransportProtocol.Udp);

            DnsDatagram response = await client.ResolveAsync("missing.example.test", DnsResourceRecordType.A);

            Assert.Equal(DnsResponseCode.NxDomain, response.RCODE);
            Assert.Throws<DnsClientNxDomainException>(() => DnsClient.ParseResponseA(response));
        }

        [Fact]
        public async Task DroppedUdpResponsesSurfaceNoResponseException()
        {
            using DnsTestServer server = new DnsTestServer();
            server.DropUdpResponses = true;
            server.Start();
            DnsClient client = CreateClient(server, DnsTransportProtocol.Udp);
            client.Timeout = 100;
            client.Retries = 1;

            await Assert.ThrowsAsync<DnsClientNoResponseException>(() => client.ResolveAsync("timeout.example.test", DnsResourceRecordType.A));

            Assert.True(server.UdpQueryCount >= 1);
        }

        private static DnsClient CreateClient(DnsTestServer server, DnsTransportProtocol protocol)
        {
            return new DnsClient(new NameServerAddress(new IPEndPoint(IPAddress.Loopback, server.Port), protocol))
            {
                Timeout = 1000,
                Retries = 1
            };
        }
    }
}
