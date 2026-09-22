using System.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Dns
{
    public class NameServerAddressTests
    {
        [Theory]
        [InlineData("192.0.2.53", DnsTransportProtocol.Udp, "192.0.2.53", 53, true)]
        [InlineData("192.0.2.53:5353", DnsTransportProtocol.Udp, "192.0.2.53", 5353, false)]
        [InlineData("[2001:db8::53]", DnsTransportProtocol.Udp, "2001:db8::53", 53, true)]
        [InlineData("tcp://dns.example.test:5353", DnsTransportProtocol.Tcp, "dns.example.test", 5353, false)]
        [InlineData("tls://dns.example.test", DnsTransportProtocol.Tls, "dns.example.test", 853, true)]
        [InlineData("quic://dns.example.test", DnsTransportProtocol.Quic, "dns.example.test", 853, true)]
        [InlineData("https://dns.example.test/dns-query", DnsTransportProtocol.Https, "dns.example.test", 443, true)]
        [InlineData("h3://dns.example.test/dns-query", DnsTransportProtocol.Https, "dns.example.test", 443, true)]
        public void ParseGuessesProtocolHostPortAndDefaultPort(string value, DnsTransportProtocol protocol, string host, int port, bool isDefaultPort)
        {
            NameServerAddress address = NameServerAddress.Parse(value);

            Assert.Equal(protocol, address.Protocol);
            Assert.Equal(host, address.Host);
            Assert.Equal(port, address.Port);
            Assert.Equal(isDefaultPort, address.IsDefaultPort);
            Assert.Equal(value, address.OriginalAddress);
            Assert.NotNull(address.EndPoint);
            Assert.Contains(host.Trim('[', ']'), address.ToString());
        }

        [Fact]
        public void ParseSupportsPinnedIpAddressBesideDomainOrDohEndpoint()
        {
            NameServerAddress domainPinned = NameServerAddress.Parse("dns.example.test (192.0.2.53)");
            NameServerAddress dohPinned = NameServerAddress.Parse("https://dns.example.test/dns-query (192.0.2.54)");

            Assert.Equal("dns.example.test", domainPinned.DomainEndPoint!.Address);
            Assert.Equal(IPAddress.Parse("192.0.2.53"), domainPinned.IPEndPoint!.Address);
            Assert.Equal(DnsTransportProtocol.Udp, domainPinned.Protocol);
            Assert.Equal("dns.example.test (192.0.2.53)", domainPinned.ToString());

            Assert.Equal(DnsTransportProtocol.Https, dohPinned.Protocol);
            Assert.Equal(new Uri("https://dns.example.test/dns-query"), dohPinned.DoHEndPoint);
            Assert.Equal(IPAddress.Parse("192.0.2.54"), dohPinned.IPEndPoint!.Address);
            Assert.Equal("https://dns.example.test/dns-query (192.0.2.54)", dohPinned.ToString());
        }

        [Fact]
        public void ExplicitProtocolValidationRejectsMismatchedAddressKinds()
        {
            Assert.Throws<ArgumentException>(() => NameServerAddress.Parse("https://dns.example.test/dns-query", DnsTransportProtocol.Udp));
            Assert.Throws<ArgumentException>(() => NameServerAddress.Parse("192.0.2.53:53", DnsTransportProtocol.Tls));
            Assert.Throws<ArgumentException>(() => NameServerAddress.Parse("192.0.2.53:853", DnsTransportProtocol.Udp));
            Assert.Throws<ArgumentException>(() => NameServerAddress.Parse("dns.example.test:853 (192.0.2.53:53)"));
            Assert.Throws<ArgumentException>(() => NameServerAddress.Parse("[not-ipv6]"));
        }

        [Fact]
        public void ConstructorsCloneAndBinarySerializationPreserveAddress()
        {
            NameServerAddress original = new NameServerAddress("dns.example.test", new IPEndPoint(IPAddress.Parse("192.0.2.53"), 5353), DnsTransportProtocol.Tcp);
            NameServerAddress clonedIp = original.Clone(IPAddress.Parse("198.51.100.53"));
            NameServerAddress clonedTls = original.Clone(DnsTransportProtocol.Tls);
            NameServerAddress sameProtocol = original.Clone(DnsTransportProtocol.Tcp);

            Assert.Equal(DnsTransportProtocol.Tcp, original.Protocol);
            Assert.Equal("dns.example.test", original.DomainEndPoint!.Address);
            Assert.Equal(5353, original.Port);
            Assert.Equal(IPAddress.Parse("198.51.100.53"), clonedIp.IPEndPoint!.Address);
            Assert.Equal(5353, clonedIp.Port);
            Assert.Equal(DnsTransportProtocol.Tls, clonedTls.Protocol);
            Assert.Equal(5353, clonedTls.Port);
            Assert.Same(original, sameProtocol);
            Assert.NotEqual(original, clonedIp);

            using MemoryStream stream = new MemoryStream();
            using (BinaryWriter writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, leaveOpen: true))
                original.WriteTo(writer);

            stream.Position = 0;
            using BinaryReader reader = new BinaryReader(stream);
            NameServerAddress parsed = new NameServerAddress(reader);

            Assert.Equal(original, parsed);
            Assert.Equal(original.GetHashCode(), parsed.GetHashCode());
        }

        [Fact]
        public void GetNameServersFromResponseUsesGlueAndFiltersLoopback()
        {
            DnsDatagram response = new DnsDatagram(
                1,
                true,
                DnsOpcode.StandardQuery,
                true,
                false,
                true,
                true,
                false,
                false,
                DnsResponseCode.NoError,
                [new DnsQuestionRecord("example.test", DnsResourceRecordType.NS, DnsClass.IN)],
                [
                    new DnsResourceRecord("example.test", DnsResourceRecordType.NS, DnsClass.IN, 300, new DnsNSRecordData("ns1.example.test")),
                    new DnsResourceRecord("example.test", DnsResourceRecordType.NS, DnsClass.IN, 300, new DnsNSRecordData("ns2.example.test"))
                ],
                [],
                [
                    new DnsResourceRecord("ns1.example.test", DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.53"))),
                    new DnsResourceRecord("ns1.example.test", DnsResourceRecordType.AAAA, DnsClass.IN, 300, new DnsAAAARecordData(IPAddress.Parse("2001:db8::53"))),
                    new DnsResourceRecord("ns2.example.test", DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Loopback))
                ]);

            List<NameServerAddress> servers = NameServerAddress.GetNameServersFromResponse(response, IPv6Mode.Enabled, filterLoopbackAddresses: true);

            Assert.Equal(2, servers.Count);
            Assert.Contains(servers, server => server.IPEndPoint!.Address.Equals(IPAddress.Parse("192.0.2.53")));
            Assert.Contains(servers, server => server.IPEndPoint!.Address.Equals(IPAddress.Parse("2001:db8::53")));
            Assert.DoesNotContain(servers, server => IPAddress.IsLoopback(server.IPEndPoint!.Address));
        }

        [Fact]
        public void GetNameServersFromResponseReturnsDomainEndpointWhenGlueIsMissing()
        {
            DnsDatagram response = new DnsDatagram(
                1,
                true,
                DnsOpcode.StandardQuery,
                true,
                false,
                true,
                true,
                false,
                false,
                DnsResponseCode.NoError,
                [new DnsQuestionRecord("www.example.test", DnsResourceRecordType.A, DnsClass.IN)],
                [],
                [new DnsResourceRecord("example.test", DnsResourceRecordType.NS, DnsClass.IN, 300, new DnsNSRecordData("ns.example.test"))]);

            NameServerAddress server = Assert.Single(NameServerAddress.GetNameServersFromResponse(response, IPv6Mode.Disabled, filterLoopbackAddresses: false));

            Assert.Null(server.IPEndPoint);
            Assert.Equal("ns.example.test", server.DomainEndPoint!.Address);
            Assert.Equal(53, server.Port);
        }
    }
}
