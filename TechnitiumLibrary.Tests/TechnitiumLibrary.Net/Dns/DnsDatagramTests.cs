using System.Net;
using System.Text.Json;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Dns
{
    public class DnsDatagramTests
    {
        [Fact]
        public void DatagramRoundTripsQuestionsRecordsAndEdns()
        {
            DnsDatagram datagram = CreateResponse(
                answers:
                [
                    new DnsResourceRecord("alias.example.test", DnsResourceRecordType.CNAME, DnsClass.IN, 60, new DnsCNAMERecordData("example.test")),
                    new DnsResourceRecord("example.test", DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(IPAddress.Parse("192.0.2.10")))
                ],
                authority:
                [
                    new DnsResourceRecord("example.test", DnsResourceRecordType.NS, DnsClass.IN, 300, new DnsNSRecordData("ns1.example.test"))
                ],
                additional:
                [
                    new DnsResourceRecord("ns1.example.test", DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.53")))
                ]);

            DnsDatagram parsed = RoundTrip(datagram);

            Assert.Equal(datagram.Identifier, parsed.Identifier);
            Assert.True(parsed.IsResponse);
            Assert.True(parsed.AuthoritativeAnswer);
            Assert.True(parsed.RecursionDesired);
            Assert.True(parsed.RecursionAvailable);
            Assert.True(parsed.AuthenticData);
            Assert.True(parsed.CheckingDisabled);
            Assert.True(parsed.DnssecOk);
            Assert.Equal(DnsResponseCode.NoError, parsed.RCODE);
            Assert.Single(parsed.Question);
            Assert.Equal(2, parsed.Answer.Count);
            Assert.Single(parsed.Authority);
            Assert.Equal(2, parsed.Additional.Count);
            Assert.NotNull(parsed.EDNS);
            Assert.Equal(DnsResourceRecordType.A, parsed.GetLastAnswerRecord().Type);
            Assert.Equal(DnsResourceRecordType.NS, parsed.FindFirstAuthorityType());
            Assert.False(parsed.IsFirstAuthoritySOA());
            Assert.False(parsed.IsFirstAuthoritySOAOrFWDOrAPP());
            AssertJsonCanBeWritten(parsed);
        }

        [Fact]
        public async Task DatagramRoundTripsThroughTcpFrame()
        {
            DnsDatagram datagram = CreateResponse(
                answers:
                [
                    new DnsResourceRecord("example.test", DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(IPAddress.Parse("192.0.2.10")))
                ]);
            using MemoryStream stream = new MemoryStream();

            await datagram.WriteToTcpAsync(stream);
            stream.Position = 0;
            DnsDatagram parsed = await DnsDatagram.ReadFromTcpAsync(stream);

            Assert.Equal(datagram.Identifier, parsed.Identifier);
            Assert.Equal(IPAddress.Parse("192.0.2.10"), ((DnsARecordData)parsed.Answer[0].RDATA).Address);
        }

        [Fact]
        public void CloneHelpersPreserveAndRemoveExpectedSections()
        {
            DnsDatagram datagram = CreateResponse(
                additional:
                [
                    new DnsResourceRecord("ns1.example.test", DnsResourceRecordType.A, DnsClass.IN, 300, new DnsARecordData(IPAddress.Parse("192.0.2.53")))
                ]);

            DnsDatagram clone = datagram.Clone();
            DnsDatagram withoutEdns = datagram.CloneWithoutEDns();
            DnsDatagram withoutGlue = datagram.CloneWithoutGlueRecords();
            DnsDatagram withoutEcs = datagram.CloneWithoutEDnsClientSubnet();

            Assert.NotSame(datagram, clone);
            Assert.Equal(datagram.Identifier, clone.Identifier);
            Assert.Null(withoutEdns.EDNS);
            Assert.Single(withoutEdns.Additional);
            Assert.Single(withoutGlue.Additional);
            Assert.Equal(DnsResourceRecordType.OPT, withoutGlue.Additional[0].Type);
            Assert.Null(withoutEcs.GetEDnsClientSubnetOption());
            Assert.NotNull(datagram.GetEDnsClientSubnetOption());
        }

        [Fact]
        public void ShadowClientSubnetOverridesAndCanBeHidden()
        {
            DnsDatagram datagram = CreateResponse();

            datagram.SetShadowEDnsClientSubnetOption(new NetworkAddress(IPAddress.Parse("198.51.100.0"), 24), advancedForwardingClientSubnet: true);

            EDnsClientSubnetOptionData shadow = datagram.GetEDnsClientSubnetOption()!;
            Assert.Equal(IPAddress.Parse("198.51.100.0"), shadow.Address);
            Assert.Equal(24, shadow.ScopePrefixLength);
            Assert.True(shadow.AdvancedForwardingClientSubnet);
            Assert.Equal(IPAddress.Parse("192.0.2.0"), datagram.GetEDnsClientSubnetOption(noShadow: true)!.Address);

            datagram.ShadowHideEDnsClientSubnetOption();

            Assert.Null(datagram.GetEDnsClientSubnetOption());
            Assert.NotNull(datagram.GetEDnsClientSubnetOption(noShadow: true));
        }

        [Fact]
        public void BlockedAndReferrerResponseDetectionUsesResponseShape()
        {
            DnsDatagram blockedByEde = CreateResponse(
                options:
                [
                    new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Blocked, "policy"))
                ],
                authoritativeAnswer: false);
            DnsDatagram blockedByAddress = CreateResponse(
                answers:
                [
                    new DnsResourceRecord("example.test", DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(IPAddress.Any))
                ],
                options: [],
                authoritativeAnswer: false);
            DnsDatagram referrer = CreateResponse(
                answers: [],
                authority:
                [
                    new DnsResourceRecord("example.test", DnsResourceRecordType.NS, DnsClass.IN, 300, new DnsNSRecordData("ns1.example.test"))
                ],
                options: []);

            Assert.True(blockedByEde.IsBlockedResponse());
            Assert.True(blockedByAddress.IsBlockedResponse());
            Assert.False(referrer.IsBlockedResponse());
            Assert.True(referrer.IsReferrerResponse());
        }

        [Fact]
        public void MetadataAndDnssecStatusCanBeAppliedAndSerialized()
        {
            DnsDatagram datagram = CreateResponse(
                answers:
                [
                    new DnsResourceRecord("example.test", DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(IPAddress.Parse("192.0.2.10")))
                ]);
            NameServerAddress server = new NameServerAddress(IPAddress.Parse("192.0.2.53"), DnsTransportProtocol.Udp);

            datagram.SetMetadata(server, 12.5);
            datagram.SetDnssecStatusForAllRecords(DnssecStatus.Secure);

            Assert.Same(server, datagram.Metadata.NameServer);
            Assert.Equal(DnsTransportProtocol.Udp, datagram.Metadata.Protocol);
            Assert.Equal(12.5, datagram.Metadata.RoundTripTime);
            Assert.Equal(DnssecStatus.Secure, datagram.Answer[0].DnssecStatus);
            Assert.Equal(DnssecStatus.Indeterminate, datagram.Additional.Last().DnssecStatus);
            Assert.Throws<InvalidOperationException>(() => datagram.SetMetadata(server));

            using MemoryStream cacheStream = new MemoryStream();
            using (BinaryWriter writer = new BinaryWriter(cacheStream, System.Text.Encoding.UTF8, leaveOpen: true))
                datagram.Metadata.WriteTo(writer);

            cacheStream.Position = 0;
            using BinaryReader reader = new BinaryReader(cacheStream);
            DnsDatagramMetadata parsed = new DnsDatagramMetadata(reader);

            Assert.Equal(datagram.Metadata.NameServer, parsed.NameServer);
            Assert.Equal(datagram.Metadata.DatagramSize, parsed.DatagramSize);
            Assert.Equal(datagram.Metadata.RoundTripTime, parsed.RoundTripTime);
            AssertJsonCanBeWritten(datagram);
        }

        [Fact]
        public void SplitRejectsUnsupportedDatagrams()
        {
            DnsDatagram query = new DnsDatagram(1, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord("example.test", DnsResourceRecordType.A, DnsClass.IN)]);
            DnsDatagram response = CreateResponse();

            Assert.Throws<InvalidOperationException>(() => query.Split());
            Assert.Throws<InvalidOperationException>(() => response.Split());
            Assert.False(query.IsZoneTransfer);
        }

        private static DnsDatagram CreateResponse(
            IReadOnlyList<DnsResourceRecord>? answers = null,
            IReadOnlyList<DnsResourceRecord>? authority = null,
            IReadOnlyList<DnsResourceRecord>? additional = null,
            IReadOnlyList<EDnsOption>? options = null,
            bool authoritativeAnswer = true)
        {
            options ??=
            [
                new EDnsOption(EDnsOptionCode.EDNS_CLIENT_SUBNET, new EDnsClientSubnetOptionData(24, 0, IPAddress.Parse("192.0.2.0")))
            ];

            return new DnsDatagram(
                0x1234,
                true,
                DnsOpcode.StandardQuery,
                authoritativeAnswer,
                false,
                true,
                true,
                true,
                true,
                DnsResponseCode.NoError,
                [new DnsQuestionRecord("example.test", DnsResourceRecordType.A, DnsClass.IN)],
                answers ?? [],
                authority ?? [],
                additional ?? [],
                DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE,
                EDnsHeaderFlags.DNSSEC_OK,
                options);
        }

        private static DnsDatagram RoundTrip(DnsDatagram datagram)
        {
            using MemoryStream stream = new MemoryStream();
            datagram.WriteTo(stream);
            stream.Position = 0;
            return DnsDatagram.ReadFrom(stream);
        }

        private static void AssertJsonCanBeWritten(DnsDatagram datagram)
        {
            using MemoryStream stream = new MemoryStream();
            using (Utf8JsonWriter writer = new Utf8JsonWriter(stream))
                datagram.SerializeTo(writer);

            Assert.True(stream.Length > 0);
        }
    }
}
