using System.Net;
using System.Text.Json;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.Dnssec;
using TechnitiumLibrary.Net.Dns.EDnsOptions;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    public class DnsResourceRecordDataTests
    {
        public static IEnumerable<object[]> RecordDataRoundTripCases()
        {
            yield return Case(DnsResourceRecordType.A, new DnsARecordData(IPAddress.Parse("192.0.2.1")));
            yield return Case(DnsResourceRecordType.AAAA, new DnsAAAARecordData(IPAddress.Parse("2001:db8::1")));
            yield return Case(DnsResourceRecordType.NS, new DnsNSRecordData("ns1.example.test"));
            yield return Case(DnsResourceRecordType.CNAME, new DnsCNAMERecordData("target.example.test"));
            yield return Case(DnsResourceRecordType.DNAME, new DnsDNAMERecordData("target.example.test"));
            yield return Case(DnsResourceRecordType.PTR, new DnsPTRRecordData("ptr.example.test"));
            yield return Case(DnsResourceRecordType.ANAME, new DnsANAMERecordData("alias.example.test"));
            yield return Case(DnsResourceRecordType.ALIAS, new DnsALIASRecordData(DnsResourceRecordType.A, "alias.example.test"));
            yield return Case(DnsResourceRecordType.MX, new DnsMXRecordData(10, "mail.example.test"));
            yield return Case(DnsResourceRecordType.SOA, new DnsSOARecordData("ns1.example.test", "hostmaster.example.test", 1, 3600, 600, 604800, 60));
            yield return Case(DnsResourceRecordType.SRV, new DnsSRVRecordData(1, 5, 443, "svc.example.test"));
            yield return Case(DnsResourceRecordType.RP, new DnsRPRecordData("admin.example.test", "txt.example.test"));
            yield return Case(DnsResourceRecordType.HINFO, new DnsHINFORecordData("x64", "linux"));
            yield return Case(DnsResourceRecordType.TXT, new DnsTXTRecordData(["hello", "world"]));
            yield return Case(DnsResourceRecordType.NAPTR, new DnsNAPTRRecordData(1, 2, "s", "SIP+D2U", "!^.*$!sip:info@example.test!", "replacement.example.test"));
            yield return Case(DnsResourceRecordType.CAA, new DnsCAARecordData(0, "issue", "ca.example.test"));
            yield return Case(DnsResourceRecordType.URI, new DnsURIRecordData(10, 1, new Uri("https://example.test/dns")));
            yield return Case(DnsResourceRecordType.DS, new DnsDSRecordData(12345, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256, Bytes(32)));
            yield return Case(DnsResourceRecordType.DNSKEY, new DnsDNSKEYRecordData(DnsDnsKeyFlag.ZoneKey, 3, DnssecAlgorithm.Unknown, DnssecPublicKey.Parse(DnssecAlgorithm.Unknown, Bytes(8))));
            yield return Case(DnsResourceRecordType.RRSIG, new DnsRRSIGRecordData(DnsResourceRecordType.A, DnssecAlgorithm.RSASHA256, 2, 60, 2000000000, 1900000000, 12345, "example.test", Bytes(16)));
            yield return Case(DnsResourceRecordType.NSEC, new DnsNSECRecordData("next.example.test", [DnsResourceRecordType.A, DnsResourceRecordType.AAAA, DnsResourceRecordType.RRSIG]));
            yield return Case(DnsResourceRecordType.NSEC3, new DnsNSEC3RecordData(DnssecNSEC3HashAlgorithm.SHA1, DnssecNSEC3Flags.OptOut, 2, [1, 2], Bytes(20), [DnsResourceRecordType.NS, DnsResourceRecordType.DS]));
            yield return Case(DnsResourceRecordType.NSEC3PARAM, new DnsNSEC3PARAMRecordData(DnssecNSEC3HashAlgorithm.SHA1, DnssecNSEC3Flags.None, 2, [1, 2]));
            yield return Case(DnsResourceRecordType.SSHFP, new DnsSSHFPRecordData(DnsSSHFPAlgorithm.RSA, DnsSSHFPFingerprintType.SHA256, Bytes(32)));
            yield return Case(DnsResourceRecordType.TLSA, new DnsTLSARecordData(DnsTLSACertificateUsage.DANE_EE, DnsTLSASelector.SPKI, DnsTLSAMatchingType.SHA2_256, Bytes(32)));
            yield return Case(DnsResourceRecordType.ZONEMD, new DnsZONEMDRecordData(1234, ZoneMdScheme.Simple, ZoneMdHashAlgorithm.SHA384, Bytes(48)));
            yield return Case(DnsResourceRecordType.APL, new DnsAPLRecordData(new NetworkAddress(IPAddress.Parse("192.0.2.0"), 24), false));
            yield return Case(DnsResourceRecordType.SVCB, new DnsSVCBRecordData(1, "svc.example.test", new Dictionary<DnsSvcParamKey, DnsSvcParamValue>
            {
                [DnsSvcParamKey.ALPN] = new DnsSvcAlpnParamValue(["h2", "dot"]),
                [DnsSvcParamKey.Port] = new DnsSvcPortParamValue(853),
                [DnsSvcParamKey.IPv4Hint] = new DnsSvcIPv4HintParamValue([IPAddress.Parse("192.0.2.53")]),
                [DnsSvcParamKey.IPv6Hint] = new DnsSvcIPv6HintParamValue([IPAddress.Parse("2001:db8::53")]),
                [DnsSvcParamKey.DoHPath] = new DnsSvcDoHPathParamValue("/dns-query{?dns}")
            }));
            yield return Case(DnsResourceRecordType.TSIG, new DnsTSIGRecordData("hmac-sha256", DateTime.UnixEpoch.AddSeconds(1234), 300, Bytes(16), 7, DnsTsigError.NoError, [9, 8]));
            yield return Case(DnsResourceRecordType.FWD, new DnsForwarderRecordData(DnsTransportProtocol.Udp, "192.0.2.53", true, DnsForwarderRecordProxyType.NoProxy, null, 0, null, null, 1));
            yield return Case(DnsResourceRecordType.APP, new DnsApplicationRecordData("app", "Namespace.Type", "{\"enabled\":true}"));
        }

        [Theory]
        [MemberData(nameof(RecordDataRoundTripCases))]
        public void RecordDataRoundTripsThroughWireFormat(DnsResourceRecordType type, DnsResourceRecordData recordData)
        {
            byte[] rData = WriteAndExtractRData(recordData);

            DnsResourceRecordData parsed = DnsResourceRecord.ReadRecordDataFrom(type, rData);

            Assert.Equal(recordData, parsed);
            Assert.True(parsed.UncompressedLength > 0);
            Assert.NotEmpty(parsed.ToString());
            AssertJsonCanBeWritten(parsed);
        }

        [Fact]
        public void UnknownRecordDataRoundTripsEmptyAndNonEmptyPayloads()
        {
            DnsResourceRecordData empty = DnsResourceRecord.ReadRecordDataFrom((DnsResourceRecordType)65000, []);
            DnsResourceRecordData payload = DnsResourceRecord.ReadRecordDataFrom((DnsResourceRecordType)65000, [1, 2, 3, 4]);

            Assert.Equal(new DnsUnknownRecordData([]), empty);
            Assert.Equal(new DnsUnknownRecordData([1, 2, 3, 4]), payload);
            Assert.NotEqual(empty, payload);
            AssertJsonCanBeWritten(empty);
            AssertJsonCanBeWritten(payload);
        }

        [Fact]
        public void OptRecordDataRoundTripsKnownAndUnknownOptions()
        {
            DnsOPTRecordData recordData = new DnsOPTRecordData(
            [
                new EDnsOption(EDnsOptionCode.EDNS_CLIENT_SUBNET, new EDnsClientSubnetOptionData(24, 0, IPAddress.Parse("192.0.2.0"))),
                new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.NetworkError, "upstream timeout")),
                new EDnsOption(EDnsOptionCode.COOKIE, new EDnsUnknownOptionData([1, 2, 3, 4]))
            ]);

            DnsOPTRecordData parsed = Assert.IsType<DnsOPTRecordData>(DnsResourceRecord.ReadRecordDataFrom(DnsResourceRecordType.OPT, WriteAndExtractRData(recordData)));

            Assert.Equal(recordData, parsed);
            Assert.Equal(3, parsed.Options.Count);
            Assert.IsType<EDnsClientSubnetOptionData>(parsed.Options[0].Data);
            Assert.IsType<EDnsExtendedDnsErrorOptionData>(parsed.Options[1].Data);
            Assert.IsType<EDnsUnknownOptionData>(parsed.Options[2].Data);
            AssertJsonCanBeWritten(parsed);
        }

        private static object[] Case(DnsResourceRecordType type, DnsResourceRecordData recordData)
        {
            return [type, recordData];
        }

        private static byte[] WriteAndExtractRData(DnsResourceRecordData recordData)
        {
            using MemoryStream stream = new MemoryStream();
            recordData.WriteTo(stream);
            byte[] wireFormat = stream.ToArray();
            return wireFormat.Skip(2).ToArray();
        }

        private static byte[] Bytes(int length)
        {
            return Enumerable.Range(1, length).Select(i => (byte)i).ToArray();
        }

        private static void AssertJsonCanBeWritten(DnsResourceRecordData recordData)
        {
            using MemoryStream stream = new MemoryStream();
            using (Utf8JsonWriter writer = new Utf8JsonWriter(stream))
                recordData.SerializeTo(writer);

            Assert.True(stream.Length > 0);
        }
    }
}
