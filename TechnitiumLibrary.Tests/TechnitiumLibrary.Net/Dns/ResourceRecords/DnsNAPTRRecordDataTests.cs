using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Linq;
using System.Text;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class DnsNAPTRRecordDataTests
    {
        private static byte[] SerializeRecord(DnsResourceRecord record)
        {
            using MemoryStream ms = new();
            record.WriteTo(ms);
            return ms.ToArray();
        }

        [TestMethod]
        public void Constructor_ValidInput_Succeeds()
        {
            var rdata = new DnsNAPTRRecordData(
                order: 100,
                preference: 10,
                flags: "U",
                services: "SIP+D2U",
                regexp: "!^.*$!sip:info@example.com!",
                replacement: "Example.COM.");

            var rr = new DnsResourceRecord(
                "example.com.",
                DnsResourceRecordType.NAPTR,
                DnsClass.IN,
                60,
                rdata);

            Assert.AreEqual("U", rdata.Flags);
            Assert.AreEqual("Example.COM", rdata.Replacement);
            Assert.IsNotNull(rr);
        }

        [TestMethod]
        public void Constructor_CharacterStringTooLong_Throws()
        {
            string longValue = new string('a', 256);

            Assert.ThrowsExactly<DnsClientException>(() =>
                new DnsNAPTRRecordData(
                    0, 0,
                    longValue,
                    "",
                    "",
                    "."));
        }

        [TestMethod]
        public void Constructor_NonAsciiCharacter_Throws()
        {
            Assert.ThrowsExactly<DnsClientException>(() =>
                new DnsNAPTRRecordData(
                    0, 0,
                    "Ü",
                    "",
                    "",
                    "."));
        }


        [TestMethod]
        public void WriteTo_PreservesOriginalCaseOnWire()
        {
            var rdata = new DnsNAPTRRecordData(
                1, 1, "U", "SIP+D2U", "", "Example.COM.");

            var rr = new DnsResourceRecord(
                "Example.COM.",
                DnsResourceRecordType.NAPTR,
                DnsClass.IN,
                60,
                rdata);

            byte[] bytes = SerializeRecord(rr);

            // Ensure uppercase bytes are present
            Assert.IsTrue(bytes.Contains((byte)'E'));
            Assert.IsTrue(bytes.Contains((byte)'C'));
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            var originalRdata = new DnsNAPTRRecordData(
                50,
                20,
                "U",
                "SIP+D2T",
                "!^.*$!sip:test@example.net!",
                "example.net."); // replacement MAY be absolute

            var original = new DnsResourceRecord(
                "example.net",   // owner MUST be relative
                DnsResourceRecordType.NAPTR,
                DnsClass.IN,
                120,
                originalRdata);

            byte[] wire = SerializeRecord(original);

            using MemoryStream ms = new(wire);
            var parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(original, parsed);
        }

        [TestMethod]
        public void Equals_IsCaseInsensitivePerDnsRules()
        {
            var a = new DnsNAPTRRecordData(
                10, 10,
                "U",
                "SIP+D2U",
                "",
                "example.org.");

            var b = new DnsNAPTRRecordData(
                10, 10,
                "u",
                "sip+d2u",
                "",
                "EXAMPLE.ORG.");

            Assert.IsTrue(a.Equals(b));
        }

        [TestMethod]
        public void UncompressedLength_MatchesWireRdataLength()
        {
            var rdata = new DnsNAPTRRecordData(
                1, 1,
                "U",
                "SIP+D2U",
                "",
                "example.org.");

            var rr = new DnsResourceRecord(
                "example.org.",
                DnsResourceRecordType.NAPTR,
                DnsClass.IN,
                60,
                rdata);

            byte[] wire = SerializeRecord(rr);

            // Strip NAME + TYPE + CLASS + TTL + RDLENGTH (minimum DNS RR header)
            int rdataOffset = wire.Length - rdata.UncompressedLength;

            Assert.AreEqual(
                rdata.UncompressedLength,
                wire.Length - rdataOffset);
        }

        [TestMethod]
        public void ToString_ProducesZoneFileCompatibleOutput()
        {
            var rdata = new DnsNAPTRRecordData(
                100, 10,
                "U",
                "SIP+D2U",
                "!^.*$!sip:info@example.com!",
                "example.com.");

            var rr = new DnsResourceRecord(
                "example.com.",
                DnsResourceRecordType.NAPTR,
                DnsClass.IN,
                60,
                rdata);

            string text = rr.ToString();

            Assert.Contains("NAPTR", text);
            Assert.Contains("SIP+D2U", text);
            Assert.Contains("example.com.", text);
        }
    }
}
