using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Text;
using TechnitiumLibrary.Net.Dns.Dnssec;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class DnsDNSKEYRecordDataTests
    {
        private static DnssecPublicKey CreateTestRsaKey()
        {
            // Minimal RSA public key material for deterministic testing
            // (exponent + modulus per DNSSEC wire format)
            byte[] rawKey =
            {
                0x01, 0x00, 0x01,             // exponent 65537
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE  // dummy modulus bytes
            };

            return DnssecPublicKey.Parse(
                DnssecAlgorithm.RSASHA256,
                rawKey);
        }

        [TestMethod]
        public void Constructor_ValidInput_Succeeds()
        {
            var key = CreateTestRsaKey();

            var rdata = new DnsDNSKEYRecordData(
                DnsDnsKeyFlag.ZoneKey,
                3,
                DnssecAlgorithm.RSASHA256,
                key);

            Assert.AreEqual(DnsDnsKeyFlag.ZoneKey, rdata.Flags);
            Assert.AreEqual((byte)3, rdata.Protocol);
            Assert.AreEqual(DnssecAlgorithm.RSASHA256, rdata.Algorithm);
            Assert.HasCount(key.RawPublicKey.Length, rdata.PublicKey.RawPublicKey);
            Assert.IsGreaterThan(0, rdata.ComputedKeyTag);
        }

        [TestMethod]
        public void Equals_SameValues_AreEqual()
        {
            var key = CreateTestRsaKey();

            var a = new DnsDNSKEYRecordData(
                DnsDnsKeyFlag.ZoneKey | DnsDnsKeyFlag.SecureEntryPoint,
                3,
                DnssecAlgorithm.RSASHA256,
                key);

            var b = new DnsDNSKEYRecordData(
                DnsDnsKeyFlag.ZoneKey | DnsDnsKeyFlag.SecureEntryPoint,
                3,
                DnssecAlgorithm.RSASHA256,
                key);

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void Equals_DifferentAlgorithm_IsFalse()
        {
            var key = CreateTestRsaKey();

            var a = new DnsDNSKEYRecordData(
                DnsDnsKeyFlag.ZoneKey,
                3,
                DnssecAlgorithm.RSASHA256,
                key);

            var b = new DnsDNSKEYRecordData(
                DnsDnsKeyFlag.ZoneKey,
                3,
                DnssecAlgorithm.RSASHA1,
                key);

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            var key = CreateTestRsaKey();

            var original = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.DNSKEY,
                DnsClass.IN,
                3600,
                new DnsDNSKEYRecordData(
                    DnsDnsKeyFlag.ZoneKey,
                    3,
                    DnssecAlgorithm.RSASHA256,
                    key));

            byte[] wire = Serialize(original);

            using MemoryStream ms = new(wire);
            var parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(original, parsed);
        }

        [TestMethod]
        public void CreateDS_And_IsDnsKeyValid_WorkTogether()
        {
            var key = CreateTestRsaKey();

            var dnskey = new DnsDNSKEYRecordData(
                DnsDnsKeyFlag.ZoneKey,
                3,
                DnssecAlgorithm.RSASHA256,
                key);

            var ds = dnskey.CreateDS(
                "Example.COM.",
                DnssecDigestType.SHA256);

            Assert.IsTrue(
                dnskey.IsDnsKeyValid("example.com.", ds),
                "DNSKEY must validate its own DS regardless of case");
        }

        [TestMethod]
        public void SerializeTo_ProducesExpectedJson()
        {
            var key = CreateTestRsaKey();

            var rdata = new DnsDNSKEYRecordData(
                DnsDnsKeyFlag.ZoneKey,
                3,
                DnssecAlgorithm.RSASHA256,
                key);

            using MemoryStream ms = new();
            using var writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = Encoding.UTF8.GetString(ms.ToArray());

            StringAssert.Contains(json, "Flags");
            StringAssert.Contains(json, "Protocol");
            StringAssert.Contains(json, "Algorithm");
            StringAssert.Contains(json, "PublicKey");
            StringAssert.Contains(json, "ComputedKeyTag");
        }

        [TestMethod]
        public void UncompressedLength_MatchesWireRdataLength()
        {
            var key = CreateTestRsaKey();

            var rdata = new DnsDNSKEYRecordData(
                DnsDnsKeyFlag.ZoneKey,
                3,
                DnssecAlgorithm.RSASHA256,
                key);

            var rr = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.DNSKEY,
                DnsClass.IN,
                3600,
                rdata);

            byte[] wire = Serialize(rr);

            Assert.IsGreaterThan(0, rdata.UncompressedLength);
            Assert.IsGreaterThanOrEqualTo(rdata.UncompressedLength, wire.Length);
        }

        private static byte[] Serialize(DnsResourceRecord rr)
        {
            using MemoryStream ms = new();
            rr.WriteTo(ms);
            return ms.ToArray();
        }
    }
}