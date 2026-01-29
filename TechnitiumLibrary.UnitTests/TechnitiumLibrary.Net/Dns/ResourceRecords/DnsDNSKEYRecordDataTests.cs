using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Text;
using TechnitiumLibrary.Net.Dns.Dnssec;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Net.Dns.ResourceRecords
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
            DnssecPublicKey key = CreateTestRsaKey();

            DnsDNSKEYRecordData rdata = new DnsDNSKEYRecordData(
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
            DnssecPublicKey key = CreateTestRsaKey();

            DnsDNSKEYRecordData a = new DnsDNSKEYRecordData(
                DnsDnsKeyFlag.ZoneKey | DnsDnsKeyFlag.SecureEntryPoint,
                3,
                DnssecAlgorithm.RSASHA256,
                key);

            DnsDNSKEYRecordData b = new DnsDNSKEYRecordData(
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
            DnssecPublicKey key = CreateTestRsaKey();

            DnsDNSKEYRecordData a = new DnsDNSKEYRecordData(
                DnsDnsKeyFlag.ZoneKey,
                3,
                DnssecAlgorithm.RSASHA256,
                key);

            DnsDNSKEYRecordData b = new DnsDNSKEYRecordData(
                DnsDnsKeyFlag.ZoneKey,
                3,
                DnssecAlgorithm.RSASHA1,
                key);

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            DnssecPublicKey key = CreateTestRsaKey();

            DnsResourceRecord original = new DnsResourceRecord(
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
            DnsResourceRecord parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(original, parsed);
        }

        [TestMethod]
        public void CreateDS_And_IsDnsKeyValid_WorkTogether()
        {
            DnssecPublicKey key = CreateTestRsaKey();

            DnsDNSKEYRecordData dnskey = new DnsDNSKEYRecordData(
                DnsDnsKeyFlag.ZoneKey,
                3,
                DnssecAlgorithm.RSASHA256,
                key);

            DnsDSRecordData ds = dnskey.CreateDS(
                "Example.COM.",
                DnssecDigestType.SHA256);

            Assert.IsTrue(
                dnskey.IsDnsKeyValid("example.com.", ds),
                "DNSKEY must validate its own DS regardless of case");
        }

        [TestMethod]
        public void SerializeTo_ProducesExpectedJson()
        {
            DnssecPublicKey key = CreateTestRsaKey();

            DnsDNSKEYRecordData rdata = new DnsDNSKEYRecordData(
                DnsDnsKeyFlag.ZoneKey,
                3,
                DnssecAlgorithm.RSASHA256,
                key);

            using MemoryStream ms = new();
            using System.Text.Json.Utf8JsonWriter writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = Encoding.UTF8.GetString(ms.ToArray());

            Assert.Contains("Flags", json);
            Assert.Contains("Protocol", json);
            Assert.Contains("Algorithm", json);
            Assert.Contains("PublicKey", json);
            Assert.Contains("ComputedKeyTag", json);
        }

        [TestMethod]
        public void UncompressedLength_MatchesWireRdataLength()
        {
            DnssecPublicKey key = CreateTestRsaKey();

            DnsDNSKEYRecordData rdata = new DnsDNSKEYRecordData(
                DnsDnsKeyFlag.ZoneKey,
                3,
                DnssecAlgorithm.RSASHA256,
                key);

            DnsResourceRecord rr = new DnsResourceRecord(
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