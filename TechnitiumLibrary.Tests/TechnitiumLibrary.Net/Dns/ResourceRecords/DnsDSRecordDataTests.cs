using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Text;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class DnsDSRecordDataTests
    {
        [TestMethod]
        public void Constructor_InvalidDigestLength_Throws()
        {
            byte[] invalidDigest = new byte[10];

            Assert.ThrowsExactly<ArgumentException>(() =>
                new DnsDSRecordData(
                    keyTag: 1,
                    algorithm: DnssecAlgorithm.RSASHA256,
                    digestType: DnssecDigestType.SHA256,
                    digest: invalidDigest));
        }

        [TestMethod]
        public void Constructor_ValidSHA256_Succeeds()
        {
            byte[] digest = new byte[32];
            Random.Shared.NextBytes(digest);

            var rdata = new DnsDSRecordData(
                keyTag: 12345,
                algorithm: DnssecAlgorithm.RSASHA256,
                digestType: DnssecDigestType.SHA256,
                digest: digest);

            Assert.AreEqual((ushort)12345, rdata.KeyTag);
            Assert.AreEqual(DnssecAlgorithm.RSASHA256, rdata.Algorithm);
            Assert.AreEqual(DnssecDigestType.SHA256, rdata.DigestType);
            CollectionAssert.AreEqual(digest, rdata.Digest);
        }

        [TestMethod]
        public void Equals_DifferentDigest_IsFalse()
        {
            byte[] digestA = new byte[20];
            byte[] digestB = new byte[20];
            Random.Shared.NextBytes(digestA);
            Random.Shared.NextBytes(digestB);

            var a = new DnsDSRecordData(
                10,
                DnssecAlgorithm.RSASHA1,
                DnssecDigestType.SHA1,
                digestA);

            var b = new DnsDSRecordData(
                10,
                DnssecAlgorithm.RSASHA1,
                DnssecDigestType.SHA1,
                digestB);

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void Equals_SameValues_AreEqual()
        {
            byte[] digest = new byte[20];
            Random.Shared.NextBytes(digest);

            var a = new DnsDSRecordData(
                10,
                DnssecAlgorithm.RSASHA1,
                DnssecDigestType.SHA1,
                digest);

            var b = new DnsDSRecordData(
                10,
                DnssecAlgorithm.RSASHA1,
                DnssecDigestType.SHA1,
                digest);

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void IsDigestTypeSupported_WorksAsSpecified()
        {
            Assert.IsTrue(DnsDSRecordData.IsDigestTypeSupported(DnssecDigestType.SHA1));
            Assert.IsTrue(DnsDSRecordData.IsDigestTypeSupported(DnssecDigestType.SHA256));
            Assert.IsFalse(DnsDSRecordData.IsDigestTypeSupported(DnssecDigestType.GOST_R_34_11_94));
        }

        [TestMethod]
        public void IsDnssecAlgorithmSupported_WorksAsSpecified()
        {
            Assert.IsTrue(DnsDSRecordData.IsDnssecAlgorithmSupported(DnssecAlgorithm.RSASHA256));
            Assert.IsTrue(DnsDSRecordData.IsDnssecAlgorithmSupported(DnssecAlgorithm.ED25519));
            Assert.IsFalse(DnsDSRecordData.IsDnssecAlgorithmSupported(DnssecAlgorithm.RSAMD5));
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            byte[] digest = new byte[32];
            Random.Shared.NextBytes(digest);

            var original = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.DS,
                DnsClass.IN,
                3600,
                new DnsDSRecordData(
                    54321,
                    DnssecAlgorithm.RSASHA256,
                    DnssecDigestType.SHA256,
                    digest));

            byte[] wire = Serialize(original);

            using MemoryStream ms = new(wire);
            var parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(original, parsed);
        }

        [TestMethod]
        public void SerializeTo_ProducesExpectedJson()
        {
            byte[] digest = new byte[32];
            Random.Shared.NextBytes(digest);

            var rdata = new DnsDSRecordData(
                100,
                DnssecAlgorithm.RSASHA256,
                DnssecDigestType.SHA256,
                digest);

            using MemoryStream ms = new();
            using var writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = Encoding.UTF8.GetString(ms.ToArray());

            StringAssert.Contains(json, "KeyTag");
            StringAssert.Contains(json, "Algorithm");
            StringAssert.Contains(json, "DigestType");
            StringAssert.Contains(json, "Digest");
        }

        [TestMethod]
        public void UncompressedLength_MatchesExpected()
        {
            byte[] digest = new byte[48];
            Random.Shared.NextBytes(digest);

            var rdata = new DnsDSRecordData(
                1,
                DnssecAlgorithm.ECDSAP384SHA384,
                DnssecDigestType.SHA384,
                digest);

            Assert.AreEqual(2 + 1 + 1 + 48, rdata.UncompressedLength);
        }

        private static byte[] Serialize(DnsResourceRecord rr)
        {
            using MemoryStream ms = new();
            rr.WriteTo(ms);
            return ms.ToArray();
        }
    }
}