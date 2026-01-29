using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Text;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class DnsCAARecordDataTests
    {
        [TestMethod]
        public void Constructor_EmptyTag_Throws()
        {
            Assert.ThrowsExactly<InvalidDataException>(() =>
                new DnsCAARecordData(
                    0,
                    "",
                    "value"));
        }

        [TestMethod]
        public void Constructor_TagIsLowercased()
        {
            DnsCAARecordData rdata = new DnsCAARecordData(
                0,
                "ISSUE",
                "ca.example");

            Assert.AreEqual("issue", rdata.Tag);
        }

        [TestMethod]
        public void Constructor_ValidInput_Succeeds()
        {
            DnsCAARecordData rdata = new DnsCAARecordData(
                flags: 0,
                tag: "issue",
                value: "letsencrypt.org");

            Assert.AreEqual((byte)0, rdata.Flags);
            Assert.AreEqual("issue", rdata.Tag);
            Assert.AreEqual("letsencrypt.org", rdata.Value);
        }

        [TestMethod]
        public void Equals_DifferentFlags_AreNotEqual()
        {
            DnsCAARecordData a = new DnsCAARecordData(0, "issue", "ca.example");
            DnsCAARecordData b = new DnsCAARecordData(128, "issue", "ca.example");

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void Equals_DifferentValue_AreNotEqual()
        {
            DnsCAARecordData a = new DnsCAARecordData(0, "issue", "ca.example");
            DnsCAARecordData b = new DnsCAARecordData(0, "issue", "other.example");

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void Equals_SameValues_AreEqual()
        {
            DnsCAARecordData a = new DnsCAARecordData(0, "issue", "ca.example");
            DnsCAARecordData b = new DnsCAARecordData(0, "ISSUE", "ca.example");

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            DnsResourceRecord original = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.CAA,
                DnsClass.IN,
                300,
                new DnsCAARecordData(
                    0,
                    "issue",
                    "letsencrypt.org"));

            byte[] wire = Serialize(original);

            using MemoryStream ms = new(wire);
            DnsResourceRecord parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(original, parsed);
        }

        [TestMethod]
        public void SerializeTo_ProducesExpectedJson()
        {
            DnsCAARecordData rdata = new DnsCAARecordData(
                128,
                "iodef",
                "mailto:security@example.com");

            using MemoryStream ms = new();
            using System.Text.Json.Utf8JsonWriter writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = Encoding.UTF8.GetString(ms.ToArray());

            Assert.Contains("Flags", json);
            Assert.Contains("128", json);
            Assert.Contains("Tag", json);
            Assert.Contains("iodef", json);
            Assert.Contains("Value", json);
            Assert.Contains("mailto:security@example.com", json);
        }

        [TestMethod]
        public void UncompressedLength_MatchesExpectedSize()
        {
            DnsCAARecordData rdata = new DnsCAARecordData(
                0,
                "issue",
                "ca.example");

            int expected =
                1 +                 // flags
                1 +                 // tag length
                "issue".Length +
                "ca.example".Length;

            Assert.AreEqual(expected, rdata.UncompressedLength);
        }

        private static byte[] Serialize(DnsResourceRecord rr)
        {
            using MemoryStream ms = new();
            rr.WriteTo(ms);
            return ms.ToArray();
        }
    }
}