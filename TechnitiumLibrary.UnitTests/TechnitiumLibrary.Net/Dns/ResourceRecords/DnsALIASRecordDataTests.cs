using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Text;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class DnsALIASRecordDataTests
    {
        [TestMethod]
        public void Constructor_ValidInput_Succeeds()
        {
            DnsALIASRecordData rdata = new DnsALIASRecordData(
                DnsResourceRecordType.A,
                "example.net");

            Assert.AreEqual(DnsResourceRecordType.A, rdata.Type);
            Assert.AreEqual("example.net", rdata.Domain);
        }

        [TestMethod]
        public void Equals_DifferentType_IsFalse()
        {
            DnsALIASRecordData a = new DnsALIASRecordData(
                DnsResourceRecordType.A,
                "example.com");

            DnsALIASRecordData b = new DnsALIASRecordData(
                DnsResourceRecordType.AAAA,
                "example.com");

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void Equals_SameTypeAndDomain_IgnoresCase()
        {
            DnsALIASRecordData a = new DnsALIASRecordData(
                DnsResourceRecordType.AAAA,
                "Example.COM");

            DnsALIASRecordData b = new DnsALIASRecordData(
                DnsResourceRecordType.AAAA,
                "example.com");

            Assert.AreEqual(a, b);
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            DnsResourceRecord original = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.ALIAS,
                DnsClass.IN,
                300,
                new DnsALIASRecordData(
                    DnsResourceRecordType.A,
                    "target.example"));

            byte[] wire = Serialize(original);

            using MemoryStream ms = new(wire);
            DnsResourceRecord parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(original, parsed);
        }

        [TestMethod]
        public void SerializeTo_ProducesExpectedJson()
        {
            DnsALIASRecordData rdata = new DnsALIASRecordData(
                DnsResourceRecordType.AAAA,
                "example.net");

            using MemoryStream ms = new();
            using System.Text.Json.Utf8JsonWriter writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = Encoding.UTF8.GetString(ms.ToArray());

            Assert.Contains("Type", json);
            Assert.Contains("AAAA", json);
            Assert.Contains("Domain", json);
            Assert.Contains("example.net", json);
        }

        [TestMethod]
        public void UncompressedLength_IncludesTypePrefix()
        {
            DnsALIASRecordData rdata = new DnsALIASRecordData(
                DnsResourceRecordType.A,
                "example.com");

            int baseLength = rdata.Domain.Length; // not exact, but sanity check

            Assert.IsGreaterThan(baseLength, rdata.UncompressedLength);
            Assert.IsGreaterThanOrEqualTo(2, rdata.UncompressedLength);
        }

        private static byte[] Serialize(DnsResourceRecord rr)
        {
            using MemoryStream ms = new();
            rr.WriteTo(ms);
            return ms.ToArray();
        }
    }
}