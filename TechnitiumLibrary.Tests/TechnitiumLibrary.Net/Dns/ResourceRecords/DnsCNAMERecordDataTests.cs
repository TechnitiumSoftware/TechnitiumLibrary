using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Text;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class DnsCNAMERecordDataTests
    {
        [TestMethod]
        public void Constructor_IDNDomain_IsConvertedToAscii()
        {
            var rdata = new DnsCNAMERecordData("bücher.example");

            Assert.AreEqual("xn--bcher-kva.example", rdata.Domain);
        }

        [TestMethod]
        public void Constructor_InvalidDomain_Throws()
        {
            Assert.ThrowsExactly<DnsClientException>(() =>
                new DnsCNAMERecordData("invalid..domain"));
        }

        [TestMethod]
        public void Constructor_ValidInput_Succeeds()
        {
            var rdata = new DnsCNAMERecordData("example.net.");

            Assert.AreEqual("example.net", rdata.Domain);
        }

        [TestMethod]
        public void Equals_DifferentDomain_IsFalse()
        {
            var a = new DnsCNAMERecordData("a.example.");
            var b = new DnsCNAMERecordData("b.example.");

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void Equals_SameDomain_IgnoresCase()
        {
            var a = new DnsCNAMERecordData("Example.COM.");
            var b = new DnsCNAMERecordData("example.com.");

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            var original = new DnsResourceRecord(
                "www",
                DnsResourceRecordType.CNAME,
                DnsClass.IN,
                300,
                new DnsCNAMERecordData("target.example."));

            byte[] wire = Serialize(original);

            using MemoryStream ms = new(wire);
            var parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(original, parsed);
        }

        [TestMethod]
        public void SerializeTo_ProducesExpectedJson()
        {
            var rdata = new DnsCNAMERecordData("example.net.");

            using MemoryStream ms = new();
            using var writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = Encoding.UTF8.GetString(ms.ToArray());

            StringAssert.Contains(json, "Domain");
            StringAssert.Contains(json, "example.net");
        }

        [TestMethod]
        public void UncompressedLength_IsPositiveAndConsistent()
        {
            var rdata = new DnsCNAMERecordData("example.org.");

            Assert.IsTrue(rdata.UncompressedLength > 0);

            var rr = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.CNAME,
                DnsClass.IN,
                60,
                rdata);

            byte[] wire = Serialize(rr);

            Assert.IsTrue(wire.Length >= rdata.UncompressedLength);
        }

        private static byte[] Serialize(DnsResourceRecord rr)
        {
            using MemoryStream ms = new();
            rr.WriteTo(ms);
            return ms.ToArray();
        }
    }
}