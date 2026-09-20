using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Text;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class DnsHINFORecordDataTests
    {
        [TestMethod]
        public void Constructor_ValidInput_Succeeds()
        {
            var rdata = new DnsHINFORecordData(
                cpu: "INTEL",
                os: "LINUX");

            Assert.AreEqual("INTEL", rdata.CPU);
            Assert.AreEqual("LINUX", rdata.OS);
        }

        [TestMethod]
        public void Equals_SameValues_AreEqual()
        {
            var a = new DnsHINFORecordData("AMD64", "WINDOWS");
            var b = new DnsHINFORecordData("AMD64", "WINDOWS");

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void Equals_DifferentCpu_IsFalse()
        {
            var a = new DnsHINFORecordData("INTEL", "LINUX");
            var b = new DnsHINFORecordData("ARM", "LINUX");

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void Equals_DifferentOs_IsFalse()
        {
            var a = new DnsHINFORecordData("INTEL", "LINUX");
            var b = new DnsHINFORecordData("INTEL", "BSD");

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            var original = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.HINFO,
                DnsClass.IN,
                3600,
                new DnsHINFORecordData("INTEL", "LINUX"));

            byte[] wire = Serialize(original);

            using MemoryStream ms = new(wire);
            var parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(original, parsed);
        }

        [TestMethod]
        public void SerializeTo_ProducesExpectedJson()
        {
            var rdata = new DnsHINFORecordData("ARM", "IOS");

            using MemoryStream ms = new();
            using var writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = Encoding.UTF8.GetString(ms.ToArray());

            StringAssert.Contains(json, "CPU");
            StringAssert.Contains(json, "ARM");
            StringAssert.Contains(json, "OS");
            StringAssert.Contains(json, "IOS");
        }

        [TestMethod]
        public void UncompressedLength_MatchesExpectedFormula()
        {
            var rdata = new DnsHINFORecordData("CPU", "OS");

            int expected =
                1 + "CPU".Length +
                1 + "OS".Length;

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