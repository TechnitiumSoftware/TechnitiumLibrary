using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Text;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class DnsMXRecordDataTests
    {
        [TestMethod]
        public void Constructor_ValidInput_Succeeds()
        {
            var rdata = new DnsMXRecordData(
                preference: 10,
                exchange: "mail.example.com.");

            Assert.AreEqual((ushort)10, rdata.Preference);
            Assert.AreEqual("mail.example.com.", rdata.Exchange);
        }

        [TestMethod]
        public void Equals_SameValues_IgnoresCaseOnExchange()
        {
            var a = new DnsMXRecordData(
                10,
                "Mail.EXAMPLE.COM.");

            var b = new DnsMXRecordData(
                10,
                "mail.example.com.");

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void Equals_DifferentPreference_IsFalse()
        {
            var a = new DnsMXRecordData(10, "mail.example.com.");
            var b = new DnsMXRecordData(20, "mail.example.com.");

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void Equals_DifferentExchange_IsFalse()
        {
            var a = new DnsMXRecordData(10, "mail1.example.com.");
            var b = new DnsMXRecordData(10, "mail2.example.com.");

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void CompareTo_OrdersByPreference()
        {
            var low = new DnsMXRecordData(5, "a.example.");
            var high = new DnsMXRecordData(20, "b.example.");

            Assert.IsLessThan(0, low.CompareTo(high));
            Assert.IsGreaterThan(0, high.CompareTo(low));
            Assert.AreEqual(0, low.CompareTo(new DnsMXRecordData(5, "other.example.")));
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            var original = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.MX,
                DnsClass.IN,
                3600,
                new DnsMXRecordData(
                    10,
                    "mail.example."));

            byte[] wire = Serialize(original);

            using MemoryStream ms = new(wire);
            var parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(original, parsed);
        }

        [TestMethod]
        public void SerializeTo_ProducesExpectedJson()
        {
            var rdata = new DnsMXRecordData(
                10,
                "mail.example.com.");

            using MemoryStream ms = new();
            using var writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = Encoding.UTF8.GetString(ms.ToArray());

            Assert.Contains("Preference", json);
            Assert.Contains("10", json);
            Assert.Contains("Exchange", json);
            Assert.Contains("mail.example.com.", json);
        }

        [TestMethod]
        public void UncompressedLength_MatchesFormula()
        {
            var rdata = new DnsMXRecordData(
                5,
                "mail.example.");

            int expected =
                2 + DnsDatagram.GetSerializeDomainNameLength("mail.example.");

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