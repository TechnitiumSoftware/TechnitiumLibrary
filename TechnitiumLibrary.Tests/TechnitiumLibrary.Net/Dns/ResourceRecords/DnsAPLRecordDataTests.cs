using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class DnsAPLRecordDataTests
    {
        [TestMethod]
        public void Constructor_SingleNetworkAddress_Succeeds()
        {
            var network = new NetworkAddress(IPAddress.Parse("192.0.2.0"), 24);

            var rdata = new DnsAPLRecordData(network, negation: false);

            Assert.HasCount(1, rdata.APItems);
            Assert.AreEqual(IanaAddressFamily.IPv4, rdata.APItems.First().AddressFamily);
            Assert.AreEqual(24, rdata.APItems.First().Prefix);
            Assert.IsFalse(rdata.APItems.First().Negation);
        }

        [TestMethod]
        public void APItem_NegationFlag_Preserved()
        {
            var network = new NetworkAddress(IPAddress.Parse("2001:db8::"), 32);

            var item = new DnsAPLRecordData.APItem(network, negation: true);

            Assert.IsTrue(item.Negation);
            Assert.AreEqual(IanaAddressFamily.IPv6, item.AddressFamily);
        }

        [TestMethod]
        public void Equals_SameItems_AreEqual()
        {
            var list1 = new List<DnsAPLRecordData.APItem>
            {
                new(new NetworkAddress(IPAddress.Parse("192.0.2.0"), 24), false),
                new(new NetworkAddress(IPAddress.Parse("198.51.100.0"), 24), true)
            };

            var list2 = new List<DnsAPLRecordData.APItem>
            {
                new(new NetworkAddress(IPAddress.Parse("192.0.2.0"), 24), false),
                new(new NetworkAddress(IPAddress.Parse("198.51.100.0"), 24), true)
            };

            var a = new DnsAPLRecordData(list1);
            var b = new DnsAPLRecordData(list2);

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void Equals_DifferentItems_AreNotEqual()
        {
            var a = new DnsAPLRecordData(
                new NetworkAddress(IPAddress.Parse("192.0.2.0"), 24), false);

            var b = new DnsAPLRecordData(
                new NetworkAddress(IPAddress.Parse("192.0.2.0"), 25), false);

            Assert.IsFalse(a.Equals(b));
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            var rdata = new DnsAPLRecordData(new List<DnsAPLRecordData.APItem>
            {
                new(new NetworkAddress(IPAddress.Parse("192.0.2.0"), 24), false),
                new(new NetworkAddress(IPAddress.Parse("2001:db8::"), 32), true)
            });

            var rr = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.APL,
                DnsClass.IN,
                300,
                rdata);

            byte[] wire = Serialize(rr);

            using MemoryStream ms = new(wire);
            var parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(rr, parsed);
        }

        [TestMethod]
        public void SerializeTo_ProducesJsonArray()
        {
            var rdata = new DnsAPLRecordData(
                new NetworkAddress(IPAddress.Parse("192.0.2.0"), 24), false);

            using MemoryStream ms = new();
            using var writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = Encoding.UTF8.GetString(ms.ToArray());

            StringAssert.StartsWith(json, "[");
            StringAssert.Contains(json, "IPv4");
            StringAssert.Contains(json, "Prefix");
        }

        [TestMethod]
        public void UncompressedLength_MatchesSumOfItems()
        {
            var items = new List<DnsAPLRecordData.APItem>
            {
                new(new NetworkAddress(IPAddress.Parse("192.0.2.0"), 24), false),
                new(new NetworkAddress(IPAddress.Parse("198.51.100.0"), 25), true)
            };

            var rdata = new DnsAPLRecordData(items);

            int expected = 0;
            foreach (var item in items)
                expected += item.UncompressedLength;

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