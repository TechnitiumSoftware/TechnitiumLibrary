using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Net;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class CanonicallySerializedResourceRecordTests
    {
        [TestMethod]
        public void CompareTo_UsesCanonicalRdataOrdering()
        {
            using MemoryStream buffer = new();

            var low = CanonicallySerializedResourceRecord.Create(
                "example.com",
                DnsResourceRecordType.A,
                DnsClass.IN,
                60,
                new DnsARecordData(IPAddress.Parse("192.0.2.1")),
                buffer);

            var high = CanonicallySerializedResourceRecord.Create(
                "example.com",
                DnsResourceRecordType.A,
                DnsClass.IN,
                60,
                new DnsARecordData(IPAddress.Parse("192.0.2.200")),
                buffer);

            Assert.IsTrue(low.CompareTo(high) < 0);
            Assert.IsTrue(high.CompareTo(low) > 0);
        }

        [TestMethod]
        public void Create_CanonicalizesOwnerName_ToLowercase()
        {
            using MemoryStream buffer = new();

            var record = CanonicallySerializedResourceRecord.Create(
                name: "Example.COM",
                type: DnsResourceRecordType.A,
                @class: DnsClass.IN,
                originalTtl: 3600,
                rData: new DnsARecordData(IPAddress.Parse("192.0.2.1")),
                buffer: buffer);

            using MemoryStream ms = new();
            record.WriteTo(ms);

            string wire = System.Text.Encoding.ASCII.GetString(ms.ToArray());
            StringAssert.Contains(wire, "example");
        }

        [TestMethod]
        public void WriteTo_IsDeterministic_ForSameInput()
        {
            using MemoryStream buffer = new();

            var a = CanonicallySerializedResourceRecord.Create(
                "example.com",
                DnsResourceRecordType.A,
                DnsClass.IN,
                60,
                new DnsARecordData(IPAddress.Parse("192.0.2.1")),
                buffer);

            var b = CanonicallySerializedResourceRecord.Create(
                "example.com",
                DnsResourceRecordType.A,
                DnsClass.IN,
                60,
                new DnsARecordData(IPAddress.Parse("192.0.2.1")),
                buffer);

            using MemoryStream m1 = new();
            using MemoryStream m2 = new();

            a.WriteTo(m1);
            b.WriteTo(m2);

            CollectionAssert.AreEqual(m1.ToArray(), m2.ToArray());
        }
    }
}