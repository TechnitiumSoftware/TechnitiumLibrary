using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Text;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class DnsForwarderRecordDataTests
    {
        [TestMethod]
        public void Constructor_MinimalValidInput_Succeeds()
        {
            var rdata = new DnsForwarderRecordData(
                DnsTransportProtocol.Udp,
                "8.8.8.8",
                dnssecValidation: false,
                proxyType: DnsForwarderRecordProxyType.None,
                proxyAddress: null,
                proxyPort: 0,
                proxyUsername: null,
                proxyPassword: null,
                priority: 10);

            Assert.AreEqual(DnsTransportProtocol.Udp, rdata.Protocol);
            Assert.AreEqual("8.8.8.8", rdata.Forwarder);
            Assert.AreEqual(10, rdata.Priority);
            Assert.IsFalse(rdata.DnssecValidation);
            Assert.AreEqual(DnsForwarderRecordProxyType.None, rdata.ProxyType);
        }

        [TestMethod]
        public void Equals_PartialRecord_IgnoresOptionalFields()
        {
            var partial = DnsForwarderRecordData.CreatePartialRecordData(
                DnsTransportProtocol.Udp,
                "9.9.9.9");

            var full = new DnsForwarderRecordData(
                DnsTransportProtocol.Udp,
                "9.9.9.9",
                dnssecValidation: true,
                proxyType: DnsForwarderRecordProxyType.Http,
                proxyAddress: "proxy.local",
                proxyPort: 8080,
                proxyUsername: "user",
                proxyPassword: "pass",
                priority: 100);

            Assert.IsTrue(partial.Equals(full));
        }

        [TestMethod]
        public void Equals_SameValues_AreEqual()
        {
            var a = new DnsForwarderRecordData(
                DnsTransportProtocol.Tcp,
                "1.1.1.1",
                true,
                DnsForwarderRecordProxyType.None,
                null,
                0,
                null,
                null,
                1);

            var b = new DnsForwarderRecordData(
                DnsTransportProtocol.Tcp,
                "1.1.1.1",
                true,
                DnsForwarderRecordProxyType.None,
                null,
                0,
                null,
                null,
                1);

            Assert.IsTrue(a.Equals(b));
            Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
        }

        [TestMethod]
        public void GetProxy_ReturnsConfiguredProxy()
        {
            var rdata = new DnsForwarderRecordData(
                DnsTransportProtocol.Tcp,
                "8.8.8.8",
                dnssecValidation: false,
                proxyType: DnsForwarderRecordProxyType.Socks5,
                proxyAddress: "proxy.local",
                proxyPort: 1080,
                proxyUsername: "u",
                proxyPassword: "p",
                priority: 0);

            NetProxy proxy = rdata.GetProxy(null);

            Assert.IsNotNull(proxy);
            Assert.AreEqual(NetProxyType.Socks5, proxy.Type);
        }

        [TestMethod]
        public void HttpProxy_IsSerializedAndParsedCorrectly()
        {
            var rdata = new DnsForwarderRecordData(
                DnsTransportProtocol.Tcp,
                "1.1.1.1",
                dnssecValidation: true,
                proxyType: DnsForwarderRecordProxyType.Http,
                proxyAddress: "proxy.example",
                proxyPort: 3128,
                proxyUsername: "user",
                proxyPassword: "pass",
                priority: 20);

            var rr = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.FWD,
                DnsClass.IN,
                60,
                rdata);

            byte[] wire = Serialize(rr);

            using MemoryStream ms = new(wire);
            var parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(rr, parsed);
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            var original = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.FWD,
                DnsClass.IN,
                60,
                new DnsForwarderRecordData(
                    DnsTransportProtocol.Tcp,
                    "8.8.4.4",
                    dnssecValidation: true,
                    proxyType: DnsForwarderRecordProxyType.None,
                    proxyAddress: null,
                    proxyPort: 0,
                    proxyUsername: null,
                    proxyPassword: null,
                    priority: 5));

            byte[] wire = Serialize(original);

            using MemoryStream ms = new(wire);
            var parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(original, parsed);
        }

        [TestMethod]
        public void SerializeTo_ProducesExpectedJson()
        {
            var rdata = new DnsForwarderRecordData(
                DnsTransportProtocol.Udp,
                "8.8.8.8",
                dnssecValidation: false,
                proxyType: DnsForwarderRecordProxyType.None,
                proxyAddress: null,
                proxyPort: 0,
                proxyUsername: null,
                proxyPassword: null,
                priority: 1);

            using MemoryStream ms = new();
            using var writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = Encoding.UTF8.GetString(ms.ToArray());

            StringAssert.Contains(json, "Protocol");
            StringAssert.Contains(json, "Forwarder");
            StringAssert.Contains(json, "Priority");
            StringAssert.Contains(json, "DnssecValidation");
        }

        [TestMethod]
        public void UncompressedLength_IsNonZero()
        {
            var rdata = new DnsForwarderRecordData(
                DnsTransportProtocol.Udp,
                "1.1.1.1",
                false,
                DnsForwarderRecordProxyType.None,
                null,
                0,
                null,
                null,
                0);

            Assert.IsTrue(rdata.UncompressedLength > 0);
        }

        private static byte[] Serialize(DnsResourceRecord rr)
        {
            using MemoryStream ms = new();
            rr.WriteTo(ms);
            return ms.ToArray();
        }
    }
}