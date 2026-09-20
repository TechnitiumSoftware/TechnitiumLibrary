/*
Technitium Library
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Text;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Net.Dns.ResourceRecords
{
    [TestClass]
    public class DnsForwarderRecordDataTests
    {
        [TestMethod]
        public void Constructor_MinimalValidInput_Succeeds()
        {
            DnsForwarderRecordData rdata = new DnsForwarderRecordData(
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
            DnsForwarderRecordData partial = DnsForwarderRecordData.CreatePartialRecordData(
                DnsTransportProtocol.Udp,
                "9.9.9.9");

            DnsForwarderRecordData full = new DnsForwarderRecordData(
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
            DnsForwarderRecordData a = new DnsForwarderRecordData(
                DnsTransportProtocol.Tcp,
                "1.1.1.1",
                true,
                DnsForwarderRecordProxyType.None,
                null,
                0,
                null,
                null,
                1);

            DnsForwarderRecordData b = new DnsForwarderRecordData(
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
            DnsForwarderRecordData rdata = new DnsForwarderRecordData(
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
            DnsForwarderRecordData rdata = new DnsForwarderRecordData(
                DnsTransportProtocol.Tcp,
                "1.1.1.1",
                dnssecValidation: true,
                proxyType: DnsForwarderRecordProxyType.Http,
                proxyAddress: "proxy.example",
                proxyPort: 3128,
                proxyUsername: "user",
                proxyPassword: "pass",
                priority: 20);

            DnsResourceRecord rr = new DnsResourceRecord(
                "example",
                DnsResourceRecordType.FWD,
                DnsClass.IN,
                60,
                rdata);

            byte[] wire = Serialize(rr);

            using MemoryStream ms = new(wire);
            DnsResourceRecord parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(rr, parsed);
        }

        [TestMethod]
        public void RoundTrip_StreamConstructor_PreservesEquality()
        {
            DnsResourceRecord original = new DnsResourceRecord(
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
            DnsResourceRecord parsed = new DnsResourceRecord(ms);

            Assert.AreEqual(original, parsed);
        }

        [TestMethod]
        public void SerializeTo_ProducesExpectedJson()
        {
            DnsForwarderRecordData rdata = new DnsForwarderRecordData(
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
            using System.Text.Json.Utf8JsonWriter writer = new System.Text.Json.Utf8JsonWriter(ms);

            rdata.SerializeTo(writer);
            writer.Flush();

            string json = Encoding.UTF8.GetString(ms.ToArray());

            Assert.Contains("Protocol", json);
            Assert.Contains("Forwarder", json);
            Assert.Contains("Priority", json);
            Assert.Contains("DnssecValidation", json);
        }

        [TestMethod]
        public void UncompressedLength_IsNonZero()
        {
            DnsForwarderRecordData rdata = new DnsForwarderRecordData(
                DnsTransportProtocol.Udp,
                "1.1.1.1",
                false,
                DnsForwarderRecordProxyType.None,
                null,
                0,
                null,
                null,
                0);

            Assert.IsGreaterThan(0, rdata.UncompressedLength);
        }

        private static byte[] Serialize(DnsResourceRecord rr)
        {
            using MemoryStream ms = new();
            rr.WriteTo(ms);
            return ms.ToArray();
        }
    }
}