using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net
{
    [TestClass]
    public sealed class EndPointExtensionsTests
    {
        [TestMethod]
        public void WriteRead_RoundTrip_IPv4()
        {
            IPEndPoint ep = new IPEndPoint(IPAddress.Parse("192.168.10.25"), 853);

            using MemoryStream ms = new MemoryStream();
            using BinaryWriter bw = new BinaryWriter(ms);

            ep.WriteTo(bw);
            ms.Position = 0;

            using BinaryReader br = new BinaryReader(ms);
            EndPoint reloaded = EndPointExtensions.ReadFrom(br);

            Assert.AreEqual(ep.Address.ToString(), reloaded.GetAddress(),
                "Round-trip must preserve IPv4 address.");
            Assert.AreEqual(ep.Port, reloaded.GetPort(),
                "Round-trip must preserve port.");
        }

        [TestMethod]
        public void WriteRead_RoundTrip_IPv6()
        {
            IPEndPoint ep = new IPEndPoint(IPAddress.IPv6Loopback, 853);

            using MemoryStream ms = new MemoryStream();
            using BinaryWriter bw = new BinaryWriter(ms);

            ep.WriteTo(bw);
            ms.Position = 0;

            using BinaryReader br = new BinaryReader(ms);
            EndPoint reloaded = EndPointExtensions.ReadFrom(br);

            Assert.AreEqual("::1", reloaded.GetAddress(),
                "Round-trip must preserve IPv6 loopback.");
            Assert.AreEqual(853, reloaded.GetPort(),
                "Round-trip must preserve port.");
        }

        [TestMethod]
        public void WriteRead_RoundTrip_Domain()
        {
            DomainEndPoint dep = new DomainEndPoint("example.org", 853);

            using MemoryStream ms = new MemoryStream();
            using BinaryWriter bw = new BinaryWriter(ms);

            dep.WriteTo(bw);
            ms.Position = 0;

            using BinaryReader br = new BinaryReader(ms);
            EndPoint reloaded = EndPointExtensions.ReadFrom(br);

            Assert.AreEqual("example.org", reloaded.GetAddress(),
                "Domain must survive round-trip serialization.");
            Assert.AreEqual(853, reloaded.GetPort(),
                "Port must survive round-trip serialization.");
        }

        [TestMethod]
        public void ReadFrom_ShouldFail_OnUnsupportedDiscriminator()
        {
            using MemoryStream ms = new MemoryStream();
            using BinaryWriter bw = new BinaryWriter(ms);

            bw.Write((byte)99); // invalid discriminator
            ms.Position = 0;

            using BinaryReader br = new BinaryReader(ms);
            Assert.ThrowsExactly<NotSupportedException>(
                () => _ = EndPointExtensions.ReadFrom(br),
                "Unsupported prefix must trigger deterministic failure.");
        }

        [TestMethod]
        public void GetAddress_ShouldReturn_IPString()
        {
            IPEndPoint ep = new IPEndPoint(IPAddress.Parse("1.2.3.4"), 1234);
            Assert.AreEqual("1.2.3.4", ep.GetAddress(),
                "Address must be returned as textual IPv4.");
        }

        [TestMethod]
        public void GetAddress_ShouldReturn_DomainString()
        {
            DomainEndPoint ep = new DomainEndPoint("dns.google", 53);
            Assert.AreEqual("dns.google", ep.GetAddress(),
                "Domain must be returned as raw host label.");
        }

        [TestMethod]
        public void GetPort_ShouldReturn_Port()
        {
            IPEndPoint ep = new IPEndPoint(IPAddress.Loopback, 1111);
            Assert.AreEqual(1111, ep.GetPort(), "Port must be returned unchanged.");
        }

        [TestMethod]
        public void SetPort_ShouldMutate_IPPort()
        {
            IPEndPoint ep = new IPEndPoint(IPAddress.Loopback, 53);
            ep.SetPort(443);

            Assert.AreEqual(443, ep.Port, "Mutated port must be observable.");
        }

        [TestMethod]
        public async Task GetIPEndPointAsync_ShouldReturn_IP_WhenAlreadyIPEndPoint()
        {
            IPEndPoint ep = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 9000);

            IPEndPoint result = await ep.GetIPEndPointAsync(cancellationToken: TestContext.CancellationToken);

            Assert.AreEqual(ep.Address, result.Address,
                "Resolved IP must match source.");
            Assert.AreEqual(ep.Port, result.Port,
                "Resolved port must match source.");
        }

        [TestMethod]
        public async Task GetIPEndPointAsync_ShouldResolve_Localhost_Predictably()
        {
            DomainEndPoint dep = new DomainEndPoint("localhost", 443);

            IPEndPoint resolved = await dep.GetIPEndPointAsync(AddressFamily.InterNetwork, cancellationToken: TestContext.CancellationToken);

            Assert.AreEqual(443, resolved.Port, "Resolved port must match declared port.");
            Assert.AreEqual(AddressFamily.InterNetwork, resolved.Address.AddressFamily,
                "Requested AF must be honored when at least one matching address exists.");
        }

        [TestMethod]
        public async Task GetIPEndPointAsync_ShouldFail_WhenDNSReturnsEmpty()
        {
            DomainEndPoint dep = new DomainEndPoint("test-invalid-unresolvable-domain.local", 5000);

            await Assert.ThrowsExactlyAsync<SocketException>(
                async () => await dep.GetIPEndPointAsync(cancellationToken: TestContext.CancellationToken),
                "Unresolvable name must trigger HostNotFound.");
        }

        [TestMethod]
        public async Task GetIPEndPointAsync_ShouldFallback_WhenRequestedFamilyUnsupported()
        {
            DomainEndPoint dep = new DomainEndPoint("localhost", 853);

            IPEndPoint ep = await dep.GetIPEndPointAsync(AddressFamily.AppleTalk, cancellationToken: TestContext.CancellationToken);

            Assert.IsNotNull(ep);
            Assert.AreEqual(853, ep.Port, "Port must be preserved.");
            Assert.IsInstanceOfType(ep, typeof(IPEndPoint), "Returned endpoint must still be resolved.");
        }

        [TestMethod]
        public void GetEndPoint_ShouldReturn_IPEndpoint_OnLiteralIP()
        {
            EndPoint ep = EndPointExtensions.GetEndPoint("10.20.30.40", 8080);

            Assert.IsInstanceOfType(ep, typeof(IPEndPoint),
                "Literal IP input must produce IPEndPoint.");
        }

        [TestMethod]
        public void GetEndPoint_ShouldReturn_DomainEndPoint_OnHostName()
        {
            EndPoint ep = EndPointExtensions.GetEndPoint("dns.google", 53);

            Assert.IsInstanceOfType(ep, typeof(DomainEndPoint),
                "Non-IP literal must produce domain endpoint.");
        }

        [TestMethod]
        public void TryParse_ShouldReturnTrue_ForIPEndPointSyntax()
        {
            Assert.IsTrue(EndPointExtensions.TryParse("5.6.7.8:22", out EndPoint? ep),
                "Valid IP must be parsed.");
            Assert.IsInstanceOfType(ep, typeof(IPEndPoint));
        }

        [TestMethod]
        public void TryParse_ShouldReturnTrue_ForDomainSyntax()
        {
            Assert.IsTrue(EndPointExtensions.TryParse("example.com:25", out EndPoint? ep),
                "Valid domain:port must be parsed.");
            Assert.IsInstanceOfType(ep, typeof(DomainEndPoint));
        }

        [TestMethod]
        public void TryParse_ShouldFail_WhenMissingPort()
        {
            Assert.IsFalse(EndPointExtensions.TryParse("example.com", out EndPoint? ep),
                "Missing port must not parse successfully.");
            Assert.IsNull(ep, "Return must be null on parse failure.");
        }

        [TestMethod]
        public void IsEquals_ShouldCompare_IPCorrectly()
        {
            IPEndPoint a = new IPEndPoint(IPAddress.Parse("1.1.1.1"), 853);
            IPEndPoint b = new IPEndPoint(IPAddress.Parse("1.1.1.1"), 853);

            Assert.IsTrue(a.IsEquals(b),
                "IPEndPoint equality must fully honor IP + port.");
        }

        [TestMethod]
        public void IsEquals_ShouldCompare_DomainCorrectly()
        {
            DomainEndPoint a = new DomainEndPoint("example.org", 443);
            DomainEndPoint b = new DomainEndPoint("example.org", 443);

            Assert.IsTrue(a.IsEquals(b),
                "Domain endpoints must compare by semantic equality.");
        }

        [TestMethod]
        public void IsEquals_MustReturnFalse_OnDifferentAddresses()
        {
            DomainEndPoint a = new DomainEndPoint("example.org", 443);
            DomainEndPoint b = new DomainEndPoint("example.net", 443);

            Assert.IsFalse(a.IsEquals(b),
                "Different hostnames must not compare equal.");
        }

        [TestMethod]
        public void IsEquals_MustReturnFalse_OnDifferentPorts()
        {
            IPEndPoint a = new IPEndPoint(IPAddress.Parse("8.8.8.8"), 53);
            IPEndPoint b = new IPEndPoint(IPAddress.Parse("8.8.8.8"), 853);

            Assert.IsFalse(a.IsEquals(b),
                "Same address but different port must not compare equal.");
        }

        public TestContext TestContext { get; set; }
    }
}
