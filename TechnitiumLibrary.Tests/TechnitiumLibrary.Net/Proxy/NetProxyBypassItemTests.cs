using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public sealed class NetProxyBypassItemTests
    {
        // ------------------------------------------------------------
        // IPv4 CIDR
        // ------------------------------------------------------------

        [TestMethod]
        public void IsMatching_Ipv4Cidr_MatchesAddressInsideRange()
        {
            var bypass = new NetProxyBypassItem("192.168.1.0/24");
            var ep = new IPEndPoint(IPAddress.Parse("192.168.1.42"), 80);

            Assert.IsTrue(
                bypass.IsMatching(ep),
                "IPv4 address inside CIDR range must bypass the proxy."
            );
        }

        [TestMethod]
        public void IsMatching_Ipv4Cidr_DoesNotMatchOutsideRange()
        {
            var bypass = new NetProxyBypassItem("192.168.1.0/24");
            var ep = new IPEndPoint(IPAddress.Parse("192.168.2.1"), 80);

            Assert.IsFalse(
                bypass.IsMatching(ep),
                "IPv4 address outside CIDR range must not bypass the proxy."
            );
        }

        // ------------------------------------------------------------
        // Exact IP match
        // ------------------------------------------------------------

        [TestMethod]
        public void IsMatching_ExactIpv4Address_MatchesOnlySameAddress()
        {
            var bypass = new NetProxyBypassItem("10.0.0.5");

            Assert.IsTrue(
                bypass.IsMatching(new IPEndPoint(IPAddress.Parse("10.0.0.5"), 1234)),
                "Exact IPv4 address must match regardless of port."
            );

            Assert.IsFalse(
                bypass.IsMatching(new IPEndPoint(IPAddress.Parse("10.0.0.6"), 1234)),
                "Different IPv4 address must not match exact bypass entry."
            );
        }

        // ------------------------------------------------------------
        // IPv6 CIDR
        // ------------------------------------------------------------

        [TestMethod]
        public void IsMatching_Ipv6Cidr_MatchesAddressInsideRange()
        {
            var bypass = new NetProxyBypassItem("fe80::/10");
            var ep = new IPEndPoint(IPAddress.Parse("fe80::1"), 443);

            Assert.IsTrue(
                bypass.IsMatching(ep),
                "IPv6 address inside CIDR range must bypass the proxy."
            );
        }

        [TestMethod]
        public void IsMatching_Ipv6Cidr_DoesNotMatchOutsideRange()
        {
            var bypass = new NetProxyBypassItem("fe80::/10");
            var ep = new IPEndPoint(IPAddress.Parse("2001:db8::1"), 443);

            Assert.IsFalse(
                bypass.IsMatching(ep),
                "IPv6 address outside CIDR range must not bypass the proxy."
            );
        }

        // ------------------------------------------------------------
        // Hostname matching
        // ------------------------------------------------------------

        [TestMethod]
        public void IsMatching_Localhost_BypassesLoopbackIp()
        {
            var bypass = new NetProxyBypassItem("localhost");

            Assert.IsTrue(
                bypass.IsMatching(new IPEndPoint(IPAddress.Loopback, 80)),
                "Bypass entry 'localhost' must match IPv4 loopback address."
            );

            Assert.IsTrue(
                bypass.IsMatching(new IPEndPoint(IPAddress.IPv6Loopback, 80)),
                "Bypass entry 'localhost' must match IPv6 loopback address."
            );
        }

        [TestMethod]
        public void IsMatching_Localhost_DoesNotMatchDnsEndPoint()
        {
            var bypass = new NetProxyBypassItem("localhost");

            var ep = new DnsEndPoint("localhost", 80);

            Assert.IsFalse(
                bypass.IsMatching(ep),
                "Bypass logic must not resolve or match DnsEndPoint hostnames."
            );
        }


        [TestMethod]
        public void IsMatching_Hostname_DoesNotMatchDifferentName()
        {
            var bypass = new NetProxyBypassItem("localhost");

            var ep = new DnsEndPoint("example.com", 80);

            Assert.IsFalse(
                bypass.IsMatching(ep),
                "Different hostname must not bypass the proxy."
            );
        }

        // ------------------------------------------------------------
        // Safety and stability
        // ------------------------------------------------------------

        [TestMethod]
        public void IsMatching_UnsupportedEndpointType_ReturnsFalse()
        {
            var bypass = new NetProxyBypassItem("127.0.0.1");

            EndPoint unsupported = new IPEndPoint(IPAddress.IPv6Any, 0);

            Assert.IsFalse(
                bypass.IsMatching(unsupported),
                "Unsupported or non-matching endpoint types must fail safely."
            );
        }

        [TestMethod]
        public void IsMatching_RepeatedCalls_AreDeterministic()
        {
            var bypass = new NetProxyBypassItem("192.168.0.0/16");
            var ep = new IPEndPoint(IPAddress.Parse("192.168.10.10"), 80);

            bool first = bypass.IsMatching(ep);
            bool second = bypass.IsMatching(ep);

            Assert.AreEqual(
                first,
                second,
                "Bypass decision must be deterministic across multiple invocations."
            );
        }
    }
}
