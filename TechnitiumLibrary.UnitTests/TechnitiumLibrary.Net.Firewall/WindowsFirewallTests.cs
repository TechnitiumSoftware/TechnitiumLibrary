using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using TechnitiumLibrary.Net.Firewall;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Net.Firewall
{
    [TestClass]
    public sealed class WindowsFirewallPublicTests
    {
        [TestMethod]
        public void AddPort_ShouldThrow_WhenUnsupportedProtocol()
        {
            // Protocol ICMPv4 cannot be added using AddPort
            Assert.ThrowsExactly<Exception>(() => WindowsFirewall.AddPort("bad", Protocol.ICMPv4, port: 55, enable: true));
        }

        [TestMethod]
        public void RemovePort_ShouldThrow_WhenUnsupportedProtocol()
        {
            // RemovePort validates only TCP, UDP, ANY
            Assert.ThrowsExactly<Exception>(() => WindowsFirewall.RemovePort(Protocol.IGMP, 123));
        }

        [TestMethod]
        public void PortExists_ShouldThrow_WhenUnsupportedProtocol()
        {
            Assert.ThrowsExactly<Exception>(() => WindowsFirewall.PortExists(Protocol.IGMP, 44));
        }

        [TestMethod]
        public void RuleExistsVista_ShouldReturnDoesNotExist_WhenInputsClearlyNotMatchingAnything()
        {
            // Since firewall is not guaranteed to have this rule,
            // safest expected response is DoesNotExists.
            RuleStatus result = WindowsFirewall.RuleExistsVista(
                name: "__Definitely_Not_A_Real_Rule__",
                applicationPath: "__Fake__");

            Assert.AreEqual(RuleStatus.DoesNotExists, result);
        }

        [TestMethod]
        public void ApplicationExists_ShouldReturnDoesNotExist_WhenApplicationIsNotRegistered()
        {
            // Public observable guarantee:
            // if the system has no such application entry → DoesNotExists

            const string fakePath = "C:\\DefinitelyNotExisting\\app.exe";

            RuleStatus status = WindowsFirewall.ApplicationExists(fakePath);

            Assert.AreEqual(RuleStatus.DoesNotExists, status);
        }
    }
}
