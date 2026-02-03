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
using System;
using TechnitiumLibrary.Net.Firewall;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Net.Firewall
{
    [TestClass]
    public sealed class WindowsFirewallTests
    {
        [TestMethod]
        [OSCondition(OperatingSystems.Windows)]
        public void AddPort_ShouldThrow_WhenUnsupportedProtocol()
        {
            // Protocol ICMPv4 cannot be added using AddPort
            Assert.ThrowsExactly<Exception>(() => WindowsFirewall.AddPort("bad", Protocol.ICMPv4, port: 55, enable: true));
        }

        [TestMethod]
        [OSCondition(OperatingSystems.Windows)]
        public void RemovePort_ShouldThrow_WhenUnsupportedProtocol()
        {
            // RemovePort validates only TCP, UDP, ANY
            Assert.ThrowsExactly<Exception>(() => WindowsFirewall.RemovePort(Protocol.IGMP, 123));
        }

        [TestMethod]
        [OSCondition(OperatingSystems.Windows)]
        public void PortExists_ShouldThrow_WhenUnsupportedProtocol()
        {
            Assert.ThrowsExactly<Exception>(() => WindowsFirewall.PortExists(Protocol.IGMP, 44));
        }

        [TestMethod]
        [OSCondition(OperatingSystems.Windows)]
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
        [OSCondition(OperatingSystems.Windows)]
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
