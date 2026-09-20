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
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public sealed class NetProxyAuthenticationFailedExceptionTests
    {
        [TestMethod]
        public void DefaultConstructor_SetsMessage_AndNullInnerException()
        {
            NetProxyAuthenticationFailedException ex = new NetProxyAuthenticationFailedException();

            Assert.IsNotNull(
                ex.Message,
                "Default constructor must set a non-null message."
            );

            Assert.IsGreaterThan(
0,
                ex.Message.Length, "Default constructor must provide a meaningful error message."
            );

            Assert.IsNull(
                ex.InnerException,
                "Default constructor must not assign an inner exception."
            );
        }

        [TestMethod]
        public void Constructor_WithMessage_PreservesMessage_AndNullInnerException()
        {
            const string message = "Authentication failed due to invalid credentials.";

            NetProxyAuthenticationFailedException ex = new NetProxyAuthenticationFailedException(message);

            Assert.AreEqual(
                message,
                ex.Message,
                "Message-only constructor must preserve the provided message verbatim."
            );

            Assert.IsNull(
                ex.InnerException,
                "Message-only constructor must not assign an inner exception."
            );
        }

        [TestMethod]
        public void Constructor_WithMessageAndInnerException_PreservesBoth()
        {
            const string message = "Authentication failed.";
            InvalidOperationException inner = new InvalidOperationException("Inner failure");

            NetProxyAuthenticationFailedException ex = new NetProxyAuthenticationFailedException(message, inner);

            Assert.AreEqual(
                message,
                ex.Message,
                "Constructor must preserve the provided message verbatim."
            );

            Assert.AreSame(
                inner,
                ex.InnerException,
                "Constructor must preserve the provided inner exception reference."
            );
        }

        [TestMethod]
        public void Exception_IsNetProxyException()
        {
            NetProxyAuthenticationFailedException ex = new NetProxyAuthenticationFailedException();

            Assert.IsInstanceOfType<NetProxyException>(
                ex,
                "NetProxyAuthenticationFailedException must inherit from NetProxyException."
            );
        }
    }
}