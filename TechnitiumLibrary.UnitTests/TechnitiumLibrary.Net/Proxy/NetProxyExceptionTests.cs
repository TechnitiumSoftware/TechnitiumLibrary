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
    public sealed class NetProxyExceptionTests
    {
        [TestMethod]
        public void DefaultConstructor_MustProvideNonEmptyMessage_AndNullInnerException()
        {
            NetProxyException ex = new NetProxyException();

            Assert.IsFalse(
                string.IsNullOrWhiteSpace(ex.Message),
                "Default constructor must provide a non-empty diagnostic message.");

            Assert.IsNull(
                ex.InnerException,
                "Default constructor must not assign an inner exception.");

            Assert.AreEqual(
                typeof(NetProxyException),
                ex.GetType(),
                "Runtime exception type must remain exactly NetProxyException.");
        }

        [TestMethod]
        public void MessageConstructor_MustPreserveMessage()
        {
            const string message = "Net proxy operation failed.";

            NetProxyException ex = new NetProxyException(message);

            Assert.AreEqual(
                message,
                ex.Message,
                "Message constructor must preserve the supplied message verbatim.");
        }

        [TestMethod]
        public void MessageAndInnerExceptionConstructor_MustPreserveBoth()
        {
            const string message = "Proxy tunnel failure.";
            InvalidOperationException inner = new InvalidOperationException("inner");

            NetProxyException ex = new NetProxyException(message, inner);

            Assert.AreEqual(
                message,
                ex.Message,
                "Exception must preserve the supplied message.");

            Assert.AreSame(
                inner,
                ex.InnerException,
                "Exception must preserve the supplied inner exception reference.");
        }

        [TestMethod]
        public void ExceptionTypeIdentity_MustRemainStable()
        {
            Exception ex = new NetProxyException();

            Assert.AreEqual(
                typeof(NetProxyException),
                ex.GetType(),
                "Consumers rely on exact exception type identity for catch filters.");
        }
    }
}