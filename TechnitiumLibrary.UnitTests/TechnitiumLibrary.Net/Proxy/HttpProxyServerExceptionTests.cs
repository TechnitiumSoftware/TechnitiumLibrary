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
    public class HttpProxyServerExceptionTests
    {
        [TestMethod]
        public void DefaultConstructor_SetsDefaultMessage_AndNullInnerException()
        {
            HttpProxyServerException ex = new HttpProxyServerException();

            // .NET default message for exceptions with no message explicitly passed
            // always includes the fully-qualified type name.
            string expectedTypeName = typeof(HttpProxyServerException).FullName!;

            Assert.Contains(
                expectedTypeName,
                ex.Message,
                "Default constructor must include the exception type name."
            );

            Assert.IsNull(
                ex.InnerException,
                "Default constructor must not provide an inner exception."
            );
        }

        [TestMethod]
        public void MessageConstructor_SetsMessage_AndNullInnerException()
        {
            const string msg = "Server failure";

            HttpProxyServerException ex = new HttpProxyServerException(msg);

            Assert.AreEqual(
                msg,
                ex.Message,
                "Message constructor must store the provided message."
            );

            Assert.IsNull(
                ex.InnerException,
                "Message constructor must not set an inner exception."
            );
        }

        [TestMethod]
        public void MessageAndInnerConstructor_SetsMessage_AndInnerException()
        {
            const string msg = "Server failure";
            InvalidOperationException inner = new InvalidOperationException("inner");

            HttpProxyServerException ex = new HttpProxyServerException(msg, inner);

            Assert.AreEqual(
                msg,
                ex.Message,
                "Message+Inner constructor must store the provided message."
            );

            Assert.AreSame(
                inner,
                ex.InnerException,
                "The provided inner exception must be preserved."
            );
        }
    }
}