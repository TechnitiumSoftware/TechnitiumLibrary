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
    public class HttpProxyAuthenticationFailedExceptionTests
    {
        [TestMethod]
        public void DefaultConstructor_SetsDefaultMessage()
        {
            HttpProxyAuthenticationFailedException ex = new HttpProxyAuthenticationFailedException();

            Assert.AreEqual(
                expected: new HttpProxyAuthenticationFailedException().Message,
                actual: ex.Message,
                message: "Default constructor must provide the base exception message."
            );

            Assert.IsNull(ex.InnerException, "Default constructor must not assign an inner exception.");
        }

        [TestMethod]
        public void MessageConstructor_PreservesMessage()
        {
            string msg = "Proxy auth failed.";
            HttpProxyAuthenticationFailedException ex = new HttpProxyAuthenticationFailedException(msg);

            Assert.AreEqual(
                expected: msg,
                actual: ex.Message,
                message: "Message constructor must preserve the supplied message verbatim."
            );
        }

        [TestMethod]
        public void MessageAndInnerConstructor_PreservesBoth()
        {
            string msg = "Proxy authentication failed.";
            InvalidOperationException inner = new InvalidOperationException("inner");
            HttpProxyAuthenticationFailedException ex = new HttpProxyAuthenticationFailedException(msg, inner);

            Assert.AreEqual(
                expected: msg,
                actual: ex.Message,
                message: "Constructor must store the message."
            );

            Assert.AreSame(
                expected: inner,
                actual: ex.InnerException,
                message: "Constructor must attach the inner exception."
            );
        }

        [TestMethod]
        public void ExceptionType_IsCorrect()
        {
            HttpProxyAuthenticationFailedException ex = new HttpProxyAuthenticationFailedException();

            Assert.AreEqual(
                expected: typeof(HttpProxyAuthenticationFailedException),
                actual: ex.GetType(),
                message: "Exception type must remain stable for consumer type checks."
            );
        }
    }
}