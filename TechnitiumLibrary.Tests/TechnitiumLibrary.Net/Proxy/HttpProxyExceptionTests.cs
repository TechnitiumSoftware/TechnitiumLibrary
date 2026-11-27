using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public class HttpProxyExceptionTests
    {
        [TestMethod]
        public void DefaultConstructor_ProvidesNonNullMessage()
        {
            HttpProxyException ex = new HttpProxyException();

            Assert.IsFalse(
                string.IsNullOrWhiteSpace(ex.Message),
                "Default constructor must provide a non-empty diagnostic message."
            );

            Assert.IsNull(
                ex.InnerException,
                "Default constructor must not assign an inner exception."
            );

            Assert.AreEqual(
                expected: typeof(HttpProxyException),
                actual: ex.GetType(),
                message: "Exception type must remain stable for typed exception handling."
            );
        }

        [TestMethod]
        public void MessageConstructor_PreservesMessage()
        {
            string msg = "HTTP proxy operation failed.";
            HttpProxyException ex = new HttpProxyException(msg);

            Assert.AreEqual(
                expected: msg,
                actual: ex.Message,
                message: "Message constructor must preserve supplied message verbatim."
            );
        }

        [TestMethod]
        public void MessageAndInnerExceptionConstructor_PreservesBoth()
        {
            string msg = "Proxy protocol error.";
            InvalidOperationException inner = new InvalidOperationException("inner");

            HttpProxyException ex = new HttpProxyException(msg, inner);

            Assert.AreEqual(
                expected: msg,
                actual: ex.Message,
                message: "Exception must preserve its message."
            );

            Assert.AreSame(
                expected: inner,
                actual: ex.InnerException,
                message: "Exception must preserve the supplied inner exception."
            );
        }

        [TestMethod]
        public void TypeIdentity_RemainsStable()
        {
            HttpProxyException ex = new HttpProxyException();

            Assert.AreEqual(
                expected: typeof(HttpProxyException),
                actual: ex.GetType(),
                message: "Typed exceptions must preserve exact runtime type identity."
            );
        }
    }
}
