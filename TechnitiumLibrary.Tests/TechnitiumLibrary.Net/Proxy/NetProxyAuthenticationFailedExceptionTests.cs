using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public sealed class NetProxyAuthenticationFailedExceptionTests
    {
        [TestMethod]
        public void DefaultConstructor_SetsMessage_AndNullInnerException()
        {
            var ex = new NetProxyAuthenticationFailedException();

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

            var ex = new NetProxyAuthenticationFailedException(message);

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
            var inner = new InvalidOperationException("Inner failure");

            var ex = new NetProxyAuthenticationFailedException(message, inner);

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
            var ex = new NetProxyAuthenticationFailedException();

            Assert.IsInstanceOfType<NetProxyException>(
                ex,
                "NetProxyAuthenticationFailedException must inherit from NetProxyException."
            );
        }
    }
}
