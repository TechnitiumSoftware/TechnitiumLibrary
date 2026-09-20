using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public sealed class SocksProxyAuthenticationFailedExceptionTests
    {
        [TestMethod]
        public void DefaultConstructor_MustProvideNonEmptyMessage_AndNullInnerException()
        {
            SocksProxyAuthenticationFailedException ex = new SocksProxyAuthenticationFailedException();

            Assert.IsFalse(
                string.IsNullOrWhiteSpace(ex.Message),
                "Default constructor must provide a non-empty diagnostic message.");

            Assert.IsNull(
                ex.InnerException,
                "Default constructor must not assign an inner exception.");

            Assert.AreEqual(
                typeof(SocksProxyAuthenticationFailedException),
                ex.GetType(),
                "Exception type identity must remain stable.");
        }

        [TestMethod]
        public void MessageConstructor_MustPreserveMessage()
        {
            const string message = "SOCKS authentication failed.";

            SocksProxyAuthenticationFailedException ex =
                new SocksProxyAuthenticationFailedException(message);

            Assert.AreEqual(
                message,
                ex.Message,
                "Message constructor must preserve the supplied message verbatim.");
        }

        [TestMethod]
        public void MessageAndInnerExceptionConstructor_MustPreserveBoth()
        {
            const string message = "SOCKS auth rejected.";
            InvalidOperationException inner = new InvalidOperationException("inner");

            SocksProxyAuthenticationFailedException ex =
                new SocksProxyAuthenticationFailedException(message, inner);

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
        public void ExceptionTypeIdentity_MustRemainExact()
        {
            Exception ex = new SocksProxyAuthenticationFailedException();

            Assert.AreEqual(
                typeof(SocksProxyAuthenticationFailedException),
                ex.GetType(),
                "Consumers rely on exact exception type identity for authentication failure handling.");
        }
    }
}
