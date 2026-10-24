using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public sealed class SocksProxyExceptionTests
    {
        [TestMethod]
        public void DefaultConstructor_MustProvideNonEmptyMessage_AndNullInnerException()
        {
            SocksProxyException ex = new SocksProxyException();

            Assert.IsFalse(
                string.IsNullOrWhiteSpace(ex.Message),
                "Default constructor must provide a non-empty diagnostic message.");

            Assert.IsNull(
                ex.InnerException,
                "Default constructor must not assign an inner exception.");

            Assert.AreEqual(
                typeof(SocksProxyException),
                ex.GetType(),
                "Runtime exception type must remain exactly SocksProxyException.");
        }

        [TestMethod]
        public void MessageConstructor_MustPreserveMessage()
        {
            const string message = "SOCKS proxy operation failed.";

            SocksProxyException ex = new SocksProxyException(message);

            Assert.AreEqual(
                message,
                ex.Message,
                "Message constructor must preserve the supplied message verbatim.");
        }

        [TestMethod]
        public void MessageAndInnerExceptionConstructor_MustPreserveBoth()
        {
            const string message = "SOCKS negotiation error.";
            InvalidOperationException inner = new InvalidOperationException("inner");

            SocksProxyException ex = new SocksProxyException(message, inner);

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
            Exception ex = new SocksProxyException();

            Assert.AreEqual(
                typeof(SocksProxyException),
                ex.GetType(),
                "Consumers rely on exact exception type identity for SOCKS error handling.");
        }
    }
}
