using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public class HttpProxyServerExceptionTests
    {
        [TestMethod]
        public void DefaultConstructor_SetsDefaultMessage_AndNullInnerException()
        {
            var ex = new HttpProxyServerException();

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

            var ex = new HttpProxyServerException(msg);

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
            var inner = new InvalidOperationException("inner");

            var ex = new HttpProxyServerException(msg, inner);

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
