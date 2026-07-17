using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Proxy
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
