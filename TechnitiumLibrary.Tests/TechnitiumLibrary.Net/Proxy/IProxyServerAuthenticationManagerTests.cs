using Microsoft.VisualStudio.TestTools.UnitTesting;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public sealed class IProxyServerAuthenticationManagerTests
    {
        [TestMethod]
        public void Authenticate_ReturnsTrue_AllowsAccess()
        {
            var auth = new FakeAuthManager(result: true);

            bool ok = auth.Authenticate("alice", "secret");

            Assert.IsTrue(ok, "Authentication manager should return true when credentials are accepted.");
            Assert.AreEqual("alice", auth.LastUser);
            Assert.AreEqual("secret", auth.LastPass);
        }

        [TestMethod]
        public void Authenticate_ReturnsFalse_DeniesAccess()
        {
            var auth = new FakeAuthManager(result: false);

            bool ok = auth.Authenticate("bob", "wrong");

            Assert.IsFalse(ok, "Authentication manager should return false when credentials are rejected.");
            Assert.AreEqual("bob", auth.LastUser);
            Assert.AreEqual("wrong", auth.LastPass);
        }

        [TestMethod]
        public void Authenticate_HandlesNulls()
        {
            var auth = new FakeAuthManager(result: false);

            bool ok = auth.Authenticate(null, null);

            Assert.IsFalse(ok, "Null credentials must be treated as failed authentication.");
            Assert.IsNull(auth.LastUser);
            Assert.IsNull(auth.LastPass);
        }

        [TestMethod]
        public void Authenticate_CalledExactlyOncePerInvocation()
        {
            var auth = new FakeAuthManager(result: true);

            _ = auth.Authenticate("u", "p");
            _ = auth.Authenticate("u", "p");

            Assert.AreEqual(2, auth.Calls, "Authenticate method must be invoked exactly once per request.");
        }

        private sealed class FakeAuthManager : IProxyServerAuthenticationManager
        {
            private readonly bool _result;

            public int Calls { get; private set; }
            public string LastUser { get; private set; }
            public string LastPass { get; private set; }

            public FakeAuthManager(bool result)
            {
                _result = result;
            }

            public bool Authenticate(string username, string password)
            {
                Calls++;
                LastUser = username;
                LastPass = password;
                return _result;
            }
        }
    }
}
