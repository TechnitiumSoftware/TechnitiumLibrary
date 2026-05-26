using TechnitiumLibrary.Net.Tor;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Tor
{
    public class TorProjectTests
    {
        [Fact]
        public void TorControllerException_PreservesMessageAndInnerException()
        {
            InvalidOperationException inner = new InvalidOperationException("inner");
            TorControllerException ex = new TorControllerException("controller failed", inner);

            Assert.Equal("controller failed", ex.Message);
            Assert.Same(inner, ex.InnerException);
        }

        [Fact]
        public void TorProxyType_ValuesRemainStable()
        {
            Assert.Equal(0, (int)TorProxyType.None);
            Assert.Equal(1, (int)TorProxyType.Http);
            Assert.Equal(4, (int)TorProxyType.Socks5);
        }
    }
}
