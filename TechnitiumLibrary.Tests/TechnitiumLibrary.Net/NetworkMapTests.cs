using System.Net;
using System.Net.Sockets;
using TechnitiumLibrary.Net;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net
{
    public class NetworkMapTests
    {
        [Fact]
        public void TryGetValueReturnsValueForAddressesInsideIPv4Network()
        {
            NetworkMap<object> map = new NetworkMap<object>(AddressFamily.InterNetwork);
            object value = new object();

            map.Add("192.0.2.0/24", value);

            Assert.True(map.TryGetValue("192.0.2.0", out object actual));
            Assert.Same(value, actual);
            Assert.True(map.TryGetValue(IPAddress.Parse("192.0.2.200"), out actual));
            Assert.Same(value, actual);
            Assert.True(map.TryGetValue("192.0.2.255", out actual));
            Assert.Same(value, actual);
            Assert.False(map.TryGetValue("192.0.3.1", out actual));
            Assert.Null(actual);
        }

        [Fact]
        public void RemoveDeletesBothBoundaryEntries()
        {
            NetworkMap<object> map = new NetworkMap<object>(AddressFamily.InterNetwork);
            NetworkAddress network = NetworkAddress.Parse("192.0.2.0/24");
            object value = new object();

            map.Add(network, value);

            Assert.True(map.Remove(network));
            Assert.False(map.TryGetValue("192.0.2.42", out _));
            Assert.False(map.Remove(network));
        }

        [Fact]
        public void TryGetValueReturnsFalseWhenMapIsEmptyOrAddressIsOutsideRange()
        {
            NetworkMap<object> map = new NetworkMap<object>(AddressFamily.InterNetwork, capacity: 4);

            Assert.False(map.TryGetValue("192.0.2.1", out _));

            object value = new object();
            map.Add("192.0.2.10/32", value);

            Assert.False(map.TryGetValue("192.0.2.9", out _));
            Assert.False(map.TryGetValue("192.0.2.11", out _));
        }

        [Fact]
        public void IPv6NetworksCanBeAddedAndQueried()
        {
            NetworkMap<object> map = new NetworkMap<object>(AddressFamily.InterNetworkV6);
            object value = new object();

            map.Add("2001:db8::/32", value);

            Assert.True(map.TryGetValue("2001:db8::1234", out object actual));
            Assert.Same(value, actual);
            Assert.False(map.TryGetValue("2001:db9::1", out _));
        }

        [Fact]
        public void AddRemoveAndLookupRejectWrongAddressFamily()
        {
            NetworkMap<object> ipv4Map = new NetworkMap<object>(AddressFamily.InterNetwork);

            Assert.Throws<ArgumentException>(() => ipv4Map.Add("2001:db8::/32", new object()));
            Assert.Throws<ArgumentException>(() => ipv4Map.Remove(NetworkAddress.Parse("2001:db8::/32")));
            Assert.Throws<ArgumentException>(() => ipv4Map.TryGetValue(IPAddress.Parse("2001:db8::1"), out _));
        }
    }
}
