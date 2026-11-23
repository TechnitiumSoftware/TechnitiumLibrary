using System.IO;
using System.Linq;
using System.Net;
using TechnitiumLibrary.Net;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net
{
    public class NetworkAccessControlTests
    {
        [Fact]
        public void ParseHandlesAllowAndDenyRules()
        {
            NetworkAccessControl allow = NetworkAccessControl.Parse("192.0.2.0/24");
            NetworkAccessControl deny = NetworkAccessControl.Parse("! 192.0.2.128/25");

            Assert.False(allow.Deny);
            Assert.True(deny.Deny);
            Assert.Equal("192.0.2.0/24", allow.ToString());
            Assert.Equal("!192.0.2.128/25", deny.ToString());
            Assert.False(NetworkAccessControl.TryParse("not-a-network", out _));
            Assert.Throws<FormatException>(() => NetworkAccessControl.Parse("not-a-network"));
        }

        [Fact]
        public void TryMatchReturnsAllowedStateWhenAddressIsInsideNetwork()
        {
            NetworkAccessControl allow = NetworkAccessControl.Parse("192.0.2.0/24");
            NetworkAccessControl deny = NetworkAccessControl.Parse("!192.0.2.0/24");

            Assert.True(allow.TryMatch(IPAddress.Parse("192.0.2.42"), out bool isAllowed));
            Assert.True(isAllowed);
            Assert.True(deny.TryMatch(IPAddress.Parse("192.0.2.42"), out isAllowed));
            Assert.False(isAllowed);
            Assert.False(allow.TryMatch(IPAddress.Parse("192.0.3.42"), out isAllowed));
            Assert.False(isAllowed);
        }

        [Fact]
        public void IsAddressAllowedUsesFirstMatchingRuleAndLoopbackFallback()
        {
            NetworkAccessControl[] acl =
            [
                NetworkAccessControl.Parse("!192.0.2.128/25"),
                NetworkAccessControl.Parse("192.0.2.0/24")
            ];

            Assert.False(NetworkAccessControl.IsAddressAllowed(IPAddress.Parse("192.0.2.200"), acl));
            Assert.True(NetworkAccessControl.IsAddressAllowed(IPAddress.Parse("192.0.2.42"), acl));
            Assert.False(NetworkAccessControl.IsAddressAllowed(IPAddress.Parse("198.51.100.1"), acl));
            Assert.True(NetworkAccessControl.IsAddressAllowed(IPAddress.Loopback, null, allowLoopbackWhenNoMatch: true));
            Assert.True(NetworkAccessControl.IsAddressAllowed(IPAddress.Parse("::ffff:192.0.2.42"), acl));
        }

        [Fact]
        public void WriteAndReadRoundtrips()
        {
            NetworkAccessControl expected = NetworkAccessControl.Parse("!2001:db8::/32");
            using MemoryStream stream = new MemoryStream();

            expected.WriteTo(stream);
            stream.Position = 0;

            NetworkAccessControl actual = NetworkAccessControl.ReadFrom(stream);

            Assert.Equal(expected, actual);
            Assert.Equal(expected.GetHashCode(), actual.GetHashCode());
        }

        [Fact]
        public void BinaryWriterAndReaderOverloadsRoundtrip()
        {
            NetworkAccessControl expected = new NetworkAccessControl(IPAddress.Parse("192.0.2.1"), 32);
            using MemoryStream stream = new MemoryStream();
            using BinaryWriter writer = new BinaryWriter(stream);

            expected.WriteTo(writer);
            stream.Position = 0;

            NetworkAccessControl actual = NetworkAccessControl.ReadFrom(new BinaryReader(stream));

            Assert.Equal(expected, actual);
            Assert.False(actual.Deny);
            Assert.Equal(IPAddress.Parse("192.0.2.1"), actual.NetworkAddress.Address);
        }

        [Fact]
        public void AplConversionRoundtripsAccessControlList()
        {
            NetworkAccessControl[] expected =
            [
                NetworkAccessControl.Parse("192.0.2.0/24"),
                NetworkAccessControl.Parse("!2001:db8::/32")
            ];

            var apl = NetworkAccessControl.ConvertToAPLRecordData(expected);
            NetworkAccessControl[] actual = NetworkAccessControl.ConvertFromAPLRecordData(apl).ToArray();

            Assert.Equal(expected, actual);
        }

        [Fact]
        public void EqualsHandlesNullReferenceAndDifferentValues()
        {
            NetworkAccessControl accessControl = NetworkAccessControl.Parse("192.0.2.0/24");

            Assert.True(accessControl.Equals((object)accessControl));
            Assert.False(accessControl.Equals(null));
            Assert.False(accessControl.Equals((object)"192.0.2.0/24"));
            Assert.False(accessControl.Equals(NetworkAccessControl.Parse("!192.0.2.0/24")));
            Assert.False(accessControl.Equals(NetworkAccessControl.Parse("192.0.3.0/24")));
        }
    }
}
