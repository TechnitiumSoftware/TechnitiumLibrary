using System.IO;
using System.Linq;
using System.Text;
using TechnitiumLibrary.Net.BitTorrent;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.BitTorrent
{
    public class TrackerClientIDTests
    {
        [Fact]
        public void WriteAndReadRoundtrips()
        {
            byte[] peerId = Enumerable.Range(1, 20).Select(Convert.ToByte).ToArray();
            byte[] clientKey = [1, 2, 3, 4];
            TrackerClientID expected = new TrackerClientID(peerId, clientKey, "agent", "gzip", 25, compact: true, noPeerID: false);
            using MemoryStream stream = new MemoryStream();

            expected.WriteTo(stream);
            stream.Position = 0;

            TrackerClientID actual = new TrackerClientID(stream);

            Assert.Equal(peerId, actual.PeerID);
            Assert.Equal(clientKey, actual.ClientKey);
            Assert.Equal("agent", actual.HttpUserAgent);
            Assert.Equal("gzip", actual.HttpAcceptEncoding);
            Assert.Equal(25, actual.NumWant);
            Assert.True(actual.Compact);
            Assert.False(actual.NoPeerID);
        }

        [Fact]
        public void GenerateClientKeyReturnsFourBytes()
        {
            Assert.Equal(4, TrackerClientID.GenerateClientKey().Length);
        }

        [Fact]
        public void GeneratePeerIDUsesAzureusStylePrefixAndTwentyBytes()
        {
            byte[] peerId = TrackerClientID.GeneratePeerID("UT3430");

            Assert.Equal(20, peerId.Length);
            Assert.StartsWith("-UT3430-", Encoding.UTF8.GetString(peerId));
        }

        [Fact]
        public void CreateDefaultIDUsesExpectedPublicDefaults()
        {
            TrackerClientID id = TrackerClientID.CreateDefaultID();

            Assert.Equal(20, id.PeerID.Length);
            Assert.Equal(4, id.ClientKey.Length);
            Assert.Equal("uTorrent/343(109551416)(40760)", id.HttpUserAgent);
            Assert.Equal("gzip", id.HttpAcceptEncoding);
            Assert.Equal(50, id.NumWant);
            Assert.True(id.Compact);
            Assert.True(id.NoPeerID);
        }

        [Fact]
        public void ConstructorRejectsInvalidHeaderAndUnsupportedVersion()
        {
            Assert.ThrowsAny<Exception>(() => new TrackerClientID(new MemoryStream(Encoding.ASCII.GetBytes("NO"))));
            Assert.Throws<NotSupportedException>(() => new TrackerClientID(new MemoryStream(new byte[] { (byte)'I', (byte)'D', 99 })));
        }
    }
}
