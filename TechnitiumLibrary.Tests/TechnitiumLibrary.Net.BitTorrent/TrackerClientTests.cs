using System.Net;
using TechnitiumLibrary.Net.BitTorrent;
using TechnitiumLibrary.Tests.Simulators.TechnitiumLibrary.Net.BitTorrent;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.BitTorrent
{
    public class TrackerClientTests
    {
        [Theory]
        [InlineData("http://tracker.example/announce")]
        [InlineData("https://tracker.example/announce")]
        [InlineData("udp://tracker.example:6969/announce")]
        public void CreateReturnsClientForSupportedSchemes(string uri)
        {
            using TrackerClient client = TrackerClient.Create(new Uri(uri), CreateInfoHash(), CreateClientId(), 60);

            Assert.Equal(new Uri(uri), client.TrackerUri);
            Assert.Equal(60, client.CustomUpdateInterval);
            Assert.Equal(20, client.InfoHash.Length);
            Assert.NotNull(client.ClientID);
        }

        [Fact]
        public void CreateAddsDefaultPortForUdpTrackerWithoutPort()
        {
            using TrackerClient client = TrackerClient.Create(new Uri("udp://tracker.example/announce"), CreateInfoHash(), CreateClientId());

            Assert.Equal(80, client.TrackerUri.Port);
        }

        [Fact]
        public void CreateRejectsUnsupportedScheme()
        {
            Assert.Throws<TrackerClientException>(() => TrackerClient.Create(new Uri("ftp://tracker.example/announce"), CreateInfoHash(), CreateClientId()));
        }

        [Fact]
        public void ScheduleUpdateNowMakesNextUpdateDue()
        {
            using TestTrackerClient client = new TestTrackerClient(customUpdateInterval: 60);

            client.ScheduleUpdateNow();

            Assert.True(client.NextUpdateIn() <= TimeSpan.Zero);
        }

        [Fact]
        public async Task UpdateAsyncStoresStateAfterSuccess()
        {
            using TestTrackerClient client = new TestTrackerClient();
            IPEndPoint endpoint = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 6881);

            await client.UpdateAsync(TrackerClientEvent.Started, endpoint);

            Assert.Equal(endpoint, client.LastClientEP);
            Assert.Null(client.LastException);
            Assert.Equal(0, client.RetriesDone);
            Assert.False(client.IsUpdating);
            Assert.Equal(TrackerClientEvent.Started, client.LastEvent);
            Assert.Equal(endpoint, client.LastUpdateEndpoint);
        }

        [Fact]
        public async Task UpdateAsyncStoresInnerExceptionAndRetryStateAfterFailure()
        {
            using TestTrackerClient client = new TestTrackerClient();
            IPEndPoint endpoint = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 6881);
            InvalidOperationException inner = new InvalidOperationException("inner");
            client.ExceptionToThrow = new ApplicationException("outer", inner);

            ApplicationException thrown = await Assert.ThrowsAsync<ApplicationException>(() => client.UpdateAsync(TrackerClientEvent.Completed, endpoint));

            Assert.Same(inner, client.LastException);
            Assert.Same(inner, thrown.InnerException);
            Assert.Equal(1, client.RetriesDone);
            Assert.Equal(client.MinimumInterval, client.Interval);
            Assert.False(client.IsUpdating);
            Assert.Equal(endpoint, client.LastClientEP);
        }

        [Fact]
        public void EqualsComparesTrackerUriAndInfoHash()
        {
            byte[] infoHash = CreateInfoHash();
            using TestTrackerClient client = new TestTrackerClient(infoHash: infoHash);
            using TestTrackerClient same = new TestTrackerClient(infoHash: infoHash.ToArray());
            using TestTrackerClient differentUri = new TestTrackerClient(trackerUri: new Uri("http://other.example/announce"), infoHash: infoHash.ToArray());
            byte[] differentHash = infoHash.ToArray();
            differentHash[19] = 255;
            using TestTrackerClient differentInfoHash = new TestTrackerClient(infoHash: differentHash);

            Assert.True(client.Equals(same));
            Assert.False(client.Equals(null));
            Assert.False(client.Equals("tracker"));
            Assert.False(client.Equals(differentUri));
            Assert.False(client.Equals(differentInfoHash));
            Assert.Equal(client.GetHashCode(), client.GetHashCode());
        }

        [Fact]
        public void PublicPropertiesExposeMutableSettingsAndTrackerState()
        {
            using TestTrackerClient client = new TestTrackerClient();

            client.CustomUpdateInterval = 45;
            client.Peers.Add(new IPEndPoint(IPAddress.Parse("192.0.2.2"), 6881));

            Assert.Equal(45, client.CustomUpdateInterval);
            Assert.Null(client.Proxy);
            Assert.Single(client.Peers);
            Assert.Equal(0, client.Leachers);
            Assert.Equal(0, client.Seeders);
        }

        private static byte[] CreateInfoHash()
        {
            return Enumerable.Range(0, 20).Select(Convert.ToByte).ToArray();
        }

        private static TrackerClientID CreateClientId()
        {
            return new TrackerClientID(Enumerable.Range(20, 20).Select(Convert.ToByte).ToArray(), [1, 2, 3, 4], "agent", "gzip", 50, true, true);
        }
    }
}
