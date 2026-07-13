using System.Net;
using TechnitiumLibrary.Net.BitTorrent;

namespace TechnitiumLibrary.Tests.Simulators.TechnitiumLibrary.Net.BitTorrent
{
    internal sealed class TestTrackerClient : TrackerClient
    {
        public TestTrackerClient(Uri? trackerUri = null, byte[]? infoHash = null, int customUpdateInterval = 0)
            : base(trackerUri ?? new Uri("http://tracker.example/announce"), infoHash ?? CreateInfoHash(), CreateClientId(), customUpdateInterval)
        { }

        public Exception? ExceptionToThrow { get; set; }

        public TrackerClientEvent LastEvent { get; private set; }

        public IPEndPoint? LastUpdateEndpoint { get; private set; }

        protected override Task UpdateTrackerAsync(TrackerClientEvent @event, IPEndPoint clientEP)
        {
            LastEvent = @event;
            LastUpdateEndpoint = clientEP;

            if (ExceptionToThrow is not null)
                throw ExceptionToThrow;

            return Task.CompletedTask;
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
