using System.Net;
using System.Net.Sockets;
using System.Reflection;
using TechnitiumLibrary.Net.Tor;
using TechnitiumLibrary.Tests.Simulators.TechnitiumLibrary.Net.Tor;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Tor
{
    public class TorControllerTests
    {
        [Fact]
        public void ConstructorRequiresExistingTorExecutablePath()
        {
            Assert.Throws<ArgumentException>(() => new TorController(Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".exe")));

            using TorController controller = CreateController();

            Assert.Equal(typeof(TorController).Assembly.Location, controller.TorExecutableFile);
            Assert.False(controller.IsRunning);
        }

        [Fact]
        public void ConfigurationPropertiesCanBeSetBeforeStart()
        {
            using TorController controller = CreateController();
            NetworkCredential credential = new NetworkCredential("user", "pass");
            IPEndPoint socksEndpoint = new IPEndPoint(IPAddress.Loopback, 19050);

            controller.ControlPort = 19051;
            controller.Socks5EndPoint = socksEndpoint;
            controller.ProxyType = TorProxyType.Socks5;
            controller.ProxyHost = "proxy.example.test";
            controller.ProxyPort = 1080;
            controller.ProxyCredential = credential;

            Assert.Equal(19051, controller.ControlPort);
            Assert.Same(socksEndpoint, controller.Socks5EndPoint);
            Assert.Equal(TorProxyType.Socks5, controller.ProxyType);
            Assert.Equal("proxy.example.test", controller.ProxyHost);
            Assert.Equal(1080, controller.ProxyPort);
            Assert.Same(credential, controller.ProxyCredential);
        }

        [Fact]
        public async Task SignalCommandsWriteTorControlCommandsAndAcceptSuccessResponses()
        {
            using TorControlTestServer server = CreateStartedServer();
            server.Enqueue("250 OK");
            server.Enqueue("250 OK");
            server.Enqueue("250 OK");
            server.Enqueue("250 OK");
            using TorController controller = await CreateConnectedControllerAsync(server);

            controller.SwitchCircuit();
            controller.ClearDnsCache();
            controller.ImmediateShutdown();
            controller.Shutdown();

            Assert.Equal(
            [
                "SIGNAL NEWNYM",
                "SIGNAL CLEARDNSCACHE",
                "SIGNAL HALT",
                "SIGNAL SHUTDOWN"
            ], server.Commands);
        }

        [Fact]
        public async Task SignalCommandsThrowWhenControlServerReturnsError()
        {
            using TorControlTestServer server = CreateStartedServer();
            server.Enqueue("551 bad signal");
            using TorController controller = await CreateConnectedControllerAsync(server);

            TorControllerException exception = Assert.Throws<TorControllerException>(() => controller.SwitchCircuit());

            Assert.Equal("Server returned: 551 bad signal", exception.Message);
            Assert.Equal("SIGNAL NEWNYM", Assert.Single(server.Commands));
        }

        [Fact]
        public async Task CreateHiddenServiceParsesMultiLineResponse()
        {
            using TorControlTestServer server = CreateStartedServer();
            server.Enqueue(
                "250-ServiceID=examplehiddenservice",
                "250-PrivateKey=ED25519-V3:private-key",
                "250-ClientAuth=alice:cookie",
                "250 OK");
            using TorController controller = await CreateConnectedControllerAsync(server);

            TorHiddenServiceInfo info = controller.CreateHiddenService(443, new IPEndPoint(IPAddress.Loopback, 8443), "alice", "cookie");

            Assert.Equal("examplehiddenservice", info.ServiceId);
            Assert.Equal("ED25519-V3:private-key", info.PrivateKey);
            Assert.Equal("alice", info.ClientBasicAuthenticationUsername);
            Assert.Equal("cookie", info.ClientBasicAuthenticationCookie);
            Assert.Equal("ADD_ONION NEW:BEST Flags=BasicAuth Port=443,127.0.0.1:8443 ClientAuth=alice:cookie", Assert.Single(server.Commands));
        }

        [Fact]
        public async Task CreateHiddenServiceWithPrivateKeyWritesExpectedCommand()
        {
            using TorControlTestServer server = CreateStartedServer();
            server.Enqueue("250-ServiceID=restoredservice", "250 OK");
            using TorController controller = await CreateConnectedControllerAsync(server);

            TorHiddenServiceInfo info = controller.CreateHiddenService(80, "ED25519-V3:private-key", new IPEndPoint(IPAddress.Loopback, 8080), "bob");

            Assert.Equal("restoredservice", info.ServiceId);
            Assert.Equal("ADD_ONION ED25519-V3:private-key Flags=BasicAuth Port=80,127.0.0.1:8080 ClientAuth=bob:", Assert.Single(server.Commands));
        }

        [Fact]
        public async Task HiddenServiceParsingThrowsOnErrorResponse()
        {
            using TorControlTestServer server = CreateStartedServer();
            server.Enqueue("551 onion failed");
            using TorController controller = await CreateConnectedControllerAsync(server);

            TorControllerException exception = Assert.Throws<TorControllerException>(() => controller.CreateHiddenService(80));

            Assert.Equal("Server returned: 551 onion failed", exception.Message);
        }

        [Fact]
        public async Task DeleteHiddenServiceWritesCommandAndHandlesErrors()
        {
            using TorControlTestServer server = CreateStartedServer();
            server.Enqueue("250 OK");
            server.Enqueue("552 unknown service");
            using TorController controller = await CreateConnectedControllerAsync(server);

            controller.DeleteHiddenService("serviceid");
            TorControllerException exception = Assert.Throws<TorControllerException>(() => controller.DeleteHiddenService("missing"));

            Assert.Equal("Server returned: 552 unknown service", exception.Message);
            Assert.Equal(["DEL_ONION serviceid", "DEL_ONION missing"], server.Commands);
        }

        private static TorControlTestServer CreateStartedServer()
        {
            TorControlTestServer server = new TorControlTestServer();
            server.Start();
            return server;
        }

        private static TorController CreateController()
        {
            return new TorController(typeof(TorController).Assembly.Location);
        }

        private static async Task<TorController> CreateConnectedControllerAsync(TorControlTestServer server)
        {
            TorController controller = CreateController();
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(IPAddress.Loopback, server.Port);
            NetworkStream stream = new NetworkStream(socket, ownsSocket: true);
            StreamReader reader = new StreamReader(stream);
            StreamWriter writer = new StreamWriter(stream) { AutoFlush = true };

            SetField(controller, "_socket", socket);
            SetField(controller, "_sR", reader);
            SetField(controller, "_sW", writer);

            return controller;
        }

        private static void SetField(TorController controller, string fieldName, object value)
        {
            typeof(TorController).GetField(fieldName, BindingFlags.NonPublic | BindingFlags.Instance)!.SetValue(controller, value);
        }

    }
}
