using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public class HttpProxyServerTests
    {
        public TestContext TestContext { get; set; }

        #region helpers

        /// <summary>
        /// Connects a TcpClient to the proxy server's listening endpoint.
        /// </summary>
        private async Task<TcpClient> ConnectClientAsync(HttpProxyServer server)
        {
            TcpClient client = new TcpClient();
            IPEndPoint ep = server.LocalEndPoint;

            Assert.IsNotNull(ep, "LocalEndPoint must be initialized before accepting connections.");

            await client.ConnectAsync(
                ep.Address.ToString(),
                ep.Port,
                TestContext.CancellationToken);

            return client;
        }

        /// <summary>
        /// Reads a single response frame from the server into a string.
        /// Used for small HTTP status responses.
        /// </summary>
        private static async Task<string> ReadResponseAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[4096];
            int bytesRead = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);

            return Encoding.ASCII.GetString(buffer, 0, bytesRead);
        }

        /// <summary>
        /// Reads everything the server has written to the given socket until it closes
        /// or no more data arrives. Intended for capturing forwarded HTTP requests.
        /// </summary>
        private static async Task<string> ReadFromSocketAsync(Socket socket, CancellationToken cancellationToken)
        {
            await using MemoryStream ms = new MemoryStream();
            using NetworkStream networkStream = new NetworkStream(socket, ownsSocket: false);

            byte[] buffer = new byte[4096];

            while (!cancellationToken.IsCancellationRequested)
            {
                if (!networkStream.CanRead)
                    break;

                if (!socket.Connected)
                    break;

                int read;
                try
                {
                    read = await networkStream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
                }
                catch (IOException)
                {
                    break;
                }

                if (read <= 0)
                    break;

                await ms.WriteAsync(buffer.AsMemory(0, read), cancellationToken);

                // For our tests, a single HTTP request is enough; break if end-of-headers reached.
                if (ms.Length > 4)
                {
                    byte[] data = ms.ToArray();
                    string text = Encoding.ASCII.GetString(data);
                    if (text.Contains("\r\n\r\n", StringComparison.Ordinal))
                        break;
                }
            }

            return Encoding.ASCII.GetString(ms.ToArray());
        }

        #endregion

        #region tests

        [TestMethod]
        public void Constructor_UsesLoopbackAndEphemeralPort()
        {
            using HttpProxyServer server = new HttpProxyServer();

            IPEndPoint ep = server.LocalEndPoint;

            Assert.IsNotNull(ep, "LocalEndPoint must be non-null after construction.");
            Assert.IsTrue(IPAddress.IsLoopback(ep.Address), "HttpProxyServer must bind only to loopback by default to avoid exposing an open proxy.");
            Assert.IsGreaterThan(0, ep.Port, "HttpProxyServer must bind to an ephemeral port when 0 is specified.");
        }

        [TestMethod]
        public async Task ConnectMethod_ValidConnectRequest_RespondsWith200AndUsesConnectionManager()
        {
            using RecordingConnectionManager connectionManager = new RecordingConnectionManager();
            using HttpProxyServer server = new HttpProxyServer(connectionManager);

            using TcpClient client = await ConnectClientAsync(server);
            using NetworkStream clientStream = client.GetStream();

            const string host = "198.51.100.10";
            const int port = 443;

            string request =
                $"CONNECT {host}:{port} HTTP/1.1\r\n" +
                $"Host: {host}:{port}\r\n" +
                "\r\n";

            byte[] requestBytes = Encoding.ASCII.GetBytes(request);
            await clientStream.WriteAsync(requestBytes.AsMemory(0, requestBytes.Length), TestContext.CancellationToken);
            await clientStream.FlushAsync(TestContext.CancellationToken);

            string response = await ReadResponseAsync(clientStream, TestContext.CancellationToken);

            StringAssert.StartsWith(
                response,
                "HTTP/1.1 200 OK",
                "CONNECT must be acknowledged with 200 OK when the connection manager succeeds.");

            Assert.HasCount(
                1,
                connectionManager.ConnectedEndpoints,
                "Proxy server must delegate exactly one CONNECT to the connection manager.");

            Assert.IsInstanceOfType(
                connectionManager.ConnectedEndpoints[0],
                typeof(IPEndPoint),
                "CONNECT target must be resolved to an IPEndPoint.");

            IPEndPoint ep = (IPEndPoint)connectionManager.ConnectedEndpoints[0];

            Assert.AreEqual(
                IPAddress.Parse(host),
                ep.Address,
                "CONNECT must target the exact IP address parsed from the request path.");

            Assert.AreEqual(
                port,
                ep.Port,
                "CONNECT must target the exact TCP port parsed from the request path.");
        }

        [TestMethod]
        public async Task ConnectMethod_ConnectWithoutPort_Returns500InternalServerError()
        {
            using RecordingConnectionManager connectionManager = new RecordingConnectionManager();
            using HttpProxyServer server = new HttpProxyServer(connectionManager);

            using TcpClient client = await ConnectClientAsync(server);
            using NetworkStream clientStream = client.GetStream();

            const string host = "example.com";

            string request =
                $"CONNECT {host} HTTP/1.1\r\n" +
                $"Host: {host}\r\n" +
                "\r\n";

            byte[] requestBytes = Encoding.ASCII.GetBytes(request);
            await clientStream.WriteAsync(requestBytes.AsMemory(0, requestBytes.Length), TestContext.CancellationToken);
            await clientStream.FlushAsync(TestContext.CancellationToken);

            string response = await ReadResponseAsync(clientStream, TestContext.CancellationToken);

            StringAssert.StartsWith(
                response,
                "HTTP/1.1 500",
                "CONNECT without port is invalid per server contract and must return 500.");

            Assert.IsEmpty(
                connectionManager.ConnectedEndpoints,
                "Invalid CONNECT target must not trigger downstream connection attempts.");
        }

        [TestMethod]
        public async Task ConnectMethod_InvalidTarget_Returns500InternalServerError()
        {
            using RecordingConnectionManager connectionManager = new RecordingConnectionManager();
            using HttpProxyServer server = new HttpProxyServer(connectionManager);

            using TcpClient client = await ConnectClientAsync(server);
            using NetworkStream clientStream = client.GetStream();

            // Request path that EndPointExtensions.TryParse cannot interpret as an endpoint.
            string request =
                "CONNECT /not-an-endpoint HTTP/1.1\r\n" +
                "Host: localhost\r\n" +
                "\r\n";

            byte[] requestBytes = Encoding.ASCII.GetBytes(request);
            await clientStream.WriteAsync(requestBytes.AsMemory(0, requestBytes.Length), TestContext.CancellationToken);
            await clientStream.FlushAsync(TestContext.CancellationToken);

            string response = await ReadResponseAsync(clientStream, TestContext.CancellationToken);

            StringAssert.StartsWith(
                response,
                "HTTP/1.1 500 500 Internal Server Error",
                "Invalid CONNECT request must be surfaced as 500 Internal Server Error according to server behavior.");


            Assert.IsEmpty(
                connectionManager.ConnectedEndpoints,
                "Invalid CONNECT target must not trigger any downstream connection attempts.");
        }

        [TestMethod]
        public async Task Forwarding_NonConnectAbsoluteUri_RewritesPathAndStripsProxyHeaders()
        {
            using CapturingConnectionManager connectionManager = new CapturingConnectionManager();
            using HttpProxyServer server = new HttpProxyServer(connectionManager);

            using TcpClient client = await ConnectClientAsync(server);
            using NetworkStream clientStream = client.GetStream();

            const string targetUri = "http://example.com/resource/path?q=1";

            string request =
                $"GET {targetUri} HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n" +
                "Proxy-Connection: keep-alive\r\n" +
                "\r\n";

            byte[] requestBytes = Encoding.ASCII.GetBytes(request);
            await clientStream.WriteAsync(requestBytes.AsMemory(0, requestBytes.Length), TestContext.CancellationToken);
            await clientStream.FlushAsync(TestContext.CancellationToken);

            // Wait until the proxy has established a remote connection.
            Assert.IsTrue(
                connectionManager.WaitForAcceptedSocket(TimeSpan.FromSeconds(5)),
                "Proxy server must establish a remote connection for non-CONNECT requests with absolute URI.");

            Socket remoteSocket = connectionManager.AcceptedSockets[0];

            string forwardedRequest = await ReadFromSocketAsync(remoteSocket, TestContext.CancellationToken);

            StringAssert.StartsWith(
                forwardedRequest,
                "GET /resource/path?q=1 HTTP/1.1",
                "Proxy must rewrite the request line to use the origin-form path and query, not the absolute URI.");

            Assert.IsFalse(
                forwardedRequest.Contains("Proxy-Authorization:", StringComparison.OrdinalIgnoreCase),
                "Proxy-Authorization header must be stripped before forwarding to the origin server to prevent credential leakage.");

            Assert.IsFalse(
                forwardedRequest.Contains("Proxy-Connection:", StringComparison.OrdinalIgnoreCase),
                "Proxy-specific connection headers must be stripped before forwarding to the origin server.");
        }

        [TestMethod]
        public void Dispose_MultipleCalls_AreIdempotentAndCloseListener()
        {
            HttpProxyServer server = new HttpProxyServer();

            IPEndPoint ep = server.LocalEndPoint;

            Assert.IsNotNull(ep, "LocalEndPoint must be available before disposal.");

            // First dispose should close underlying listener and all sessions.
            server.Dispose();

            // Second dispose must be a no-op (no ObjectDisposedException, no side-effects).
            server.Dispose();
        }

        #endregion

        #region fakes

        /// <summary>
        /// Minimal connection manager that records the endpoints it is asked to connect to,
        /// and returns a connected loopback socket for each request.
        /// Suitable for CONNECT tests that only care about the handshake and not data relay.
        /// </summary>
        private sealed class RecordingConnectionManager : IProxyServerConnectionManager, IDisposable
        {
            private readonly List<Socket> _allocatedSockets = new();

            public IList<EndPoint> ConnectedEndpoints { get; } = new List<EndPoint>();

            public async Task<Socket> ConnectAsync(EndPoint remoteEP, CancellationToken cancellationToken = default)
            {
                // Record the requested endpoint without performing any external network calls.
                ConnectedEndpoints.Add(remoteEP);

                // Create a loopback-connected socket pair so that the proxy has
                // a valid, connected socket to work with.
                TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();

                EndPoint? epObj = listener.Server.LocalEndPoint;
                Assert.IsNotNull(epObj, "Listener.LocalEndPoint must not be null after Start().");
                IPEndPoint listenerEp = (IPEndPoint)epObj;

                Socket clientSocket = new Socket(listenerEp.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                await clientSocket.ConnectAsync(listenerEp, cancellationToken);
                Socket serverSocket = await listener.AcceptSocketAsync(cancellationToken);

                listener.Stop();

                // We only return the client side to the proxy; the server side is discarded.
                serverSocket.Dispose();

                clientSocket.NoDelay = true;
                _allocatedSockets.Add(clientSocket);

                return clientSocket;
            }

            public Task<IProxyServerBindHandler> GetBindHandlerAsync(AddressFamily family)
            {
                throw new NotSupportedException("Bind is not required for HttpProxyServer unit tests.");
            }

            public Task<IProxyServerUdpAssociateHandler> GetUdpAssociateHandlerAsync(EndPoint localEP)
            {
                throw new NotSupportedException("UDP associate is not required for HttpProxyServer unit tests.");
            }

            public void Dispose()
            {
                foreach (Socket s in _allocatedSockets)
                {
                    try
                    {
                        s.Dispose();
                    }
                    catch
                    {
                        // Ignore cleanup errors in test fake.
                    }
                }

                _allocatedSockets.Clear();
            }
        }

        /// <summary>
        /// Connection manager that exposes the server-side sockets so tests can
        /// inspect the HTTP request bytes forwarded by the proxy.
        /// </summary>
        private sealed class CapturingConnectionManager : IProxyServerConnectionManager, IDisposable
        {
            private readonly List<TcpListener> _listeners = new();
            private readonly List<Socket> _clientSockets = new();

            private readonly List<Socket> _acceptedSockets = new();
            private readonly List<EndPoint> _endpoints = new();

            private readonly AutoResetEvent _hasAccepted = new(false);

            public IList<Socket> AcceptedSockets => _acceptedSockets;
            public IList<EndPoint> ConnectedEndpoints => _endpoints;

            public async Task<Socket> ConnectAsync(EndPoint remoteEP, CancellationToken cancellationToken = default)
            {
                _endpoints.Add(remoteEP);

                TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();
                _listeners.Add(listener);

                EndPoint? epObj = listener.Server.LocalEndPoint;
                Assert.IsNotNull(epObj, "Listener.LocalEndPoint must not be null after Start().");
                IPEndPoint listenerEp = (IPEndPoint)epObj;

                Socket clientSocket = new Socket(listenerEp.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                _clientSockets.Add(clientSocket);

                await clientSocket.ConnectAsync(listenerEp, cancellationToken);
                Socket serverSocket = await listener.AcceptSocketAsync(cancellationToken);

                _acceptedSockets.Add(serverSocket);
                _hasAccepted.Set();

                clientSocket.NoDelay = true;

                return clientSocket;
            }

            public Task<IProxyServerBindHandler> GetBindHandlerAsync(AddressFamily family)
            {
                throw new NotSupportedException("Bind is not required for HttpProxyServer forwarding tests.");
            }

            public Task<IProxyServerUdpAssociateHandler> GetUdpAssociateHandlerAsync(EndPoint localEP)
            {
                throw new NotSupportedException("UDP associate is not required for HttpProxyServer forwarding tests.");
            }

            public bool WaitForAcceptedSocket(TimeSpan timeout)
            {
                return _hasAccepted.WaitOne(timeout);
            }

            public void Dispose()
            {
                foreach (Socket s in _clientSockets)
                {
                    try
                    {
                        s.Dispose();
                    }
                    catch
                    {
                        // Ignore cleanup errors in test fake.
                    }
                }

                foreach (Socket s in _acceptedSockets)
                {
                    try
                    {
                        s.Dispose();
                    }
                    catch
                    {
                        // Ignore cleanup errors in test fake.
                    }
                }

                foreach (TcpListener l in _listeners)
                {
                    try
                    {
                        l.Stop();
                    }
                    catch
                    {
                        // Ignore cleanup errors in test fake.
                    }
                }

                _clientSockets.Clear();
                _acceptedSockets.Clear();
                _listeners.Clear();
            }
        }

        #endregion
    }
}
