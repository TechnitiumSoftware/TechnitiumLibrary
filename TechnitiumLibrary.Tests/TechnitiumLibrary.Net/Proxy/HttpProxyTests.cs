using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Proxy
{
    [TestClass]
    public class HttpProxyTests
    {
        public TestContext TestContext { get; set; }

        private static Task<(TcpListener listener, int port)> StartListenerAsync()
        {
            TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            return Task.FromResult((listener, port));
        }

        /// <summary>
        /// Reads a complete HTTP request from the given socket until the end-of-headers
        /// marker ("\r\n\r\n") is observed or the socket closes. This is robust against
        /// TCP fragmentation of the CONNECT and Proxy-Authorization lines.
        /// </summary>
        private static async Task<string> ReadHttpRequestAsync(Socket socket, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[2048];
            StringBuilder builder = new StringBuilder();

            while (!cancellationToken.IsCancellationRequested)
            {
                int read = await socket.ReceiveAsync(buffer.AsMemory(0, buffer.Length), SocketFlags.None, cancellationToken);
                if (read <= 0)
                    break;

                builder.Append(Encoding.ASCII.GetString(buffer, 0, read));

                if (builder.ToString().Contains("\r\n\r\n", StringComparison.Ordinal))
                    break;
            }

            return builder.ToString();
        }

        private static Task<int> RespondAsync(Socket socket, string httpResponse, CancellationToken cancellationToken)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(httpResponse);
            return socket.SendAsync(bytes.AsMemory(0, bytes.Length), SocketFlags.None, cancellationToken).AsTask();
        }

        // ------------------------------------------------------------
        // 200 OK
        // ------------------------------------------------------------
        [TestMethod]
        public async Task ConnectAsync_When200_ReturnsConnectedSocket()
        {
            (TcpListener listener, int port) = await StartListenerAsync();

            HttpProxy proxy = new HttpProxy(new IPEndPoint(IPAddress.Loopback, port));
            IPEndPoint destination = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 5555);

            Task<Socket> connectTask = proxy.ConnectAsync(destination, TestContext.CancellationToken);

            using Socket serverSide = await listener.AcceptSocketAsync(TestContext.CancellationToken);
            string request = await ReadHttpRequestAsync(serverSide, TestContext.CancellationToken);

            Console.WriteLine("REQUEST RAW:");
            Console.WriteLine(request);

            Assert.IsTrue(
                request.StartsWith("CONNECT ", StringComparison.Ordinal),
                "Proxy must send a CONNECT request line to the upstream proxy."
            );

            Assert.Contains(
                value: request,
                substring: destination.ToString(),
                message: "CONNECT request must contain 'host:port'."
            );

            await RespondAsync(serverSide, "HTTP/1.0 200 Connection Established\r\n\r\n", TestContext.CancellationToken);

            Socket result = await connectTask;
            Assert.IsNotNull(result, "ConnectAsync must return a non-null Socket when the proxy responds 200.");
            Assert.IsTrue(result.Connected, "Socket must be connected after a 200 OK response from the HTTP proxy.");

            result.Dispose();
            listener.Stop();
        }

        // ------------------------------------------------------------
        // 407 Authentication Required
        // ------------------------------------------------------------
        [TestMethod]
        public async Task ConnectAsync_When407_ThrowsAuthenticationFailed()
        {
            (TcpListener listener, int port) = await StartListenerAsync();
            NetworkCredential creds = new NetworkCredential("alice", "secret");

            HttpProxy proxy = new HttpProxy(new IPEndPoint(IPAddress.Loopback, port), creds);
            IPEndPoint destination = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 8080);

            Task<Socket> connectTask = proxy.ConnectAsync(destination, TestContext.CancellationToken);

            using Socket serverSide = await listener.AcceptSocketAsync(TestContext.CancellationToken);

            string request = await ReadHttpRequestAsync(serverSide, TestContext.CancellationToken);

            string expectedAuth = Convert.ToBase64String(
                Encoding.ASCII.GetBytes("alice:secret")
            );

            Assert.Contains(
                value: request,
                substring: expectedAuth,
                message: "CONNECT request must include Proxy-Authorization header with Base64 credentials."
            );

            await RespondAsync(serverSide, "HTTP/1.0 407 Proxy Authentication Required\r\n\r\n", TestContext.CancellationToken);

            await Assert.ThrowsExactlyAsync<HttpProxyAuthenticationFailedException>(() => connectTask);

            listener.Stop();
        }

        // ------------------------------------------------------------
        // 500 Internal Server Error
        // ------------------------------------------------------------
        [TestMethod]
        public async Task ConnectAsync_When500_ThrowsHttpProxyException()
        {
            (TcpListener listener, int port) = await StartListenerAsync();

            HttpProxy proxy = new HttpProxy(new IPEndPoint(IPAddress.Loopback, port));
            IPEndPoint destination = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 9090);

            Task<Socket> connectTask = proxy.ConnectAsync(destination, TestContext.CancellationToken);

            using Socket serverSide = await listener.AcceptSocketAsync(TestContext.CancellationToken);

            string request = await ReadHttpRequestAsync(serverSide, TestContext.CancellationToken);

            Assert.IsTrue(
                request.StartsWith("CONNECT ", StringComparison.Ordinal),
                "Proxy must issue a CONNECT before receiving a 500 response."
            );

            await RespondAsync(serverSide, "HTTP/1.0 500 Internal Server Error\r\n\r\n", TestContext.CancellationToken);

            await Assert.ThrowsExactlyAsync<HttpProxyException>(() => connectTask);

            listener.Stop();
        }

        // ------------------------------------------------------------
        // Malformed response
        // ------------------------------------------------------------
        [TestMethod]
        public async Task ConnectAsync_WhenMalformedResponse_ThrowsHttpProxyException()
        {
            (TcpListener listener, int port) = await StartListenerAsync();

            HttpProxy proxy = new HttpProxy(new IPEndPoint(IPAddress.Loopback, port));
            IPEndPoint destination = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 8081);

            Task<Socket> connectTask = proxy.ConnectAsync(destination, TestContext.CancellationToken);

            using Socket serverSide = await listener.AcceptSocketAsync(TestContext.CancellationToken);
            _ = await ReadHttpRequestAsync(serverSide, TestContext.CancellationToken);

            await RespondAsync(serverSide, "NOTVALID\r\n\r\n", TestContext.CancellationToken);

            await Assert.ThrowsExactlyAsync<HttpProxyException>(() => connectTask);

            listener.Stop();
        }

        // ------------------------------------------------------------
        // Zero-byte receive
        // ------------------------------------------------------------
        [TestMethod]
        public async Task ConnectAsync_WhenZeroByteResponse_ThrowsHttpProxyException()
        {
            (TcpListener listener, int port) = await StartListenerAsync();

            HttpProxy proxy = new HttpProxy(new IPEndPoint(IPAddress.Loopback, port));
            IPEndPoint destination = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 6060);

            Task<Socket> connectTask = proxy.ConnectAsync(destination, TestContext.CancellationToken);

            using Socket serverSide = await listener.AcceptSocketAsync(TestContext.CancellationToken);
            _ = await ReadHttpRequestAsync(serverSide, TestContext.CancellationToken);

            serverSide.Shutdown(SocketShutdown.Both);
            serverSide.Close();

            await Assert.ThrowsExactlyAsync<HttpProxyException>(() => connectTask);

            listener.Stop();
        }

        // ------------------------------------------------------------
        // Basic auth header correctness
        // ------------------------------------------------------------
        [TestMethod]
        public async Task ConnectAsync_IncludesBasicAuthHeader_WhenCredentialsProvided()
        {
            (TcpListener listener, int port) = await StartListenerAsync();

            NetworkCredential creds = new NetworkCredential("userX", "pa$$word");
            HttpProxy proxy = new HttpProxy(new IPEndPoint(IPAddress.Loopback, port), creds);

            // Use a non-bypassed address
            IPEndPoint destination = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 7007);

            Task<Socket> connectTask = proxy.ConnectAsync(destination, TestContext.CancellationToken);

            using Socket serverSide = await listener.AcceptSocketAsync(TestContext.CancellationToken);
            string request = await ReadHttpRequestAsync(serverSide, TestContext.CancellationToken);

            string expected = Convert.ToBase64String(Encoding.ASCII.GetBytes("userX:pa$$word"));

            Assert.Contains(
                value: request,
                substring: expected,
                message: "CONNECT request must include Proxy-Authorization header with Base64 credentials."
            );

            await RespondAsync(serverSide, "HTTP/1.0 200 OK\r\n\r\n", TestContext.CancellationToken);

            Socket finalSocket = await connectTask;
            Assert.IsTrue(finalSocket.Connected, "Socket must remain connected after a successful authenticated CONNECT.");

            finalSocket.Dispose();
            listener.Stop();
        }
    }
}
