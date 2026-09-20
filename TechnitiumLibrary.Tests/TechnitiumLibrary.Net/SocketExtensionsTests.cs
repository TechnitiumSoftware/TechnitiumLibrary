using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net
{
    [TestClass]
    public sealed class SocketExtensionsTests
    {
        [TestMethod]
        public void GetEndPointAnyFor_ShouldReturnV4Any()
        {
            IPEndPoint ep = InvokeInternal(AddressFamily.InterNetwork);
            Assert.AreEqual(IPAddress.Any, ep.Address);
            Assert.AreEqual(0, ep.Port);
        }

        [TestMethod]
        public void GetEndPointAnyFor_ShouldReturnV6Any()
        {
            IPEndPoint ep = InvokeInternal(AddressFamily.InterNetworkV6);
            Assert.AreEqual(IPAddress.IPv6Any, ep.Address);
            Assert.AreEqual(0, ep.Port);
        }

        [TestMethod]
        public void GetEndPointAnyFor_ShouldRejectUnsupported()
        {
            Assert.ThrowsExactly<NotSupportedException>(() =>
                InvokeInternal(AddressFamily.AppleTalk),
                "Unsupported AF must surface NotSupportedException.");
        }

        [TestMethod]
        public void Connect_ShouldFail_OnTimeoutHost()
        {
            using Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            Assert.ThrowsExactly<SocketException>(() =>
                s.Connect("192.0.2.1", 6555, timeout: 1),
                "Unreachable host must timeout immediately.");
        }

        [TestMethod]
        public void Connect_EndPoint_ShouldFail_OnTimeout()
        {
            using Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            IPEndPoint unreachable = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 65000);

            Assert.ThrowsExactly<SocketException>(() =>
                s.Connect(unreachable, timeout: 1),
                "Timeout on explicit endpoint must raise.");
        }

        [TestMethod]
        public async Task UdpQueryAsync_ShouldTimeout_WhenReceivingNothing()
        {
            using Socket server = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            server.Bind(new IPEndPoint(IPAddress.Loopback, 0));

            using Socket client = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            byte[] req = new byte[] { 1, 2, 3 };
            byte[] resp = new byte[512];

            IPEndPoint? remote = (IPEndPoint?)server.LocalEndPoint;

            await Assert.ThrowsExactlyAsync<SocketException>(async () =>
            {
                await client.UdpQueryAsync(
                    request: req,
                    response: resp,
                    remoteEP: remote,
                    timeout: 50,
                    retries: 1, cancellationToken: TestContext.CancellationToken);
            });
        }

        [TestMethod]
        public async Task CopyToAsync_ShouldThrowSocketException_WhenDestinationClosesMidSend()
        {
            using TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();

            using Socket client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            await client.ConnectAsync((IPEndPoint)listener.LocalEndpoint);

            using Socket server = await listener.AcceptSocketAsync();

            Task copyTask = server.CopyToAsync(client);

            // Ensure data reaches read phase
            await server.SendAsync(new byte[] { 1, 2, 3, 4 }, SocketFlags.None);

            // Give the receiving side time to begin processing
            await Task.Delay(50);

            // Force destination break AFTER sending has begun
            client.Close();

            SocketException ex = await Assert.ThrowsExactlyAsync<SocketException>(
                async () => await copyTask,
                "Closing destination during active send must propagate socket failure.");

            Assert.AreNotEqual(SocketError.Success, ex.SocketErrorCode);
        }

        private static IPEndPoint InvokeInternal(AddressFamily af)
        {
            MethodInfo method = typeof(SocketExtensions).GetMethod(
                "GetEndPointAnyFor", BindingFlags.NonPublic | BindingFlags.Static) ?? throw new MissingMethodException("SocketExtensions.GetEndPointAnyFor was not found.");
            try
            {
                return (IPEndPoint)method.Invoke(null, new object[] { af })!;
            }
            catch (TargetInvocationException tie) when (tie.InnerException is not null)
            {
                // Preserve original intention
                throw tie.InnerException;
            }
        }

        public TestContext TestContext { get; set; }
    }
}
