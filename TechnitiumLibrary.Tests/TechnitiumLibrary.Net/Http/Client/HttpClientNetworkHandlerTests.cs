using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Http.Client;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Http.Client
{
    [TestClass]
    public class HttpClientNetworkHandlerTests
    {
        [TestMethod]
        public void Constructor_InitializesSocketsHttpHandlerCorrectly()
        {
            using HttpClientNetworkHandler handler = new HttpClientNetworkHandler();

            Assert.IsNotNull(
                handler.InnerHandler,
                "InnerHandler must be initialized.");

            Assert.IsTrue(
                handler.InnerHandler.EnableMultipleHttp2Connections,
                "Handler must enable multiple HTTP/2 connections.");
        }

        [TestMethod]
        public void NetworkType_Property_RoundTrips()
        {
            using HttpClientNetworkHandler handler = new HttpClientNetworkHandler();

            handler.NetworkType = HttpClientNetworkType.IPv6Only;

            Assert.AreEqual(
                HttpClientNetworkType.IPv6Only,
                handler.NetworkType);
        }

        [TestMethod]
        public void Send_WhenHttpVersion30_IsDowngradedToHttp2()
        {
            using HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
            using HttpMessageInvoker invoker = new HttpMessageInvoker(handler);

            HttpRequestMessage request = new HttpRequestMessage(
                HttpMethod.Get,
                "http://example.com")
            {
                Version = HttpVersion.Version30
            };

            Assert.AreEqual(
                HttpVersion.Version30,
                request.Version,
                "Precondition: request must start as HTTP/3.");

            Assert.ThrowsExactly<NotSupportedException>(() =>
            {
                invoker.Send(request, CancellationToken.None);
            });

            Assert.AreEqual(
                HttpVersion.Version20,
                request.Version,
                "Handler must downgrade HTTP/3 to HTTP/2 even when the send fails.");
        }

        [TestMethod]
        public void Send_WhenSocketsHttpHandlerProxyIsUsed_ThrowsHttpRequestException()
        {
            using HttpClientNetworkHandler handler = new HttpClientNetworkHandler();

            handler.InnerHandler.UseProxy = true;
            handler.InnerHandler.Proxy = new WebProxy("http://127.0.0.1:8080");

            using HttpMessageInvoker invoker = new HttpMessageInvoker(handler);

            HttpRequestMessage request = new HttpRequestMessage(
                HttpMethod.Get,
                "http://example.com");

            Assert.ThrowsExactly<HttpRequestException>(() =>
            {
                invoker.Send(request, CancellationToken.None);
            });
        }

        [TestMethod]
        public async Task SendAsync_WhenHttpVersion30_IsDowngradedToHttp2()
        {
            using HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
            using HttpMessageInvoker invoker = new HttpMessageInvoker(handler);

            HttpRequestMessage request = new HttpRequestMessage(
                HttpMethod.Get,
                "http://example.com")
            {
                Version = HttpVersion.Version30
            };

            // We do NOT assert on success or failure of the send itself.
            // The contract we enforce here is the version downgrade.
            try
            {
                await invoker.SendAsync(request, CancellationToken.None);
            }
            catch
            {
                // Outcome of the send is environment-dependent and not part of the contract.
            }

            Assert.AreEqual(
                HttpVersion.Version20,
                request.Version,
                "Async path must downgrade HTTP/3 to HTTP/2.");
        }
    }
}