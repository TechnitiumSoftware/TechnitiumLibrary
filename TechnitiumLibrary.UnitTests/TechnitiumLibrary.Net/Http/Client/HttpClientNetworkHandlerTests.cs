/*
Technitium Library
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Http.Client;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Net.Http.Client
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

            using HttpRequestMessage request = new HttpRequestMessage(
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

            using HttpRequestMessage request = new HttpRequestMessage(
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

            using HttpRequestMessage request = new HttpRequestMessage(
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