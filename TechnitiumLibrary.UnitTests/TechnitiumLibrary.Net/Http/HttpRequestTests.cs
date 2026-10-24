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
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Http;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Net.Http
{
    [TestClass]
    public class HttpRequestTests
    {
        public TestContext TestContext { get; set; }

        [TestMethod]
        public async Task ReadRequestAsync_ParsesQueryStringCorrectly()
        {
            string raw =
                "GET /search?q=test&flag HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "\r\n";

            using MemoryStream stream = MakeStream(raw);

            HttpRequest req = await HttpRequest.ReadRequestAsync(
                stream,
                cancellationToken: TestContext.CancellationToken);

            Assert.AreEqual("/search", req.RequestPath);
            Assert.AreEqual("test", req.QueryString["q"]);
            Assert.IsNull(req.QueryString["flag"]);
        }

        [TestMethod]
        public async Task ReadRequestAsync_WhenBodyIsTruncated_ReturnsEOFWithoutThrowing()
        {
            string raw =
                "POST /data HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "Content-Length: 10\r\n" +
                "\r\n" +
                "short";

            using MemoryStream stream = MakeStream(raw);

            HttpRequest req = await HttpRequest.ReadRequestAsync(
                stream,
                cancellationToken: TestContext.CancellationToken);

            byte[] buffer = new byte[16];

            int totalRead = 0;
            int r;

            while ((r = await req.InputStream.ReadAsync(
                buffer, 0, buffer.Length, TestContext.CancellationToken)) > 0)
            {
                totalRead += r;
            }

            Assert.AreEqual(
                5,
                totalRead,
                "InputStream must expose only the bytes actually available.");

            Assert.AreEqual(
                0,
                r,
                "InputStream must signal truncation via EOF, not via exception.");
        }

        [TestMethod]
        public async Task ReadRequestAsync_WhenChunkedBodyExceedsMaxContentLength_ThrowsHttpRequestException()
        {
            string raw =
                "POST /x HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "4\r\nWiki\r\n" +
                "0\r\n\r\n";

            using MemoryStream stream = MakeStream(raw);

            HttpRequest req = await HttpRequest.ReadRequestAsync(
                stream,
                maxContentLength: 3,
                cancellationToken: TestContext.CancellationToken);

            await Assert.ThrowsExactlyAsync<HttpRequestException>(async () =>
            {
                _ = await ReadAllAsciiAsync(req.InputStream, TestContext.CancellationToken);
            });
        }

        [TestMethod]
        public async Task ReadRequestAsync_WhenChunkedEndsImmediately_ReturnsEmptyBody()
        {
            string raw =
                "POST /x HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "0\r\n\r\n";

            using MemoryStream stream = MakeStream(raw);

            HttpRequest req = await HttpRequest.ReadRequestAsync(
                stream,
                cancellationToken: TestContext.CancellationToken);

            string body = await ReadAllAsciiAsync(req.InputStream, TestContext.CancellationToken);
            Assert.AreEqual(string.Empty, body);
        }

        [TestMethod]
        public async Task ReadRequestAsync_WhenChunkedTruncated_ThrowsEndOfStreamOnBodyRead()
        {
            string raw =
                "POST /x HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "5\r\nabc";

            using MemoryStream stream = MakeStream(raw);

            HttpRequest req = await HttpRequest.ReadRequestAsync(
                stream,
                cancellationToken: TestContext.CancellationToken);

            await Assert.ThrowsExactlyAsync<EndOfStreamException>(async () =>
            {
                _ = await ReadAllAsciiAsync(req.InputStream, TestContext.CancellationToken);
            });
        }

        [TestMethod]
        public async Task ReadRequestAsync_WhenConnectionClosedBeforeRequest_ReturnsNull()
        {
            using MemoryStream stream = new MemoryStream(Array.Empty<byte>());

            HttpRequest req = await HttpRequest.ReadRequestAsync(
                stream,
                cancellationToken: TestContext.CancellationToken);

            Assert.IsNull(req, "Graceful close before request must return null.");
        }

        [TestMethod]
        public async Task ReadRequestAsync_WhenContentLengthExceedsMax_ThrowsHttpRequestException()
        {
            string raw =
                "POST /data HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "Content-Length: 100\r\n" +
                "\r\n";

            using MemoryStream stream = MakeStream(raw);

            await Assert.ThrowsExactlyAsync<HttpRequestException>(async () =>
            {
                _ = await HttpRequest.ReadRequestAsync(
                    stream,
                    maxContentLength: 10,
                    cancellationToken: TestContext.CancellationToken);
            });
        }

        [TestMethod]
        public async Task ReadRequestAsync_WhenHeaderIsTruncated_ThrowsEndOfStream()
        {
            string raw =
                "GET / HTTP/1.1\r\n" +
                "Host: example.com\r\n"; // missing terminating CRLF

            using MemoryStream stream = MakeStream(raw);

            await Assert.ThrowsExactlyAsync<EndOfStreamException>(async () =>
            {
                _ = await HttpRequest.ReadRequestAsync(
                    stream,
                    cancellationToken: TestContext.CancellationToken);
            });
        }

        [TestMethod]
        public async Task ReadRequestAsync_WhenHeaderLineIsInvalid_ThrowsInvalidData()
        {
            string raw =
                "GET / HTTP/1.1\r\n" +
                "Host example.com\r\n" + // missing colon
                "\r\n";

            using MemoryStream stream = MakeStream(raw);

            await Assert.ThrowsExactlyAsync<InvalidDataException>(async () =>
            {
                _ = await HttpRequest.ReadRequestAsync(
                    stream,
                    cancellationToken: TestContext.CancellationToken);
            });
        }

        [TestMethod]
        public async Task ReadRequestAsync_WhenRequestLineIsInvalid_ThrowsInvalidData()
        {
            string raw =
                "GET /only-two-parts\r\n" +
                "Host: example.com\r\n" +
                "\r\n";

            using MemoryStream stream = MakeStream(raw);

            await Assert.ThrowsExactlyAsync<InvalidDataException>(async () =>
            {
                _ = await HttpRequest.ReadRequestAsync(
                    stream,
                    cancellationToken: TestContext.CancellationToken);
            });
        }

        [TestMethod]
        public async Task ReadRequestAsync_WhenTransferEncodingChunked_ExposesDecodedBody()
        {
            string raw =
                "POST /submit HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "4\r\nWiki\r\n" +
                "5\r\npedia\r\n" +
                "0\r\n\r\n";

            using MemoryStream stream = MakeStream(raw);

            HttpRequest req = await HttpRequest.ReadRequestAsync(
                stream,
                cancellationToken: TestContext.CancellationToken);

            Assert.AreEqual("POST", req.HttpMethod);
            Assert.AreEqual("/submit", req.RequestPath);

            string body = await ReadAllAsciiAsync(req.InputStream, TestContext.CancellationToken);
            Assert.AreEqual("Wikipedia", body);
        }

        [TestMethod]
        public async Task ReadRequestAsync_WhenTransferEncodingUnsupported_ThrowsHttpRequestException()
        {
            string raw =
                "POST /x HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "Transfer-Encoding: gzip\r\n" +
                "\r\n";

            using MemoryStream stream = MakeStream(raw);

            await Assert.ThrowsExactlyAsync<HttpRequestException>(async () =>
            {
                _ = await HttpRequest.ReadRequestAsync(
                    stream,
                    cancellationToken: TestContext.CancellationToken);
            });
        }

        private static MemoryStream MakeStream(string ascii) => new MemoryStream(Encoding.ASCII.GetBytes(ascii));

        private static async Task<string> ReadAllAsciiAsync(Stream s, CancellationToken ct)
        {
            using MemoryStream ms = new MemoryStream();
            await s.CopyToAsync(ms, 8192, ct);
            return Encoding.ASCII.GetString(ms.ToArray());
        }
    }
}