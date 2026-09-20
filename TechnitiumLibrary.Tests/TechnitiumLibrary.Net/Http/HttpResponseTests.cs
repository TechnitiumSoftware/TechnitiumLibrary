using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Http;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Http
{
    [TestClass]
    public class HttpResponseTests
    {
        public TestContext TestContext { get; set; }

        [TestMethod]
        public async Task ReadResponseAsync_WhenChunkedTruncated_ThrowsEndOfStreamOnBodyRead()
        {
            string raw =
                "HTTP/1.1 200 OK\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "5\r\nabc";

            using MemoryStream stream = MakeStream(raw);

            HttpResponse resp = await HttpResponse.ReadResponseAsync(
                stream,
                TestContext.CancellationToken);

            await Assert.ThrowsExactlyAsync<EndOfStreamException>(async () =>
            {
                _ = await ReadAllAsciiAsync(resp.OutputStream, TestContext.CancellationToken);
            });
        }

        [TestMethod]
        public async Task ReadResponseAsync_WhenHeaderLineIsInvalid_ThrowsInvalidData()
        {
            string raw =
                "HTTP/1.1 200 OK\r\n" +
                "Content-Length 10\r\n" + // missing colon
                "\r\n";

            using MemoryStream stream = MakeStream(raw);

            await Assert.ThrowsExactlyAsync<InvalidDataException>(async () =>
            {
                _ = await HttpResponse.ReadResponseAsync(
                    stream,
                    TestContext.CancellationToken);
            });
        }

        [TestMethod]
        public async Task ReadResponseAsync_WhenHeadersAreTruncated_ThrowsEndOfStream()
        {
            string raw =
                "HTTP/1.1 200 OK\r\n" +
                "Content-Length: 0\r\n"; // missing terminating CRLF

            using MemoryStream stream = MakeStream(raw);

            await Assert.ThrowsExactlyAsync<EndOfStreamException>(async () =>
            {
                _ = await HttpResponse.ReadResponseAsync(
                    stream,
                    TestContext.CancellationToken);
            });
        }

        [TestMethod]
        public async Task ReadResponseAsync_WhenStatusCodeIsNonNumeric_ThrowsFormatException()
        {
            string raw =
                "HTTP/1.1 OK OK\r\n" +
                "Content-Length: 0\r\n" +
                "\r\n";

            using MemoryStream stream = MakeStream(raw);

            await Assert.ThrowsExactlyAsync<FormatException>(async () =>
            {
                _ = await HttpResponse.ReadResponseAsync(
                    stream,
                    TestContext.CancellationToken);
            });
        }

        [TestMethod]
        public async Task ReadResponseAsync_WhenStatusLineIsInvalid_ThrowsInvalidData()
        {
            string raw =
                "HTTP/1.1 200\r\n" +   // missing reason phrase
                "Content-Length: 0\r\n" +
                "\r\n";

            using MemoryStream stream = MakeStream(raw);

            await Assert.ThrowsExactlyAsync<InvalidDataException>(async () =>
            {
                _ = await HttpResponse.ReadResponseAsync(
                    stream,
                    TestContext.CancellationToken);
            });
        }

        [TestMethod]
        public async Task ReadResponseAsync_WhenTransferEncodingChunked_ExposesDecodedBody()
        {
            string raw =
                "HTTP/1.1 200 OK\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "3\r\nfoo\r\n" +
                "3\r\nbar\r\n" +
                "0\r\n\r\n";

            using MemoryStream stream = MakeStream(raw);

            HttpResponse resp = await HttpResponse.ReadResponseAsync(
                stream,
                TestContext.CancellationToken);

            Assert.AreEqual("HTTP/1.1", resp.Protocol);
            Assert.AreEqual(200, resp.StatusCode);

            string body = await ReadAllAsciiAsync(resp.OutputStream, TestContext.CancellationToken);
            Assert.AreEqual("foobar", body);
        }

        [TestMethod]
        public async Task ReadResponseAsync_WhenTransferEncodingUnsupported_ThrowsHttpRequestException()
        {
            string raw =
                "HTTP/1.1 200 OK\r\n" +
                "Transfer-Encoding: br\r\n" +
                "\r\n";

            using MemoryStream stream = MakeStream(raw);

            await Assert.ThrowsExactlyAsync<HttpRequestException>(async () =>
            {
                _ = await HttpResponse.ReadResponseAsync(
                    stream,
                    TestContext.CancellationToken);
            });
        }

        [TestMethod]
        public async Task ReadResponseAsync_WithContentLength_ExposesExactlyContentLengthBytesInTotal()
        {
            string raw =
                "HTTP/1.1 200 OK\r\n" +
                "Content-Length: 4\r\n" +
                "\r\n" +
                "TestEXTRA";

            using MemoryStream stream = MakeStream(raw);

            HttpResponse resp = await HttpResponse.ReadResponseAsync(
                stream,
                TestContext.CancellationToken);

            byte[] buffer = new byte[8];

            int totalRead = 0;
            int r;

            while ((r = await resp.OutputStream.ReadAsync(
                buffer, 0, buffer.Length, TestContext.CancellationToken)) > 0)
            {
                totalRead += r;
            }

            Assert.AreEqual(
                4,
                totalRead,
                "OutputStream must expose exactly Content-Length bytes (RFC 9112).");

            Assert.AreEqual(
                "Test",
                Encoding.ASCII.GetString(buffer, 0, totalRead));
        }

        private static MemoryStream MakeStream(string ascii)
                                                            => new MemoryStream(Encoding.ASCII.GetBytes(ascii));

        private static async Task<string> ReadAllAsciiAsync(Stream s, CancellationToken ct)
        {
            using MemoryStream ms = new MemoryStream();
            await s.CopyToAsync(ms, 8192, ct);
            return Encoding.ASCII.GetString(ms.ToArray());
        }
    }
}