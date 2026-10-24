using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace TechnitiumLibrary.Net.ProxyProtocol.Tests
{
    [TestClass]
    public class ProxyProtocolStreamTests
    {
        [TestMethod]
        public async Task CreateAsServerAsync_V1_MemoryStream_ParsesMetadataAndExposesPayload()
        {
            string line = "PROXY TCP4 192.168.0.1 192.168.0.11 56324 443";
            byte[] header = MakeV1(line);
            byte[] payload = Encoding.ASCII.GetBytes("HELLO");
            byte[] source = Join(header, payload);

            using MemoryStream baseStream = new(source);

            ProxyProtocolStream proxy =
                await ProxyProtocolStream.CreateAsServerAsync(baseStream);

            Assert.AreEqual(1, proxy.ProtocolVersion, "ProtocolVersion must be 1.");
            Assert.AreEqual(AddressFamily.InterNetwork, proxy.AddressFamily, "TCP4 must map to IPv4.");
            Assert.AreEqual(SocketType.Stream, proxy.SocketType);
            Assert.AreEqual(IPAddress.Parse("192.168.0.1"), proxy.SourceAddress);
            Assert.AreEqual(IPAddress.Parse("192.168.0.11"), proxy.DestinationAddress);
            Assert.AreEqual(56324, proxy.SourcePort);
            Assert.AreEqual(443, proxy.DestinationPort);
            Assert.AreEqual(header.Length, proxy.DataOffset, "DataOffset must equal the header length.");

            byte[] buffer = new byte[payload.Length];
            int read = proxy.Read(buffer, 0, buffer.Length);

            Assert.AreEqual(payload.Length, read, "Read must return only payload bytes.");
            Assert.AreEqual("HELLO", Encoding.ASCII.GetString(buffer));
        }

        [TestMethod]
        public async Task CreateAsServerAsync_V1_FragmentedStream_ReadsHeaderAcrossMultipleChunks()
        {
            string line = "PROXY TCP4 10.0.0.1 10.0.0.2 1000 2000";
            byte[] header = MakeV1(line);
            byte[] payload = Encoding.ASCII.GetBytes("PAYLOAD");
            byte[] source = Join(header, payload);

            using FragmentedReadStream baseStream =
                new(source, header.Length);

            ProxyProtocolStream proxy =
                await ProxyProtocolStream.CreateAsServerAsync(baseStream);

            Assert.AreEqual(1, proxy.ProtocolVersion);
            Assert.AreEqual("10.0.0.1", proxy.SourceAddress.ToString());
            Assert.AreEqual("10.0.0.2", proxy.DestinationAddress.ToString());
            Assert.AreEqual(1000, proxy.SourcePort);
            Assert.AreEqual(2000, proxy.DestinationPort);
            Assert.AreEqual(header.Length, proxy.DataOffset);

            byte[] buffer = new byte[payload.Length];
            int read = proxy.Read(buffer, 0, buffer.Length);

            Assert.AreEqual(payload.Length, read);
            Assert.AreEqual("PAYLOAD", Encoding.ASCII.GetString(buffer));
        }

        [TestMethod]
        public async Task CreateAsServerAsync_V2_IPv4_MemoryStream_CorrectMetadataAndPayload()
        {
            IPAddress src = IPAddress.Parse("192.0.2.1");
            IPAddress dst = IPAddress.Parse("198.51.100.2");
            ushort srcPort = 12345;
            ushort dstPort = 443;

            byte[] header = MakeV2v4(src, dst, srcPort, dstPort, local: false, streamProto: true);
            byte[] payload = Encoding.ASCII.GetBytes("DATA");
            byte[] source = Join(header, payload);

            using MemoryStream baseStream = new(source);

            ProxyProtocolStream proxy =
                await ProxyProtocolStream.CreateAsServerAsync(baseStream);

            Assert.AreEqual(2, proxy.ProtocolVersion);
            Assert.IsFalse(proxy.IsLocal);
            Assert.AreEqual(AddressFamily.InterNetwork, proxy.AddressFamily);
            Assert.AreEqual(SocketType.Stream, proxy.SocketType);
            Assert.AreEqual(src, proxy.SourceAddress);
            Assert.AreEqual(dst, proxy.DestinationAddress);
            Assert.AreEqual(srcPort, proxy.SourcePort);
            Assert.AreEqual(dstPort, proxy.DestinationPort);
            Assert.AreEqual(28, proxy.DataOffset, "IPv4 PROXY v2 header must be 16 + 12 bytes.");

            byte[] buffer = new byte[payload.Length];
            int read = proxy.Read(buffer, 0, buffer.Length);

            Assert.AreEqual("DATA", Encoding.ASCII.GetString(buffer));
        }

        [TestMethod]
        public async Task CreateAsServerAsync_V2_IPv4_Fragmented_StillParsesCorrectly()
        {
            IPAddress src = IPAddress.Parse("203.0.113.10");
            IPAddress dst = IPAddress.Parse("203.0.113.20");
            ushort srcPort = 8080;
            ushort dstPort = 8443;

            byte[] header = MakeV2v4(src, dst, srcPort, dstPort, local: false, streamProto: true);
            byte[] payload = Encoding.ASCII.GetBytes("FRAG");
            byte[] source = Join(header, payload);

            using FragmentedReadStream baseStream =
                new(source, header.Length);

            ProxyProtocolStream proxy =
                await ProxyProtocolStream.CreateAsServerAsync(baseStream);

            Assert.AreEqual(2, proxy.ProtocolVersion);
            Assert.AreEqual(src, proxy.SourceAddress);
            Assert.AreEqual(dst, proxy.DestinationAddress);
            Assert.AreEqual(8080, proxy.SourcePort);
            Assert.AreEqual(8443, proxy.DestinationPort);

            byte[] buffer = new byte[payload.Length];
            int read = proxy.Read(buffer, 0, buffer.Length);

            Assert.AreEqual("FRAG", Encoding.ASCII.GetString(buffer));
        }

        [TestMethod]
        public async Task CreateAsServerAsync_InvalidPrefix_ThrowsInvalidDataException()
        {
            // Arrange: must provide enough bytes to exceed detection thresholds (>=16 bytes)
            byte[] bad =
            {
                0xFF, 0xFF, 0xFF, 0xFF,
                0xAA, 0xAA, 0xAA, 0xAA,
                0xEE, 0xEE, 0xEE, 0xEE,
                0xCC, 0xCC, 0xCC, 0xCC,
                0x00 // ensures not EOF boundary
            };

            using MemoryStream baseStream = new(bad);

            // Act & Assert
            InvalidDataException ex =
                await Assert.ThrowsExactlyAsync<InvalidDataException>(
                    () => ProxyProtocolStream.CreateAsServerAsync(baseStream));

            Assert.IsTrue(
                ex.Message.Contains("PROXY", StringComparison.OrdinalIgnoreCase),
                "Exception message must indicate invalid PROXY protocol header.");
        }


        [TestMethod]
        public async Task CreateAsServerAsync_EndOfStreamBeforeHeader_ThrowsEndOfStreamException()
        {
            using MemoryStream baseStream = new(Encoding.ASCII.GetBytes("PROX"));

            _ = await Assert.ThrowsExactlyAsync<EndOfStreamException>(
                () => ProxyProtocolStream.CreateAsServerAsync(baseStream));
        }

        [TestMethod]
        public async Task Dispose_IsIdempotent_AndDisposesUnderlyingStream()
        {
            string line = "PROXY TCP4 127.0.0.1 127.0.0.1 1 2";
            byte[] header = MakeV1(line);
            using MemoryStream underlying = new(header);

            ProxyProtocolStream proxy =
                await ProxyProtocolStream.CreateAsServerAsync(underlying);

            proxy.Dispose();
            proxy.Dispose(); // must not throw

            Assert.ThrowsExactly<ObjectDisposedException>(
                () => underlying.ReadByte(),
                "Underlying stream must actually be disposed.");
        }

        [TestMethod]
        public async Task FlushAfterDispose_Throws_ObjectDisposedException()
        {
            string line = "PROXY TCP4 127.0.0.1 127.0.0.1 10 20";
            byte[] header = MakeV1(line);
            using MemoryStream underlying = new(header);

            ProxyProtocolStream proxy =
                await ProxyProtocolStream.CreateAsServerAsync(underlying);

            proxy.Dispose();

            Assert.ThrowsExactly<ObjectDisposedException>(
                () => proxy.Flush(),
                "Flush() after disposal must signal ODE.");
        }

        [TestMethod]
        public async Task WriteAfterDispose_DoesNotWriteAndThrows()
        {
            string line = "PROXY TCP4 127.0.0.1 127.0.0.1 30 40";
            byte[] header = MakeV1(line);
            using WriteTrackerStream baseStream = new(header);

            ProxyProtocolStream proxy =
                await ProxyProtocolStream.CreateAsServerAsync(baseStream);

            proxy.Dispose();

            byte[] bytes = Encoding.ASCII.GetBytes("NOPE");

            Assert.ThrowsExactly<ObjectDisposedException>(
                () => proxy.Write(bytes, 0, bytes.Length));

            Assert.IsFalse(baseStream.WroteAfterDispose,
                "Write() must not propagate to underlying after disposal.");
        }

        [TestMethod]
        public async Task ReadAsyncBufferedData_ReturnsPayloadWithoutTouchingBaseStream()
        {
            string line = "PROXY TCP4 192.168.1.1 192.168.1.2 100 200";
            byte[] header = MakeV1(line);
            byte[] payload = Encoding.ASCII.GetBytes("ASYNC");
            byte[] source = Join(header, payload);

            using MemoryStream baseStream = new(source);

            ProxyProtocolStream proxy =
                await ProxyProtocolStream.CreateAsServerAsync(baseStream);

            byte[] buffer = new byte[payload.Length];
            int read = await proxy.ReadAsync(buffer, 0, buffer.Length);

            Assert.AreEqual(payload.Length, read);
            Assert.AreEqual("ASYNC", Encoding.ASCII.GetString(buffer));
        }

        [TestMethod]
        public async Task CapabilityAndSeekContract_IsCorrect()
        {
            string line = "PROXY TCP4 127.0.0.1 127.0.0.1 5 6";
            byte[] header = MakeV1(line);

            using MemoryStream baseStream = new(header);

            ProxyProtocolStream proxy =
                await ProxyProtocolStream.CreateAsServerAsync(baseStream);

            Assert.IsTrue(proxy.CanRead);
            Assert.IsFalse(proxy.CanSeek);
            Assert.IsTrue(proxy.CanWrite);

            _ = Assert.ThrowsExactly<NotSupportedException>(() => proxy.Length);
            _ = Assert.ThrowsExactly<NotSupportedException>(() => proxy.Seek(0, SeekOrigin.Begin));
            _ = Assert.ThrowsExactly<NotSupportedException>(() => proxy.SetLength(0));
        }

        // --------------------
        // Helper functions
        // --------------------
        private static byte[] MakeV1(string headerLineNoCrlf)
        {
            string full = headerLineNoCrlf + "\r\n";
            return Encoding.ASCII.GetBytes(full);
        }

        private static byte[] Join(byte[] left, byte[] right)
        {
            byte[] result = new byte[left.Length + right.Length];
            Buffer.BlockCopy(left, 0, result, 0, left.Length);
            Buffer.BlockCopy(right, 0, result, left.Length, right.Length);
            return result;
        }

        private static byte[] MakeV2sig()
        {
            return new byte[]
            {
                0x0D,0x0A,0x0D,0x0A,
                0x00,0x0D,0x0A,0x51,
                0x55,0x49,0x54,0x0A
            };
        }

        private static byte[] MakeV2v4(
            IPAddress src,
            IPAddress dst,
            ushort srcPort,
            ushort dstPort,
            bool local,
            bool streamProto)
        {
            byte[] sig = MakeV2sig();
            byte command = (byte)(local ? 0x0 : 0x1); // LOCAL or PROXY
            byte versionNibble = 0x2;
            byte verCmd = (byte)((versionNibble << 4) | command);

            byte afNibble = 1;
            byte protoNibble = streamProto ? (byte)1 : (byte)2;
            byte famProto = (byte)((afNibble << 4) | protoNibble);

            ushort len = 12;
            byte[] h = new byte[16 + len];

            Buffer.BlockCopy(sig, 0, h, 0, sig.Length);
            h[12] = verCmd;
            h[13] = famProto;
            h[14] = (byte)(len >> 8);
            h[15] = (byte)(len & 0xFF);

            byte[] srcb = src.GetAddressBytes();
            byte[] dstb = dst.GetAddressBytes();

            Buffer.BlockCopy(srcb, 0, h, 16, 4);
            Buffer.BlockCopy(dstb, 0, h, 20, 4);

            h[24] = (byte)(srcPort >> 8);
            h[25] = (byte)(srcPort & 0xFF);
            h[26] = (byte)(dstPort >> 8);
            h[27] = (byte)(dstPort & 0xFF);

            return h;
        }

        internal sealed class FragmentedReadStream : Stream
        {
            private readonly byte[] _data;
            private readonly int _chunkSize;
            private int _pos;
            private bool _disposed;

            public FragmentedReadStream(byte[] data, int chunkSize)
            {
                _data = data;
                _chunkSize = chunkSize;
            }

            public override bool CanRead => !_disposed;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => throw new NotSupportedException();
            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public override void Flush() { }

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (_disposed)
                    throw new ObjectDisposedException(nameof(FragmentedReadStream));

                if (_pos >= _data.Length)
                    return 0;

                int cut = Math.Min(count, _chunkSize);
                cut = Math.Min(cut, _data.Length - _pos);

                Buffer.BlockCopy(_data, _pos, buffer, offset, cut);
                _pos += cut;
                return cut;
            }

            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
                => Task.FromResult(Read(buffer, offset, count));

            public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                byte[] tmp = new byte[buffer.Length];
                int n = Read(tmp, 0, tmp.Length);
                if (n > 0)
                    new ReadOnlySpan<byte>(tmp, 0, n).CopyTo(buffer.Span);
                return ValueTask.FromResult(n);
            }

            protected override void Dispose(bool disposing)
            {
                _disposed = true;
            }

            public override long Seek(long offset, SeekOrigin origin)
                => throw new NotSupportedException();

            public override void SetLength(long value)
                => throw new NotSupportedException();

            public override void Write(byte[] buffer, int offset, int count)
                => throw new NotSupportedException();
        }

        internal sealed class WriteTrackerStream : MemoryStream
        {
            public bool WroteAfterDispose { get; private set; }
            private bool _disposed;

            public WriteTrackerStream(byte[] initial) : base(initial) { }

            protected override void Dispose(bool disposing)
            {
                _disposed = true;
                base.Dispose(disposing);
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                if (_disposed)
                    WroteAfterDispose = true;
                base.Write(buffer, offset, count);
            }
        }
    }
}
