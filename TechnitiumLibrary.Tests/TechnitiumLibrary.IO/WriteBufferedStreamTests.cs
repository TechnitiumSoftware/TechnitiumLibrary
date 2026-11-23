using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.IO
{
    public class WriteBufferedStreamTests
    {
        private sealed class NonWritableStream : MemoryStream
        {
            public override bool CanWrite => false;
        }

        [Fact]
        public async Task BuffersFlushesAndDelegatesReads()
        {
            using MemoryStream baseStream = new MemoryStream();
            using WriteBufferedStream stream = new WriteBufferedStream(baseStream, bufferSize: 3);

            stream.Write(new byte[] { 1, 2 }, 0, 2);
            Assert.Empty(baseStream.ToArray());

            stream.Write(new byte[] { 3, 4 }, 0, 2);
            Assert.Equal(new byte[] { 1, 2, 3 }, baseStream.ToArray());

            await stream.WriteAsync(new byte[] { 5, 6 }, 0, 2);
            await stream.WriteAsync(new byte[] { 7, 8 }.AsMemory());
            await stream.FlushAsync(default);
            Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, baseStream.ToArray());

            baseStream.Position = 0;
            byte[] read = new byte[2];
            Assert.Equal(2, stream.Read(read, 0, 2));
            Assert.Equal(new byte[] { 1, 2 }, read);

            Span<byte> span = stackalloc byte[2];
            Assert.Equal(2, stream.Read(span));
            Assert.Equal(new byte[] { 3, 4 }, span.ToArray());

            byte[] asyncRead = new byte[2];
            Assert.Equal(2, await stream.ReadAsync(asyncRead, 0, 2, default));
            Assert.Equal(new byte[] { 5, 6 }, asyncRead);

            byte[] memoryRead = new byte[2];
            Assert.Equal(2, await stream.ReadAsync(memoryRead.AsMemory(), default));
            Assert.Equal(new byte[] { 7, 8 }, memoryRead);
        }

        [Fact]
        public void ThrowsForUnsupportedAndDisposedOperations()
        {
            Assert.Throws<NotSupportedException>(() => new WriteBufferedStream(new NonWritableStream()));

            MemoryStream baseStream = new MemoryStream();
            WriteBufferedStream stream = new WriteBufferedStream(baseStream);

            Assert.False(stream.CanSeek);
            Assert.Throws<NotSupportedException>(() => stream.Position = 1);
            Assert.Throws<NotSupportedException>(() => stream.Seek(0, SeekOrigin.Begin));
            Assert.Throws<NotSupportedException>(() => stream.SetLength(1));

            stream.Dispose();
            Assert.Throws<ObjectDisposedException>(() => stream.Write(new byte[] { 1 }, 0, 1));
            Assert.Throws<ObjectDisposedException>(() => stream.Flush());
        }
    }
}
