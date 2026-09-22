using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.IO
{
    public class OffsetStreamTests
    {
        [Fact]
        public void Read_ReadsOnlyConfiguredWindow()
        {
            byte[] source = new byte[] { 10, 20, 30, 40, 50 };
            using MemoryStream baseStream = new MemoryStream(source);
            using OffsetStream offsetStream = new OffsetStream(baseStream, offset: 1, length: 3, readOnly: true);

            byte[] buffer = new byte[10];
            int read = offsetStream.Read(buffer, 0, buffer.Length);

            Assert.Equal(3, read);
            Assert.Equal(new byte[] { 20, 30, 40 }, buffer.Take(read).ToArray());
            Assert.Equal(0, offsetStream.Read(buffer, 0, buffer.Length));
        }

        [Fact]
        public void Write_StartsAtBaseOffsetAndExpandsVirtualLength()
        {
            using MemoryStream baseStream = new MemoryStream(new byte[] { 1, 2, 3, 4, 5 });
            using OffsetStream offsetStream = new OffsetStream(baseStream, offset: 2);

            offsetStream.Write(new byte[] { 9, 8, 7 }, 0, 3);

            Assert.Equal(3, offsetStream.Length);
            Assert.Equal(new byte[] { 1, 2, 9, 8, 7 }, baseStream.ToArray());
        }

        [Fact]
        public void ReadOnlyWrite_Throws()
        {
            using MemoryStream baseStream = new MemoryStream(new byte[] { 1, 2, 3 });
            using OffsetStream offsetStream = new OffsetStream(baseStream, length: 3, readOnly: true);

            Assert.False(offsetStream.CanWrite);
            Assert.Throws<InvalidOperationException>(() => offsetStream.Write(new byte[] { 4 }, 0, 1));
        }

        [Fact]
        public void SeekSetLengthWriteToAndFlush_CoverSyncPaths()
        {
            using MemoryStream baseStream = new MemoryStream(new byte[] { 1, 2, 3, 4, 5 });
            using OffsetStream offsetStream = new OffsetStream(baseStream, offset: 1, length: 3);

            Assert.True(offsetStream.CanRead);
            Assert.True(offsetStream.CanSeek);
            Assert.True(offsetStream.CanWrite);
            Assert.False(offsetStream.CanTimeout);
            Assert.Same(baseStream, offsetStream.BaseStream);
            Assert.Equal(1, offsetStream.BaseStreamOffset);

            Assert.Equal(1, offsetStream.Seek(1, SeekOrigin.Begin));
            Assert.Equal(2, offsetStream.Seek(1, SeekOrigin.Current));
            Assert.Equal(1, offsetStream.Seek(-2, SeekOrigin.End));
            Assert.Throws<EndOfStreamException>(() => offsetStream.Seek(3, SeekOrigin.Begin));

            offsetStream.SetLength(4);
            Assert.Equal(4, offsetStream.Length);
            offsetStream.Flush();

            using MemoryStream copy = new MemoryStream();
            offsetStream.WriteTo(copy, 8);
            Assert.Equal(new byte[] { 2, 3, 4, 5 }, copy.ToArray());
        }

        [Fact]
        public async Task AsyncPaths_ReadWriteFlushAndCopy()
        {
            using MemoryStream baseStream = new MemoryStream(new byte[10]);
            using OffsetStream offsetStream = new OffsetStream(baseStream, offset: 2);

            await offsetStream.WriteAsync(new byte[] { 1, 2, 3 }, 0, 3, default);
            await offsetStream.WriteAsync(new byte[] { 4, 5 }.AsMemory(), default);
            await offsetStream.FlushAsync(default);

            offsetStream.Position = 0;
            byte[] buffer = new byte[5];
            Assert.Equal(5, await offsetStream.ReadAsync(buffer, 0, 5, default));
            Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, buffer);

            offsetStream.Position = 0;
            byte[] memoryBuffer = new byte[5];
            Assert.Equal(5, await offsetStream.ReadAsync(memoryBuffer.AsMemory(), default));
            Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, memoryBuffer);

            using MemoryStream copy = new MemoryStream();
            await offsetStream.WriteToAsync(copy, 8);
            Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, copy.ToArray());
        }
    }
}
