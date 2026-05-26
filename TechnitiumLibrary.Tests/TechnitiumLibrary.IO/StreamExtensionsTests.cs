using System.Text;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.IO
{
    public class StreamExtensionsTests
    {
        [Fact]
        public void ReadWriteShortStringAndDateTime_Roundtrips()
        {
            DateTime date = DateTime.UnixEpoch.AddMilliseconds(123456789);
            using MemoryStream stream = new MemoryStream();

            stream.WriteShortString("hello");
            stream.WriteDateTime(date);
            stream.Position = 0;

            Assert.Equal("hello", stream.ReadShortString());
            Assert.Equal(date, stream.ReadDateTime());
        }

        [Fact]
        public async Task AsyncReadWriteShortStringAndDateTime_Roundtrips()
        {
            DateTime date = DateTime.UnixEpoch.AddMilliseconds(987654321);
            using MemoryStream stream = new MemoryStream();

            await stream.WriteShortStringAsync("hello");
            await stream.WriteDateTimeAsync(date);
            stream.Position = 0;

            Assert.Equal("hello", await stream.ReadShortStringAsync());
            Assert.Equal(date, await stream.ReadDateTimeAsync());
        }

        [Fact]
        public void CopyTo_CopiesExactLengthAndThrowsOnShortSource()
        {
            using MemoryStream source = new MemoryStream(new byte[] { 1, 2, 3, 4, 5 });
            using MemoryStream destination = new MemoryStream();

            source.CopyTo(destination, bufferSize: 10, length: 3);

            Assert.Equal(new byte[] { 1, 2, 3 }, destination.ToArray());
            Assert.Throws<EndOfStreamException>(() => source.CopyTo(Stream.Null, bufferSize: 4, length: 10));
        }

        [Fact]
        public async Task CopyToAsync_CopiesExactLengthAndThrowsOnShortSource()
        {
            using MemoryStream source = new MemoryStream(new byte[] { 1, 2, 3, 4, 5 });
            using MemoryStream destination = new MemoryStream();

            await source.CopyToAsync(destination, bufferSize: 10, length: 3);

            Assert.Equal(new byte[] { 1, 2, 3 }, destination.ToArray());
            await Assert.ThrowsAsync<EndOfStreamException>(() => source.CopyToAsync(Stream.Null, bufferSize: 4, length: 10));
        }

        [Fact]
        public void ReadByteValueAndWriteShortString_ThrowOnInvalidData()
        {
            using MemoryStream empty = new MemoryStream();
            Assert.Throws<EndOfStreamException>(() => empty.ReadByteValue());

            using MemoryStream stream = new MemoryStream();
            Assert.Throws<ArgumentOutOfRangeException>(() => stream.WriteShortString(new string('x', 256), Encoding.ASCII));
        }

        [Fact]
        public async Task AsyncByteAndLongStringPaths_Work()
        {
            using MemoryStream stream = new MemoryStream();

            await stream.WriteByteAsync(123);
            await stream.WriteShortStringAsync(new string('x', 255), Encoding.ASCII);
            stream.Position = 0;

            Assert.Equal(123, await stream.ReadByteValueAsync());
            Assert.Equal(new string('x', 255), await stream.ReadShortStringAsync(Encoding.ASCII));
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => stream.WriteShortStringAsync(new string('x', 256), Encoding.ASCII));
        }
    }
}
