using System.Text;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.IO
{
    public class BinaryReaderWriterExtensionsTests
    {
        [Fact]
        public void WriteBufferAndReadBuffer_RoundtripShortAndLongBuffers()
        {
            byte[] shortBuffer = new byte[] { 1, 2, 3 };
            byte[] longBuffer = Enumerable.Range(0, 300).Select(i => (byte)i).ToArray();
            using MemoryStream stream = new MemoryStream();
            using BinaryWriter writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);

            writer.WriteBuffer(shortBuffer);
            writer.WriteBuffer(longBuffer, 10, 200);
            writer.Flush();
            stream.Position = 0;

            using BinaryReader reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
            Assert.Equal(shortBuffer, reader.ReadBuffer());
            Assert.Equal(longBuffer.Skip(10).Take(200).ToArray(), reader.ReadBuffer());
        }

        [Fact]
        public void ReadLength_UnsupportedLengthThrows()
        {
            using MemoryStream stream = new MemoryStream(new byte[] { 0x85, 1, 2, 3, 4, 5 });
            using BinaryReader reader = new BinaryReader(stream);

            Assert.Throws<IOException>(() => reader.ReadLength());
        }
    }
}
