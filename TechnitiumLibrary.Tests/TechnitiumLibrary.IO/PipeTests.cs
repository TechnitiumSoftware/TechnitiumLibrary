using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.IO
{
    public class PipeTests
    {
        [Fact]
        public void TransfersBytesAndSupportsTimeoutAndSeekExceptions()
        {
            Pipe pipe = new Pipe();
            Stream stream1 = pipe.Stream1;
            Stream stream2 = pipe.Stream2;

            Assert.True(stream1.CanRead);
            Assert.True(stream1.CanWrite);
            Assert.True(stream1.CanTimeout);
            Assert.False(stream1.CanSeek);

            stream1.WriteTimeout = 50;
            stream2.ReadTimeout = 50;
            Assert.Equal(50, stream1.WriteTimeout);
            Assert.Equal(50, stream2.ReadTimeout);

            stream1.Write(new byte[] { 1, 2, 3 }, 0, 3);
            byte[] buffer = new byte[5];
            Assert.Equal(2, stream2.Read(buffer, 0, 2));
            Assert.Equal(new byte[] { 1, 2 }, buffer.Take(2).ToArray());
            Assert.Equal(1, stream2.Read(buffer, 0, 5));
            Assert.Equal(3, buffer[0]);
            Assert.Equal(0, stream2.Read(buffer, 0, 0));

            Assert.Throws<IOException>(() => _ = stream1.Length);
            Assert.Throws<IOException>(() => _ = stream1.Position);
            Assert.Throws<IOException>(() => stream1.Position = 0);
            Assert.Throws<IOException>(() => stream1.Seek(0, SeekOrigin.Begin));
            Assert.Throws<IOException>(() => stream1.SetLength(1));
            Assert.Throws<IOException>(() => stream2.Read(buffer, 0, 1));

            stream1.Dispose();
            Assert.Equal(0, stream2.Read(buffer, 0, 1));
            Assert.Throws<ObjectDisposedException>(() => stream2.Write(new byte[] { 1 }, 0, 1));
        }
    }
}
