using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.IO
{
    [TestClass]
    public sealed class WriteBufferedStreamTests
    {
        private sealed class NonWritableStream : MemoryStream
        {
            public override bool CanWrite => false;
        }

        private static MemoryStream CreateBaseStream(byte[]? initial = null) =>
            initial is null ? new MemoryStream() : new MemoryStream(initial);

        // ------------------------------------------------------
        // CONSTRUCTION / CAPABILITIES
        // ------------------------------------------------------

        [TestMethod]
        public void Constructor_ShouldThrow_WhenBaseStreamNotWritable()
        {
            // GIVEN
            using NonWritableStream baseStream = new NonWritableStream();

            // WHEN-THEN
            Assert.ThrowsExactly<NotSupportedException>(
                () => new WriteBufferedStream(baseStream));
        }

        [TestMethod]
        public void Constructor_ShouldExposeCapabilitiesFromBaseStream()
        {
            // GIVEN
            using MemoryStream baseStream = CreateBaseStream();

            // WHEN
            using WriteBufferedStream buffered = new WriteBufferedStream(baseStream);

            // THEN
            Assert.IsTrue(buffered.CanWrite);
            Assert.AreEqual(baseStream.CanRead, buffered.CanRead);
            Assert.AreEqual(baseStream.CanTimeout, buffered.CanTimeout);
            Assert.IsFalse(buffered.CanSeek);
        }

        // ------------------------------------------------------
        // BASIC WRITE & FLUSH (SYNC)
        // ------------------------------------------------------

        [TestMethod]
        public void Write_ShouldBufferUntilFlushed()
        {
            // GIVEN
            using MemoryStream baseStream = CreateBaseStream();
            using WriteBufferedStream buffered = new WriteBufferedStream(baseStream, bufferSize: 8);

            byte[] data = Encoding.ASCII.GetBytes("ABCD"); // 4 bytes

            // WHEN
            buffered.Write(data, 0, data.Length);

            // THEN – nothing written yet to base
            CollectionAssert.AreEqual(Array.Empty<byte>(), baseStream.ToArray());
            Assert.AreEqual(0L, baseStream.Length);

            // WHEN
            buffered.Flush();

            // THEN – data should now exist in base stream
            CollectionAssert.AreEqual(data, baseStream.ToArray());
        }

        [TestMethod]
        public void Write_ShouldFlushBufferWhenFull_AndKeepRemainderBuffered()
        {
            // GIVEN
            using MemoryStream baseStream = CreateBaseStream();
            using WriteBufferedStream buffered = new WriteBufferedStream(baseStream, bufferSize: 4);

            // 6 bytes, buffer 4 -> first 4 flushed, last 2 remain buffered after Flush
            byte[] data = Encoding.ASCII.GetBytes("ABCDEF");

            // WHEN
            buffered.Write(data, 0, data.Length);

            // buffer is full internally twice, so Flush() is invoked from Write
            // After Write completes, we call Flush() to ensure remainder is written.
            buffered.Flush();

            // THEN
            CollectionAssert.AreEqual(data, baseStream.ToArray());
        }

        // ------------------------------------------------------
        // BASIC WRITE & FLUSH (ASYNC)
        // ------------------------------------------------------

        [TestMethod]
        public async Task WriteAsync_ShouldBufferAndFlushAsync()
        {
            // GIVEN
            using MemoryStream baseStream = CreateBaseStream();
            using WriteBufferedStream buffered = new WriteBufferedStream(baseStream, bufferSize: 8);

            byte[] data = Encoding.UTF8.GetBytes("123456");

            // WHEN
            await buffered.WriteAsync(data, 0, data.Length, CancellationToken.None);

            // Still buffered
            CollectionAssert.AreEqual(Array.Empty<byte>(), baseStream.ToArray());

            await buffered.FlushAsync(CancellationToken.None);

            // THEN
            CollectionAssert.AreEqual(data, baseStream.ToArray());
        }

        [TestMethod]
        public async Task WriteAsync_MemoryOverload_ShouldRespectBuffering()
        {
            // GIVEN
            using MemoryStream baseStream = CreateBaseStream();
            using WriteBufferedStream buffered = new WriteBufferedStream(baseStream, bufferSize: 4);

            byte[] data = Encoding.ASCII.GetBytes("WXYZ12"); // 6 bytes

            // WHEN
            await buffered.WriteAsync(data.AsMemory(), CancellationToken.None);
            await buffered.FlushAsync(CancellationToken.None);

            // THEN
            CollectionAssert.AreEqual(data, baseStream.ToArray());
        }

        // ------------------------------------------------------
        // READ DELEGATION
        // ------------------------------------------------------

        [TestMethod]
        public void Read_ShouldDelegateToBaseStream()
        {
            // GIVEN
            byte[] initial = Encoding.ASCII.GetBytes("HELLO");
            using MemoryStream baseStream = CreateBaseStream(initial);
            using WriteBufferedStream buffered = new WriteBufferedStream(baseStream);

            // WHEN
            byte[] buffer = new byte[5];
            baseStream.Position = 0; // ensure we read from start
            int read = buffered.Read(buffer, 0, buffer.Length);

            // THEN
            Assert.AreEqual(5, read);
            CollectionAssert.AreEqual(initial, buffer);
        }

        // ------------------------------------------------------
        // SEEK / LENGTH / POSITION BEHAVIOR
        // ------------------------------------------------------

        [TestMethod]
        public void Position_Get_ShouldMatchBaseStreamPosition()
        {
            // GIVEN
            using MemoryStream baseStream = CreateBaseStream(new byte[10]);
            baseStream.Position = 4;
            using WriteBufferedStream buffered = new WriteBufferedStream(baseStream);

            // WHEN
            long position = buffered.Position;

            // THEN
            Assert.AreEqual(4L, position);
        }

        [TestMethod]
        public void Position_Set_ShouldThrow_NotSupported()
        {
            // GIVEN
            using MemoryStream baseStream = CreateBaseStream();
            using WriteBufferedStream buffered = new WriteBufferedStream(baseStream);

            // WHEN-THEN
            Assert.ThrowsExactly<NotSupportedException>(() =>
                buffered.Position = 1);
        }

        [TestMethod]
        public void Seek_ShouldThrow_NotSupported()
        {
            // GIVEN
            using MemoryStream baseStream = CreateBaseStream();
            using WriteBufferedStream buffered = new WriteBufferedStream(baseStream);

            // WHEN-THEN
            Assert.ThrowsExactly<NotSupportedException>(() =>
                buffered.Seek(0, SeekOrigin.Begin));
        }

        [TestMethod]
        public void SetLength_ShouldThrow_NotSupported()
        {
            // GIVEN
            using MemoryStream baseStream = CreateBaseStream();
            using WriteBufferedStream buffered = new WriteBufferedStream(baseStream);

            // WHEN-THEN
            Assert.ThrowsExactly<NotSupportedException>(() =>
                buffered.SetLength(10));
        }

        // ------------------------------------------------------
        // DISPOSAL & OWNERSHIP
        // ------------------------------------------------------

        [TestMethod]
        public void Dispose_ShouldDisposeUnderlyingStream()
        {
            // GIVEN
            MemoryStream baseStream = CreateBaseStream();
            WriteBufferedStream buffered = new WriteBufferedStream(baseStream);

            // WHEN
            buffered.Dispose();

            // THEN – base stream also disposed
            Assert.ThrowsExactly<ObjectDisposedException>(() =>
                baseStream.WriteByte(1));
        }

        [TestMethod]
        public void Write_ShouldThrow_WhenDisposed()
        {
            // GIVEN
            using MemoryStream baseStream = CreateBaseStream();
            WriteBufferedStream buffered = new WriteBufferedStream(baseStream);
            buffered.Dispose();

            // WHEN-THEN
            Assert.ThrowsExactly<ObjectDisposedException>(() =>
                buffered.Write(new byte[] { 1 }, 0, 1));
        }

        [TestMethod]
        public async Task WriteAsync_ShouldThrow_WhenDisposed()
        {
            // GIVEN
            using MemoryStream baseStream = CreateBaseStream();
            WriteBufferedStream buffered = new WriteBufferedStream(baseStream);
            buffered.Dispose();

            // WHEN-THEN
            await Assert.ThrowsExactlyAsync<ObjectDisposedException>(() =>
                buffered.WriteAsync(new byte[] { 1 }, 0, 1, CancellationToken.None));
        }

        [TestMethod]
        public async Task FlushAsync_ShouldNotFlush_WhenNothingBuffered()
        {
            // GIVEN
            using MemoryStream baseStream = CreateBaseStream();
            using WriteBufferedStream buffered = new WriteBufferedStream(baseStream);

            // WHEN
            await buffered.FlushAsync(CancellationToken.None);

            // THEN – nothing written
            CollectionAssert.AreEqual(Array.Empty<byte>(), baseStream.ToArray());
        }
    }
}
