using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.IO
{
    [TestClass]
    public sealed class PipeTests
    {
        private static Pipe CreatePipe() => new Pipe();

        // ------------------------------------------------------------
        // CONSTRUCTION
        // ------------------------------------------------------------

        [TestMethod]
        public void Constructor_ShouldExposeTwoConnectedStreams()
        {
            Pipe p = CreatePipe();

            Assert.IsNotNull(p.Stream1);
            Assert.IsNotNull(p.Stream2);

            Assert.IsTrue(p.Stream1.CanRead);
            Assert.IsTrue(p.Stream1.CanWrite);

            Assert.IsTrue(p.Stream2.CanRead);
            Assert.IsTrue(p.Stream2.CanWrite);
        }

        // ------------------------------------------------------------
        // BASIC DATA TRANSFER
        // ------------------------------------------------------------

        [TestMethod]
        public void WriteOnStream1_ShouldBeReadableFromStream2()
        {
            Pipe pipe = CreatePipe();
            byte[] data = new byte[] { 1, 2, 3 };

            pipe.Stream1.Write(data, 0, data.Length);

            byte[] buffer = new byte[10];
            int read = pipe.Stream2.Read(buffer, 0, 10);

            Assert.AreEqual(3, read);
            CollectionAssert.AreEqual(new byte[] { 1, 2, 3 }, buffer[..3]);
        }

        [TestMethod]
        public void Read_ShouldReturnZero_WhenOtherSideDisposed()
        {
            Pipe pipe = CreatePipe();

            pipe.Stream1.Dispose();

            byte[] buffer = new byte[5];
            int read = pipe.Stream2.Read(buffer, 0, 5);

            Assert.AreEqual(0, read);
        }

        // ------------------------------------------------------------
        // SEEK PROHIBITIONS
        // ------------------------------------------------------------

        [TestMethod]
        public void Position_ShouldThrowOnGet()
        {
            Pipe pipe = CreatePipe();
            Assert.ThrowsExactly<IOException>(() => _ = pipe.Stream1.Position);
        }

        [TestMethod]
        public void Position_ShouldThrowOnSet()
        {
            Pipe pipe = CreatePipe();
            Assert.ThrowsExactly<IOException>(() => pipe.Stream1.Position = 10);
        }

        [TestMethod]
        public void Seek_ShouldThrow()
        {
            Pipe pipe = CreatePipe();
            Assert.ThrowsExactly<IOException>(() => pipe.Stream1.Seek(10, SeekOrigin.Begin));
        }

        [TestMethod]
        public void Length_ShouldThrow()
        {
            Pipe pipe = CreatePipe();
            Assert.ThrowsExactly<IOException>(() => _ = pipe.Stream1.Length);
        }

        // ------------------------------------------------------------
        // BUFFER BOUNDARY BEHAVIOR
        // ------------------------------------------------------------

        [TestMethod]
        public void Write_ShouldBlockWhenBufferFull_ThenResumeAfterRead()
        {
            Pipe pipe = CreatePipe();
            Stream stream1 = pipe.Stream1;
            Stream stream2 = pipe.Stream2;

            stream1.WriteTimeout = 2000;
            stream2.ReadTimeout = 2000;

            byte[] large = new byte[64 * 1024]; // exactly buffer size

            // Fill buffer completely
            stream1.Write(large, 0, large.Length);

            // Now write again, but on another thread
            using Task t = Task.Run(() =>
            {
                // Should block until read
                stream1.Write(new byte[] { 7 }, 0, 1);
            }, TestContext.CancellationToken);

            // Give writer thread chance to block
            Thread.Sleep(100);

            // Now read entire buffer
            byte[] readBuffer = new byte[large.Length];
            int readTotal = stream2.Read(readBuffer, 0, large.Length);

            Assert.AreEqual(large.Length, readTotal);

            // Now writer should have completed
            t.Wait(TestContext.CancellationToken);
        }

        [TestMethod]
        public void Write_ShouldFailWhenTimeoutExceeded()
        {
            Pipe pipe = CreatePipe();
            pipe.Stream1.WriteTimeout = 300;

            // fill buffer without draining
            pipe.Stream1.Write(new byte[64 * 1024], 0, 64 * 1024);

            Assert.ThrowsExactly<IOException>(() => pipe.Stream1.Write(new byte[] { 1 }, 0, 1));
        }

        [TestMethod]
        public void Read_ShouldFailWhenTimeoutExceeded()
        {
            Pipe pipe = CreatePipe();
            pipe.Stream2.ReadTimeout = 200;

            byte[] buffer = new byte[1];

            Assert.ThrowsExactly<IOException>(() => pipe.Stream2.Read(buffer, 0, 1));
        }

        // ------------------------------------------------------------
        // DISPOSAL CASCADE
        // ------------------------------------------------------------

        [TestMethod]
        public void Dispose_ShouldStopOtherSideFromDeliveringData()
        {
            Pipe pipe = CreatePipe();
            pipe.Stream1.Dispose();

            Assert.ThrowsExactly<ObjectDisposedException>(() => pipe.Stream1.Write(new byte[] { 1 }, 0, 1));
        }

        public TestContext TestContext { get; set; }
    }
}
