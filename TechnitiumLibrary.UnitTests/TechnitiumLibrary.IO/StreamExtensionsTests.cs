using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.IO
{
    [TestClass]
    public sealed class StreamExtensionsTests
    {
        private static MemoryStream StreamOf(params byte[] data) =>
            new MemoryStream(data, writable: true);

        // --------------------------------------------------------------------
        // ReadByteValue & WriteByteAsync
        // --------------------------------------------------------------------

        [TestMethod]
        public void ReadByteValue_ShouldReturnFirstByte()
        {
            using MemoryStream s = StreamOf("c"u8.ToArray());
            Assert.AreEqual(99, s.ReadByteValue());
        }

        [TestMethod]
        public void ReadByteValue_ShouldThrow_WhenEmpty()
        {
            using MemoryStream s = StreamOf();
            Assert.ThrowsExactly<EndOfStreamException>(() => s.ReadByteValue());
        }

        [TestMethod]
        public async Task WriteByteAsync_ShouldWriteByte()
        {
            await using MemoryStream s = new MemoryStream(); // expandable stream

            await s.WriteByteAsync(42, TestContext.CancellationToken);

            s.Position = 0;

            byte value = await s.ReadByteValueAsync(TestContext.CancellationToken);

            Assert.AreEqual(42, value);
        }

        // --------------------------------------------------------------------
        // ReadExactly
        // --------------------------------------------------------------------

        [TestMethod]
        public void ReadExactly_ShouldReturnRequestedBytes()
        {
            using MemoryStream s = StreamOf(1, 2, 3, 4);
            byte[] data = s.ReadExactly(3);

            CollectionAssert.AreEqual(new byte[] { 1, 2, 3 }, data);
        }

        [TestMethod]
        public void ReadExactly_ShouldThrow_WhenInsufficientData()
        {
            using MemoryStream s = StreamOf(1, 2);
            Assert.ThrowsExactly<EndOfStreamException>(() => s.ReadExactly(3));
        }

        [TestMethod]
        public async Task ReadExactlyAsync_ShouldReturnRequestedBytes()
        {
            await using MemoryStream s = StreamOf(10, 20, 30);
            byte[] result = await s.ReadExactlyAsync(2, TestContext.CancellationToken);

            CollectionAssert.AreEqual(new byte[] { 10, 20 }, result);
        }

        [TestMethod]
        public async Task ReadExactlyAsync_ShouldThrow_WhenStreamEnds()
        {
            await using MemoryStream s = StreamOf(5);
            await Assert.ThrowsExactlyAsync<EndOfStreamException>(() => s.ReadExactlyAsync(2, TestContext.CancellationToken));
        }

        // --------------------------------------------------------------------
        // Short string read/write
        // --------------------------------------------------------------------

        [TestMethod]
        public void WriteShortString_ThenReadShortString_ShouldRoundtrip()
        {
            using MemoryStream s = new MemoryStream(); // expandable stream

            s.WriteShortString("Hello");

            s.Position = 0;
            string str = s.ReadShortString();

            Assert.AreEqual("Hello", str);
        }

        [TestMethod]
        public void WriteShortString_ShouldThrow_WhenLengthExceeds255()
        {
            string oversized = new string('A', 300);

            using MemoryStream s = StreamOf();
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => s.WriteShortString(oversized));
        }

        [TestMethod]
        public void ReadShortString_ShouldThrow_WhenLengthGreaterThanAvailableData()
        {
            using MemoryStream s = StreamOf(2, 65); // length=2, only 1 byte remains
            Assert.ThrowsExactly<EndOfStreamException>(() => s.ReadShortString());
        }

        [TestMethod]
        public async Task WriteShortStringAsync_ShouldRoundtripWithUTF8()
        {
            await using MemoryStream s = new MemoryStream(); // expandable

            await s.WriteShortStringAsync("test✓", TestContext.CancellationToken);

            s.Position = 0;
            string parsed = await s.ReadShortStringAsync(TestContext.CancellationToken);

            Assert.AreEqual("test✓", parsed);
        }

        // --------------------------------------------------------------------
        // CopyTo & CopyToAsync
        // --------------------------------------------------------------------

        [TestMethod]
        public void CopyTo_ShouldCopyExactBytes()
        {
            using MemoryStream src = StreamOf(1, 2, 3, 4);
            using MemoryStream dst = new MemoryStream(); // must be expandable here

            src.CopyTo(dst, bufferSize: 3, length: 3);

            CollectionAssert.AreEqual(new byte[] { 1, 2, 3 }, dst.ToArray());
        }

        [TestMethod]
        public void CopyTo_ShouldFailWhenEOSIsReachedPrematurely()
        {
            using MemoryStream src = StreamOf(1, 2);
            using MemoryStream dst = new MemoryStream(); // must allow writing

            Assert.ThrowsExactly<EndOfStreamException>(() =>
                src.CopyTo(dst, bufferSize: 4, length: 3));
        }

        [TestMethod]
        public async Task CopyToAsync_ShouldCopyExactBytes()
        {
            await using MemoryStream src = StreamOf("cba"u8.ToArray());
            await using MemoryStream dst = new MemoryStream(); // expandable destination

            await src.CopyToAsync(dst, bufferSize: 10, length: 3, TestContext.CancellationToken);

            CollectionAssert.AreEqual("cba"u8.ToArray(), dst.ToArray());
        }

        [TestMethod]
        public async Task CopyToAsync_ShouldFailWhenEOSReachedPrematurely()
        {
            await using MemoryStream src = StreamOf("\t"u8.ToArray());
            await using MemoryStream dst = new MemoryStream(); // expandable

            await Assert.ThrowsExactlyAsync<EndOfStreamException>(async () =>
                await src.CopyToAsync(dst, bufferSize: 8, length: 2, TestContext.CancellationToken));
        }

        [TestMethod]
        public void CopyTo_ShouldReturnImmediately_WhenLengthIsZero()
        {
            using MemoryStream src = StreamOf(1, 2, 3);
            using MemoryStream dst = StreamOf();

            src.CopyTo(dst, bufferSize: 5, length: 0);

            Assert.IsEmpty(dst.ToArray());
        }

        public TestContext TestContext { get; set; }
    }
}
