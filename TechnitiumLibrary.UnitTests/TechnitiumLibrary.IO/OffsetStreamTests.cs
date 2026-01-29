using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.IO
{
    [TestClass]
    public sealed class OffsetStreamTests
    {
        public TestContext TestContext { get; set; } = null!;


        // ------------------------------------------------------
        // CONSTRUCTION & BASIC METADATA
        // ------------------------------------------------------

        [TestMethod]
        public void Constructor_ShouldExposeCorrectBasicProperties()
        {
            // GIVEN
            using MemoryStream source = new MemoryStream(new byte[] { 1, 2, 3, 4, 5 }, writable: true);

            // WHEN
            using OffsetStream offsetStream = new OffsetStream(source, offset: 1, length: 3);

            // THEN
            Assert.AreEqual(3, offsetStream.Length);
            Assert.AreEqual(0, offsetStream.Position);
            Assert.IsTrue(offsetStream.CanRead);
            Assert.IsTrue(offsetStream.CanSeek);
        }

        [TestMethod]
        public void Constructor_ShouldRespectReadOnlyFlag()
        {
            // GIVEN
            using MemoryStream source = new MemoryStream(new byte[10], writable: true);

            // WHEN
            using OffsetStream offsetStream = new OffsetStream(source, readOnly: true);

            // THEN
            Assert.IsFalse(offsetStream.CanWrite);
        }

        // ------------------------------------------------------
        // READ OPERATIONS
        // ------------------------------------------------------

        [TestMethod]
        public void Read_ShouldReturnSegmentWithinBounds()
        {
            // GIVEN
            using MemoryStream source = new MemoryStream(new byte[] { 10, 20, 30, 40, 50 }, writable: true);
            using OffsetStream offsetStream = new OffsetStream(source, offset: 1, length: 3);

            byte[] buffer = new byte[10];

            // WHEN
            int readCount = offsetStream.Read(buffer, 0, 10);

            // THEN
            Assert.AreEqual(3, readCount);
            CollectionAssert.AreEqual(new byte[] { 20, 30, 40 }, buffer[..3]);
        }

        [TestMethod]
        public void Read_ShouldReturnZero_WhenPastLength()
        {
            // GIVEN
            using MemoryStream source = new MemoryStream(new byte[] { 1, 2, 3, 4 }, writable: true);
            using OffsetStream offsetStream = new OffsetStream(source, offset: 2, length: 1);

            byte[] buffer = new byte[5];
            offsetStream.Position = 1;

            // WHEN
            int count = offsetStream.Read(buffer, 0, 5);

            // THEN
            Assert.AreEqual(0, count);
        }

        [TestMethod]
        public void ReadAsync_ShouldReturnCorrectData()
        {
            // GIVEN
            using MemoryStream source = new MemoryStream(new byte[] { 9, 8, 7, 6 }, writable: true);
            using OffsetStream offsetStream = new OffsetStream(source, offset: 1, length: 2);
            byte[] buffer = new byte[10];

            // WHEN
            int count = offsetStream.ReadAsync(buffer, 0, 10, TestContext.CancellationToken).Result;

            // THEN
            Assert.AreEqual(2, count);
            CollectionAssert.AreEqual(new byte[] { 8, 7 }, buffer[..2]);
        }

        // ------------------------------------------------------
        // WRITE OPERATIONS
        // ------------------------------------------------------

        [TestMethod]
        public void Write_ShouldPlaceDataAtOffset()
        {
            // GIVEN
            using MemoryStream source = new MemoryStream(new byte[] { 1, 2, 3, 4 }, writable: true);
            using OffsetStream offsetStream = new OffsetStream(source, offset: 1, length: 2);

            // WHEN
            offsetStream.Write("23"u8.ToArray(), 0, 2);

            // THEN
            CollectionAssert.AreEqual(new byte[] { 1, 50, 51, 4 }, source.ToArray());
        }

        [TestMethod]
        public void Write_ShouldExtendLength()
        {
            // GIVEN
            using MemoryStream source = new MemoryStream(new byte[] { 1, 2, 3 }, writable: true);
            using OffsetStream offsetStream = new OffsetStream(source, offset: 0, length: 2);

            // WHEN
            offsetStream.Position = 2;
            offsetStream.Write("\t"u8.ToArray(), 0, 1);

            // THEN
            Assert.AreEqual(3, offsetStream.Length);
        }

        [TestMethod]
        public void Write_ShouldThrow_WhenReadOnly()
        {
            // GIVEN
            using MemoryStream source = new MemoryStream(new byte[] { 1, 2, 3 }, writable: true);
            using OffsetStream offsetStream = new OffsetStream(source, readOnly: true);

            // WHEN–THEN
            Assert.ThrowsExactly<InvalidOperationException>(() =>
                offsetStream.Write(new byte[] { 0 }, 0, 1));
        }

        // ------------------------------------------------------
        // SEEK OPERATIONS
        // ------------------------------------------------------

        [TestMethod]
        public void Seek_ShouldMoveWithinValidRange()
        {
            // GIVEN
            using MemoryStream source = new MemoryStream(new byte[] { 1, 2, 3, 4 }, writable: true);
            using OffsetStream offsetStream = new OffsetStream(source, offset: 0, length: 4);

            // WHEN
            long newPos = offsetStream.Seek(2, SeekOrigin.Begin);

            // THEN
            Assert.AreEqual(2, newPos);
            Assert.AreEqual(2, offsetStream.Position);
        }

        [TestMethod]
        public void Seek_ShouldThrow_WhenSeekingPastEnd()
        {
            // GIVEN
            using MemoryStream source = new MemoryStream(new byte[] { 1, 2, 3 }, writable: true);
            using OffsetStream offsetStream = new OffsetStream(source, offset: 0, length: 3);

            // WHEN–THEN
            Assert.ThrowsExactly<EndOfStreamException>(() =>
                offsetStream.Seek(4, SeekOrigin.Begin));
        }

        // ------------------------------------------------------
        // DISPOSAL OWNERSHIP
        // ------------------------------------------------------

        [TestMethod]
        public void Dispose_ShouldCloseBaseStream_WhenOwnsStream()
        {
            // GIVEN
            using MemoryStream source = new MemoryStream(new byte[] { 1 }, writable: true);
            using OffsetStream offsetStream = new OffsetStream(source, ownsStream: true);

            // WHEN
            offsetStream.Dispose();

            // THEN
            Assert.ThrowsExactly<ObjectDisposedException>(() => source.ReadByte());
        }

        [TestMethod]
        public void Dispose_ShouldNotCloseBaseStream_WhenNotOwned()
        {
            // GIVEN
            using MemoryStream source = new MemoryStream(new byte[] { 1 }, writable: true);
            using OffsetStream offsetStream = new OffsetStream(source, ownsStream: false);

            // WHEN
            offsetStream.Dispose();

            // THEN
            Assert.AreEqual(1, source.ReadByte());
        }

        // ------------------------------------------------------
        // WRITETO & WRITETOASYNC
        // ------------------------------------------------------

        [TestMethod]
        public void WriteTo_ShouldCopyOnlyOffsetRange()
        {
            // GIVEN
            using MemoryStream source = new MemoryStream(new byte[] { 10, 20, 30, 40 }, writable: true);
            using OffsetStream offsetStream = new OffsetStream(source, offset: 1, length: 2);
            using MemoryStream target = new MemoryStream();

            // WHEN
            offsetStream.WriteTo(target);

            // THEN
            CollectionAssert.AreEqual(new byte[] { 20, 30 }, target.ToArray());
        }

        [TestMethod]
        public async Task WriteToAsync_ShouldCopyOnlyOffsetRange()
        {
            // GIVEN
            using MemoryStream source = new MemoryStream("2<F"u8.ToArray(), writable: true);
            using OffsetStream offsetStream = new OffsetStream(source, offset: 1, length: 2);
            using MemoryStream target = new MemoryStream();

            // WHEN
            await offsetStream.WriteToAsync(target);

            // THEN
            CollectionAssert.AreEqual("<F"u8.ToArray(), target.ToArray());
        }
    }
}
