using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Linq;
using System.Text;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.IO
{
    [TestClass]
    public sealed class BinaryReaderExtensionsTests
    {
        private static BinaryReader ReaderOf(params byte[] bytes)
        {
            return new BinaryReader(new MemoryStream(bytes));
        }

        // -----------------------------------------------
        // ReadLength()
        // -----------------------------------------------

        [TestMethod]
        public void ReadLength_ShouldReadSingleByteLengths()
        {
            // GIVEN
            BinaryReader reader = ReaderOf(0x05);

            // WHEN
            int length = reader.ReadLength();

            // THEN
            Assert.AreEqual(5, length);
            Assert.AreEqual(1, reader.BaseStream.Position);
        }

        [TestMethod]
        public void ReadLength_ShouldReadMultiByteBigEndianLengths()
        {
            // GIVEN
            // 0x82 => 2-byte length follows → value = 0x01 0x2C → 300 decimal
            BinaryReader reader = ReaderOf(0x82, 0x01, 0x2C);

            // WHEN
            int length = reader.ReadLength();

            // THEN
            Assert.AreEqual(300, length);
            Assert.AreEqual(3, reader.BaseStream.Position);
        }

        [TestMethod]
        public void ReadLength_ShouldThrow_WhenLengthPrefixTooLarge()
        {
            // GIVEN
            // lower 7 bits = 0x05, meaning "next 5 bytes", exceeding allowed 4
            BinaryReader reader = ReaderOf(0x85);

            // WHEN-THEN
            Assert.ThrowsExactly<IOException>(() => reader.ReadLength());
        }

        // -----------------------------------------------
        // ReadBuffer()
        // -----------------------------------------------

        [TestMethod]
        public void ReadBuffer_ShouldReturnBytes_WhenLengthPrefixed()
        {
            // GIVEN
            // length=3, then bytes 0xAA, 0xBB, 0xCC
            BinaryReader reader = ReaderOf(0x03, 0xAA, 0xBB, 0xCC);

            // WHEN
            byte[] data = reader.ReadBuffer();

            // THEN
            Assert.HasCount(3, data);
            CollectionAssert.AreEqual(new byte[] { 0xAA, 0xBB, 0xCC }, data);
        }

        // -----------------------------------------------
        // ReadShortString()
        // -----------------------------------------------

        [TestMethod]
        public void ReadShortString_ShouldDecodeUtf8StringCorrectly()
        {
            // GIVEN
            string text = "Hello";
            byte[] encoded = Encoding.UTF8.GetBytes(text);

            byte[] bytes = new byte[] { (byte)encoded.Length }.Concat(encoded).ToArray();
            BinaryReader reader = ReaderOf(bytes);

            // WHEN
            string result = reader.ReadShortString();

            // THEN
            Assert.AreEqual(text, result);
        }

        [TestMethod]
        public void ReadShortString_ShouldUseSpecifiedEncoding()
        {
            // GIVEN
            string text = "Å";
            Encoding encoding = Encoding.UTF32;
            byte[] encoded = encoding.GetBytes(text);

            byte[] bytes = new byte[] { (byte)encoded.Length }.Concat(encoded).ToArray();
            BinaryReader reader = ReaderOf(bytes);

            // WHEN
            string result = reader.ReadShortString(encoding);

            // THEN
            Assert.AreEqual(text, result);
        }

        // -----------------------------------------------
        // ReadDateTime()
        // -----------------------------------------------

        [TestMethod]
        public void ReadDateTime_ShouldConvertEpochMilliseconds()
        {
            // GIVEN
            DateTime expected = new DateTime(2024, 01, 01, 12, 00, 00, DateTimeKind.Utc);
            long millis = (long)(expected - DateTime.UnixEpoch).TotalMilliseconds;

            byte[] encoded = BitConverter.GetBytes(millis);

            // Normalize to little-endian, which BinaryReader expects
            if (!BitConverter.IsLittleEndian)
                Array.Reverse(encoded);

            BinaryReader reader = ReaderOf(encoded);

            // WHEN
            DateTime result = reader.ReadDateTime();

            // THEN
            Assert.AreEqual(expected, result);
        }
    }
}
