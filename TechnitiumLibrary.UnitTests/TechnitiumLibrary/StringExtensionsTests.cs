using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary
{
    [TestClass]
    public sealed class StringExtensionsTests
    {
        // -----------------------------
        // Split<T>
        // -----------------------------

        [TestMethod]
        public void Split_ShouldConvertItems_WhenParsingSucceeds()
        {
            // GIVEN
            const string input = "1, 2, 3";

            // WHEN
            int[] result = input.Split(int.Parse, ',');

            // THEN
            Assert.HasCount(3, result);
            Assert.AreEqual(1, result[0]);
            Assert.AreEqual(2, result[1]);
            Assert.AreEqual(3, result[2]);
        }

        [TestMethod]
        public void Split_ShouldRemoveEmptyEntries_AndTrim()
        {
            // GIVEN
            const string input = " 10 ; ; 20 ; 30 ";

            // WHEN
            int[] result = input.Split(int.Parse, ';');

            // THEN
            Assert.HasCount(3, result);
            Assert.AreEqual(10, result[0]);
            Assert.AreEqual(20, result[1]);
            Assert.AreEqual(30, result[2]);
        }

        [TestMethod]
        public void Split_ShouldThrow_WhenParserThrows()
        {
            // GIVEN
            const string input = "10, BAD";

            // WHEN–THEN
            Assert.ThrowsExactly<FormatException>(() => _ = input.Split(int.Parse, ','));
        }

        [TestMethod]
        public void Split_ShouldThrow_WhenStringIsNull()
        {
            // GIVEN
            const string? input = null;

            // WHEN–THEN
            Assert.ThrowsExactly<NullReferenceException>(() =>
                _ = input.Split(int.Parse, ','));
        }

        // -----------------------------
        // Join<T>
        // -----------------------------

        [TestMethod]
        public void Join_ShouldReturnCommaSeparatedValues()
        {
            // GIVEN
            int[] input = new[] { 1, 2, 3 };

            // WHEN
            string result = input.Join(',');

            // THEN
            Assert.AreEqual("1, 2, 3", result);
        }

        [TestMethod]
        public void Join_ShouldReturnNull_WhenCollectionEmpty()
        {
            // GIVEN
            int[] input = Array.Empty<int>();

            // WHEN
            string result = input.Join(',');

            // THEN
            Assert.IsNull(result);
        }

        [TestMethod]
        public void Join_ShouldThrow_WhenValuesIsNull()
        {
            // GIVEN
            int[]? input = null;

            // WHEN–THEN
            Assert.ThrowsExactly<NullReferenceException>(() => input.Join(','));
        }

        // -----------------------------
        // ParseColonHexString
        // -----------------------------

        [TestMethod]
        public void ParseColonHexString_ShouldReturnBytes_WhenValidHex()
        {
            // GIVEN
            const string input = "0A:FF:01";

            // WHEN
            byte[] result = input.ParseColonHexString();

            // THEN
            Assert.HasCount(3, result);
            Assert.AreEqual(0x0A, result[0]);
            Assert.AreEqual(0xFF, result[1]);
            Assert.AreEqual(0x01, result[2]);
        }

        [TestMethod]
        public void ParseColonHexString_ShouldThrow_WhenInvalidHex()
        {
            // GIVEN
            const string input = "GG:12";

            // WHEN–THEN
            Assert.ThrowsExactly<ArgumentException>(() =>
                _ = input.ParseColonHexString());
        }

        [TestMethod]
        public void ParseColonHexString_ShouldThrow_WhenValueNotHex()
        {
            // GIVEN
            const string input = "1K";

            // WHEN–THEN
            Assert.ThrowsExactly<ArgumentException>(() =>
                _ = input.ParseColonHexString());
        }

        [TestMethod]
        public void ParseColonHexString_ShouldThrow_WhenInputContainsEmptySegments()
        {
            // GIVEN
            const string input = "FF::AA";

            // WHEN–THEN
            Assert.ThrowsExactly<ArgumentException>(() =>
                _ = input.ParseColonHexString());
        }

        [TestMethod]
        public void ParseColonHexString_ShouldThrow_WhenValueIsNull()
        {
            // GIVEN
            const string? input = null;

            // WHEN–THEN
            Assert.ThrowsExactly<NullReferenceException>(() =>
                _ = input.ParseColonHexString());
        }

        [TestMethod]
        public void ParseColonHexString_ShouldSupportSingleSegment()
        {
            // GIVEN
            const string input = "FE";

            // WHEN
            byte[] result = input.ParseColonHexString();

            // THEN
            Assert.HasCount(1, result);
            Assert.AreEqual(0xFE, result[0]);
        }
    }
}
