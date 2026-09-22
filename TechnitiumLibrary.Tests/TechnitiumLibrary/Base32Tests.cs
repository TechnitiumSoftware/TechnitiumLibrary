using System;
using System.Linq;
using Xunit;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary
{
    public class Base32Tests
    {
        [Fact]
        public void Roundtrip_Base32_WithPadding()
        {
            byte[] data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
            string encoded = Base32.ToBase32String(data);
            byte[] decoded = Base32.FromBase32String(encoded);
            Assert.Equal(data, decoded);
        }

        [Fact]
        public void Roundtrip_Base32_WithoutPadding()
        {
            byte[] data = new byte[] { 10, 20, 30 };
            string encoded = Base32.ToBase32String(data, skipPadding: true);
            Assert.DoesNotContain("=", encoded);
            byte[] decoded = Base32.FromBase32String(encoded);
            Assert.Equal(data, decoded);
        }

        [Fact]
        public void Base32Hex_Roundtrip()
        {
            var data = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
            var enc = Base32.ToBase32HexString(data);
            var dec = Base32.FromBase32HexString(enc);
            Assert.Equal(data, dec);
        }

        [Fact]
        public void FromBase32_InvalidPadding_Throws()
        {
            // The implementation may throw different exception types for malformed input; assert that it fails.
            Assert.ThrowsAny<Exception>(() => Base32.FromBase32String("====="));
        }

        [Theory]
        [InlineData(1, "AE======")]
        [InlineData(2, "AEBA====")]
        [InlineData(3, "AEBAG===")]
        [InlineData(4, "AEBAGBA=")]
        [InlineData(5, "AEBAGBAF")]
        public void ToBase32String_CoversAllPaddingLengths(int length, string expected)
        {
            byte[] data = Enumerable.Range(1, length).Select(i => (byte)i).ToArray();

            Assert.Equal(expected, Base32.ToBase32String(data));
            Assert.Equal(expected.TrimEnd('='), Base32.ToBase32String(data, skipPadding: true));
            Assert.Equal(data, Base32.FromBase32String(expected));
            Assert.Equal(data, Base32.FromBase32String(expected.TrimEnd('=')));
        }

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(5)]
        public void Base32Hex_CoversAllPaddingLengths(int length)
        {
            byte[] data = Enumerable.Range(1, length).Select(i => (byte)i).ToArray();
            string encoded = Base32.ToBase32HexString(data);

            Assert.Equal(data, Base32.FromBase32HexString(encoded));
            Assert.Equal(data, Base32.FromBase32HexString(encoded.TrimEnd('=')));
        }

        [Fact]
        public void FromBase32String_SingleCharacterThrowsIndexOutOfRange()
        {
            Assert.Throws<IndexOutOfRangeException>(() => Base32.FromBase32String("A"));
        }

        [Theory]
        [InlineData("AA==")]
        [InlineData("AAA")]
        [InlineData("AAAAAA")]
        public void FromBase32String_InvalidLengthsThrow(string value)
        {
            Assert.ThrowsAny<Exception>(() => Base32.FromBase32String(value));
        }
    }
}
