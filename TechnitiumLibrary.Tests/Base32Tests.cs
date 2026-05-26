using System;
using Xunit;

namespace TechnitiumLibrary.Tests
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
    }
}
