using System;
using Xunit;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary
{
    public class StringExtensionsTests
    {
        [Fact]
        public void Split_ParseIntArray()
        {
            var input = "1, 2,3";
            var arr = input.Split(s => int.Parse(s), ',');
            Assert.Equal(new int[] { 1, 2, 3 }, arr);
        }

        [Fact]
        public void Join_Enumerable()
        {
            var joined = new int[] { 1, 2, 3 }.Join(',');
            Assert.Equal("1, 2, 3", joined);
        }

        [Fact]
        public void ParseColonHexString_Valid()
        {
            var bytes = "0A:FF:10".ParseColonHexString();
            Assert.Equal(new byte[] { 0x0A, 0xFF, 0x10 }, bytes);
        }

        [Fact]
        public void ParseColonHexString_Invalid_Throws()
        {
            Assert.Throws<ArgumentException>(() => "0G:12".ParseColonHexString());
        }
    }
}
