using System;
using System.IO;
using Xunit;

namespace TechnitiumLibrary.Tests
{
    public class BinaryNumberTests
    {
        [Fact]
        public void ParseAndToString_Roundtrip()
        {
            var hex = "0a0b0c";
            var bn = BinaryNumber.Parse(hex);
            Assert.Equal(hex, bn.ToString());
        }

        [Fact]
        public void Clone_EqualsOriginal()
        {
            var data = new byte[] { 1, 2, 3 };
            var bn = new BinaryNumber(data);
            var clone = bn.Clone();
            Assert.Equal(bn, clone);
            Assert.NotSame(bn.Value, clone.Value);
        }

        [Fact]
        public void WriteTo_And_ReadFromStream()
        {
            var bytes = new byte[] { 0xAA, 0xBB };
            var bn = new BinaryNumber(bytes);

            using MemoryStream ms = new MemoryStream();
            bn.WriteTo(ms);
            ms.Position = 0;

            using BinaryReader br = new BinaryReader(ms);
            var read = new BinaryNumber(br);
            Assert.Equal(bn, read);
        }

        [Fact]
        public void BitwiseOperators_WorkAndCompare()
        {
            var a = new BinaryNumber(new byte[] { 0xFF, 0x00 });
            var b = new BinaryNumber(new byte[] { 0x0F, 0xFF });

            var or = a | b;
            var and = a & b;
            var xor = a ^ b;

            Assert.Equal(new BinaryNumber(new byte[] { 0xFF, 0xFF }), or);
            Assert.Equal(new BinaryNumber(new byte[] { 0x0F, 0x00 }), and);
            Assert.Equal(new BinaryNumber(new byte[] { 0xF0, 0xFF }), xor);

            Assert.True(a > b || a < b || a == b); // simple sanity
        }

        [Fact]
        public void CompareTo_DifferentLength_Throws()
        {
            var a = new BinaryNumber(new byte[] { 1, 2 });
            var b = new BinaryNumber(new byte[] { 1 });
            Assert.Throws<ArgumentException>(() => a.CompareTo(b));
        }

        [Fact]
        public void ShiftOperators_DoNotThrow()
        {
            var v = new BinaryNumber(new byte[] { 0x01, 0x02, 0x03 });
            var r1 = v >> 4;
            var r2 = v << 9;
            Assert.Equal(3, r1.Value.Length);
            Assert.Equal(3, r2.Value.Length);
        }
    }
}
