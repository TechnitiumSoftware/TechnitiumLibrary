using System;
using System.IO;
using Xunit;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary
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

        [Fact]
        public void StaticFactories_CreateExpectedLengthsAndValues()
        {
            Assert.Equal(20, BinaryNumber.GenerateRandomNumber160().Value.Length);
            Assert.Equal(32, BinaryNumber.GenerateRandomNumber256().Value.Length);
            Assert.Equal(20, BinaryNumber.MaxValueNumber160().Value.Length);
            Assert.All(BinaryNumber.MaxValueNumber160().Value, b => Assert.Equal(0xFF, b));

            byte[] source = new byte[] { 9, 8, 7, 6 };
            BinaryNumber clone = BinaryNumber.Clone(source, 1, 2);
            Assert.Equal(new byte[] { 8, 7 }, clone.Value);
            Assert.NotSame(source, clone.Value);
        }

        [Fact]
        public void StaticEquals_CoversReferenceNullLengthAndByteMismatch()
        {
            byte[] value = new byte[] { 1, 2 };

            Assert.True(BinaryNumber.Equals(value, value));
            Assert.False(BinaryNumber.Equals(value, null));
            Assert.False(BinaryNumber.Equals(null, value));
            Assert.False(BinaryNumber.Equals(value, new byte[] { 1 }));
            Assert.False(BinaryNumber.Equals(value, new byte[] { 1, 3 }));
            Assert.True(BinaryNumber.Equals(value, new byte[] { 1, 2 }));
        }

        [Fact]
        public void EqualityComparisonAndHashCode_CoverBranches()
        {
            BinaryNumber a = new BinaryNumber(new byte[] { 1, 2 });
            BinaryNumber same = new BinaryNumber(new byte[] { 1, 2 });
            BinaryNumber smaller = new BinaryNumber(new byte[] { 1, 1 });
            BinaryNumber larger = new BinaryNumber(new byte[] { 1, 3 });

            Assert.True(a.Equals((object)same));
            Assert.False(a.Equals((object)"not binary"));
            Assert.False(a.Equals(null!));
            Assert.Equal(0, a.CompareTo(same));
            Assert.True(a.CompareTo(smaller) > 0);
            Assert.True(a.CompareTo(larger) < 0);
            Assert.Equal(a.GetHashCode(), same.GetHashCode());
            BinaryNumber sameReference = a;
            Assert.True(a == sameReference);
            Assert.False(a != sameReference);
        }

        [Fact]
        public void StreamConstructor_ReadsBinaryNumber()
        {
            BinaryNumber expected = new BinaryNumber(new byte[] { 4, 5, 6 });
            using MemoryStream stream = new MemoryStream();
            expected.WriteTo(stream);
            stream.Position = 0;

            BinaryNumber actual = new BinaryNumber((Stream)stream);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public void RelationalOperators_CoverEqualLessGreaterAndLengthMismatch()
        {
            BinaryNumber a = new BinaryNumber(new byte[] { 1, 2 });
            BinaryNumber same = new BinaryNumber(new byte[] { 1, 2 });
            BinaryNumber smaller = new BinaryNumber(new byte[] { 1, 1 });
            BinaryNumber larger = new BinaryNumber(new byte[] { 1, 3 });
            BinaryNumber differentLength = new BinaryNumber(new byte[] { 1 });

            Assert.True(a == same);
            Assert.False(a != same);
            Assert.True(a != smaller);
            Assert.True(smaller < a);
            Assert.False(a < smaller);
            Assert.False(a < same);
            Assert.True(larger > a);
            Assert.False(a > larger);
            Assert.False(a > same);
            Assert.True(smaller <= a);
            Assert.True(a <= same);
            Assert.False(larger <= a);
            Assert.True(larger >= a);
            Assert.True(a >= same);
            Assert.False(smaller >= a);

            Assert.Throws<ArgumentException>(() => _ = a | differentLength);
            Assert.Throws<ArgumentException>(() => _ = a & differentLength);
            Assert.Throws<ArgumentException>(() => _ = a ^ differentLength);
            Assert.Throws<ArgumentException>(() => _ = a < differentLength);
            Assert.Throws<ArgumentException>(() => _ = a > differentLength);
            Assert.Throws<ArgumentException>(() => _ = a <= differentLength);
            Assert.Throws<ArgumentException>(() => _ = a >= differentLength);
        }

        [Fact]
        public void ShiftAndNotOperators_ProduceExpectedValues()
        {
            BinaryNumber value = new BinaryNumber(new byte[] { 0x12, 0x34 });

            Assert.Equal(new BinaryNumber(new byte[] { 0x01, 0x23 }), value >> 4);
            Assert.Equal(new BinaryNumber(new byte[] { 0x00, 0x12 }), value >> 8);
            Assert.Equal(new BinaryNumber(new byte[] { 0x23, 0x40 }), value << 4);
            Assert.Equal(new BinaryNumber(new byte[] { 0x34, 0x00 }), value << 8);
            Assert.Equal(new BinaryNumber(new byte[] { 0xED, 0xCB }), ~value);
        }
    }
}
