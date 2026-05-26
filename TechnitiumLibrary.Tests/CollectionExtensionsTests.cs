using System;
using System.Collections.Generic;
using Xunit;

namespace TechnitiumLibrary.Tests
{
    public class CollectionExtensionsTests
    {
        [Fact]
        public void Convert_ListAndCollection()
        {
            var list = new List<int> { 1, 2, 3 };
            var converted = ((IReadOnlyList<int>)list).Convert(i => i * 2);
            Assert.Equal(new int[] { 2, 4, 6 }, converted);

            var set = new HashSet<int> { 4, 5 };
            var conv2 = ((IReadOnlyCollection<int>)set).Convert(i => i + 1);
            Assert.Contains(5, conv2);
        }

        [Fact]
        public void ListEqualsAndHasSameItems()
        {
            var a = new List<string> { "x", "y" };
            var b = new List<string> { "x", "y" };
            var c = new List<string> { "y", "x" };

            Assert.True(((IReadOnlyList<string>)a).ListEquals(b));
            Assert.False(((IReadOnlyList<string>)a).ListEquals(c));

            Assert.True(((IReadOnlyCollection<string>)a).HasSameItems(c));
        }

        [Fact]
        public void Interleave_MergesLists()
        {
            var l1 = new List<int> { 1, 3 };
            var l2 = new List<int> { 2, 4, 5 };
            var inter = ((IReadOnlyList<int>)l1).Interleave(l2);
            Assert.Equal(5, inter.Count);
            Assert.Equal(new int[] { 1, 2, 3, 4, 5 }, inter);
        }
    }
}
