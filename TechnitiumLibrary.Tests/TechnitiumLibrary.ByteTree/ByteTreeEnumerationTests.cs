using TechnitiumLibrary.ByteTree;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.ByteTree
{
    public class ByteTreeEnumerationTests
    {
        [Fact]
        public void EnumeratesInKeyOrderAndReverseKeyOrder()
        {
            ByteTree<string> tree = new ByteTree<string>();
            tree.Add(new byte[] { 2 }, "two");
            tree.Add(new byte[] { 1 }, "one");
            tree.Add(new byte[] { 1, 1 }, "one-one");

            Assert.Equal(new[] { "one", "one-one", "two" }, tree.ToArray());
            Assert.Equal(new[] { "two", "one-one", "one" }, tree.GetReverseEnumerable().ToArray());
        }

        [Fact]
        public void NonGenericEnumerator_CurrentResetAndFinishedState_Work()
        {
            ByteTree<string> tree = new ByteTree<string>();

            Assert.Empty(((System.Collections.IEnumerable)tree).Cast<object>());
            tree.Add(new byte[] { 1 }, "one");

            System.Collections.IEnumerator enumerator = ((System.Collections.IEnumerable)tree).GetEnumerator();
            Assert.Null(enumerator.Current);
            Assert.True(enumerator.MoveNext());
            Assert.Equal("one", enumerator.Current);
            enumerator.Reset();
            Assert.True(enumerator.MoveNext());
            Assert.Equal("one", enumerator.Current);
            Assert.False(enumerator.MoveNext());
            Assert.Null(enumerator.Current);
        }

        [Fact]
        public void DeepStemEnumeration_CoversNestedTraversal()
        {
            ByteTree<string> tree = new ByteTree<string>();
            tree.Add(new byte[] { 1, 1, 1 }, "a");
            tree.Add(new byte[] { 1, 1, 2 }, "b");
            tree.Add(new byte[] { 1, 2 }, "c");
            tree.Add(new byte[] { 2 }, "d");

            Assert.Equal(new[] { "a", "b", "c", "d" }, tree.ToArray());
            Assert.Equal(new[] { "d", "c", "b", "a" }, tree.GetReverseEnumerable().ToArray());
        }
    }
}
