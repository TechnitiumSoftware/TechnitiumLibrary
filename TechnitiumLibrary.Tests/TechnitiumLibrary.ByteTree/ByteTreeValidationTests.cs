using TechnitiumLibrary.ByteTree;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.ByteTree
{
    public class ByteTreeValidationTests
    {
        [Fact]
        public void DuplicateAddThrows()
        {
            ByteTree<object> tree = new ByteTree<object>();
            byte[] key = new byte[] { 42 };
            tree.Add(key, new object());

            Assert.Throws<ArgumentException>(() => tree.Add(key, new object()));
        }

        [Fact]
        public void NullKeysThrow()
        {
            ByteTree<string> tree = new ByteTree<string>();

            Assert.Throws<ArgumentNullException>(() => tree.Add(null, "value"));
            Assert.Throws<ArgumentNullException>(() => tree.TryAdd(null, "value"));
            Assert.Throws<ArgumentNullException>(() => tree.ContainsKey(null));
            Assert.Throws<ArgumentNullException>(() => tree.TryGet(null, out _));
            Assert.Throws<ArgumentNullException>(() => tree.GetOrAdd(null, "value"));
            Assert.Throws<ArgumentNullException>(() => tree.AddOrUpdate(null, "value", (_, existing) => existing));
            Assert.Throws<ArgumentNullException>(() => tree.TryRemove(null, out _));
            Assert.Throws<ArgumentNullException>(() => tree.TryUpdate(null, "new", "old"));
            Assert.Throws<ArgumentNullException>(() => tree[null]);
        }

        [Fact]
        public void InvalidKeySpaceThrows()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new ByteTree<string>(-1));
            Assert.Throws<ArgumentOutOfRangeException>(() => new ByteTree<string>(257));
        }

        [Fact]
        public void RemoveMissingReturnsFalseAndDefaultValue()
        {
            ByteTree<string> tree = new ByteTree<string>();

            Assert.False(tree.TryRemove(new byte[] { 99 }, out string removed));
            Assert.Null(removed);
        }

        [Fact]
        public void CustomConverterNullKey_ReturnsFalseForTryMethods()
        {
            RejectingByteTree tree = new RejectingByteTree();

            Assert.False(tree.TryAdd("reject-add", "value"));
            Assert.False(tree.ContainsKey("reject-contains"));
            Assert.False(tree.TryGet("reject-get", out string value));
            Assert.Null(value);
            Assert.False(tree.TryRemove("reject-remove", out string removed));
            Assert.Null(removed);
            Assert.False(tree.TryUpdate("reject-update", "new", "old"));
        }
    }
}
