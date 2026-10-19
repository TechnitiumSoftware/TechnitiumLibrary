using TechnitiumLibrary.ByteTree;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.ByteTree
{
    public class ByteTreeMutationTests
    {
        [Fact]
        public void AddUpdateRemove_TracksValuesByByteKey()
        {
            ByteTree<string> tree = new ByteTree<string>();
            byte[] key = new byte[] { 1, 2, 3 };

            Assert.True(tree.IsEmpty);
            tree.Add(key, "one");

            Assert.False(tree.IsEmpty);
            Assert.True(tree.ContainsKey(key));
            Assert.Equal("one", tree[key]);

            string updated = tree.AddOrUpdate(key, "new", (_, existing) => existing + "-updated");
            Assert.Equal("one-updated", updated);
            Assert.Equal("one-updated", tree[key]);

            Assert.True(tree.TryRemove(key, out string removed));
            Assert.Equal("one-updated", removed);
            Assert.False(tree.ContainsKey(key));
        }

        [Fact]
        public void TryAddGetOrAddIndexerAndClear_CoverCommonBranches()
        {
            ByteTree<string> tree = new ByteTree<string>();
            byte[] key = new byte[] { 1, 2 };

            Assert.True(tree.TryAdd(key, "one"));
            Assert.False(tree.TryAdd(key, "duplicate"));
            Assert.True(tree.TryGet(key, out string value));
            Assert.Equal("one", value);
            Assert.Equal("one", tree.GetOrAdd(key, "two"));
            Assert.Equal("three", tree.GetOrAdd(new byte[] { 1, 3 }, _ => "three"));

            tree[key] = "updated";
            Assert.Equal("updated", tree[key]);

            tree.Clear();
            Assert.True(tree.IsEmpty);
            Assert.False(tree.TryGet(key, out _));
            Assert.Throws<KeyNotFoundException>(() => tree[key]);
        }

        [Fact]
        public void TryUpdate_UsesReferenceComparison()
        {
            ByteTree<object> tree = new ByteTree<object>();
            byte[] key = new byte[] { 1 };
            object original = new object();
            object replacement = new object();

            tree.Add(key, original);

            Assert.False(tree.TryUpdate(new byte[] { 2 }, replacement, original));
            Assert.False(tree.TryUpdate(key, replacement, new object()));
            Assert.True(tree.TryUpdate(key, replacement, original));
            Assert.Same(replacement, tree[key]);
        }

        [Fact]
        public void AddOrUpdate_AddFactoryBranchAndIndexerInsert()
        {
            ByteTree<string> tree = new ByteTree<string>();

            Assert.Equal("added", tree.AddOrUpdate(new byte[] { 7 }, _ => "added", (_, existing) => existing));
            tree[new byte[] { 8 }] = "inserted";

            Assert.Equal("added", tree[new byte[] { 7 }]);
            Assert.Equal("inserted", tree[new byte[] { 8 }]);
        }
    }
}
