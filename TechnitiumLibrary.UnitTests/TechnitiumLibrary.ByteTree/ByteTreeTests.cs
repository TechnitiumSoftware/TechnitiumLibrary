using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using TechnitiumLibrary.ByteTree;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.ByteTree
{
    [TestClass]
    public sealed class ByteTreeTests
    {
        private static byte[] Key(params byte[] b) => b;

        // ---------------------------
        // ADD + GET
        // ---------------------------
        [TestMethod]
        public void Add_ShouldInsertValue_WhenKeyDoesNotExist()
        {
            // GIVEN
            ByteTree<string> tree = new ByteTree<string>();

            // WHEN
            tree.Add(Key(1, 2, 3), "value");

            // THEN
            Assert.AreEqual("value", tree[Key(1, 2, 3)]);
        }

        [TestMethod]
        public void Add_ShouldThrow_WhenKeyExists()
        {
            // GIVEN
            ByteTree<string> tree = new ByteTree<string>();
            tree.Add(Key(4), "first");

            // WHEN – THEN
            Assert.ThrowsExactly<ArgumentException>(() =>
                tree.Add(Key(4), "duplicate"));
        }

        [TestMethod]
        public void Add_ShouldThrow_WhenKeyNull()
        {
            ByteTree<string> tree = new ByteTree<string>();
            Assert.ThrowsExactly<ArgumentNullException>(() => tree.Add(null, "x"));
        }

        // ---------------------------
        // TryAdd
        // ---------------------------
        [TestMethod]
        public void TryAdd_ShouldReturnTrue_WhenKeyAdded()
        {
            ByteTree<string> tree = new ByteTree<string>();
            bool result = tree.TryAdd(Key(1), "v");
            Assert.IsTrue(result);
        }

        [TestMethod]
        public void TryAdd_ShouldReturnFalse_WhenKeyExists()
        {
            ByteTree<string> tree = new ByteTree<string>();
            tree.Add(Key(5), "initial");

            bool result = tree.TryAdd(Key(5), "other");

            Assert.IsFalse(result);
            Assert.AreEqual("initial", tree[Key(5)]);
        }

        [TestMethod]
        public void TryAdd_ShouldThrow_WhenKeyNull()
        {
            ByteTree<string> tree = new ByteTree<string>();
            Assert.ThrowsExactly<ArgumentNullException>(() => tree.TryAdd(null, "x"));
        }

        // ---------------------------
        // GET operations
        // ---------------------------
        [TestMethod]
        public void TryGet_ShouldReturnTrue_WhenKeyExists()
        {
            ByteTree<string> tree = new ByteTree<string>();
            tree.Add(Key(1, 2), "data");

            bool found = tree.TryGet(Key(1, 2), out string? value);

            Assert.IsTrue(found);
            Assert.AreEqual("data", value);
        }

        [TestMethod]
        public void TryGet_ShouldReturnFalse_WhenMissing()
        {
            ByteTree<string> tree = new ByteTree<string>();

            bool result = tree.TryGet(Key(9), out string? value);

            Assert.IsFalse(result);
            Assert.IsNull(value);
        }

        [TestMethod]
        public void TryGet_ShouldThrow_WhenNull()
        {
            ByteTree<string> tree = new ByteTree<string>();
            Assert.ThrowsExactly<ArgumentNullException>(() => tree.TryGet(null, out _));
        }

        // ---------------------------
        // ContainsKey
        // ---------------------------
        [TestMethod]
        public void ContainsKey_ShouldReturnTrue_WhenKeyPresent()
        {
            ByteTree<string> tree = new ByteTree<string>();
            tree.Add(Key(3, 3), "v");

            Assert.IsTrue(tree.ContainsKey(Key(3, 3)));
        }

        [TestMethod]
        public void ContainsKey_ShouldReturnFalse_WhenKeyMissing()
        {
            ByteTree<string> tree = new ByteTree<string>();
            Assert.IsFalse(tree.ContainsKey(Key(3, 100)));
        }

        [TestMethod]
        public void ContainsKey_ShouldThrow_WhenNull()
        {
            ByteTree<string> tree = new ByteTree<string>();
            Assert.ThrowsExactly<ArgumentNullException>(() => tree.ContainsKey(null));
        }

        // ---------------------------
        // Remove
        // ---------------------------
        [TestMethod]
        public void TryRemove_ShouldReturnTrue_WhenKeyExists()
        {
            ByteTree<string> tree = new ByteTree<string>();
            tree.Add(Key(10), "v");

            bool result = tree.TryRemove(Key(10), out string? removed);

            Assert.IsTrue(result);
            Assert.AreEqual("v", removed);
            Assert.IsFalse(tree.ContainsKey(Key(10)));
        }

        [TestMethod]
        public void TryRemove_ShouldReturnFalse_WhenMissing()
        {
            ByteTree<string> tree = new ByteTree<string>();
            bool result = tree.TryRemove(Key(11), out string? removed);

            Assert.IsFalse(result);
            Assert.IsNull(removed);
        }

        [TestMethod]
        public void TryRemove_ShouldThrow_WhenNull()
        {
            ByteTree<string> tree = new ByteTree<string>();
            Assert.ThrowsExactly<ArgumentNullException>(() => tree.TryRemove(null, out _));
        }

        // ---------------------------
        // TryUpdate
        // ---------------------------
        [TestMethod]
        public void TryUpdate_ShouldReplaceValue_WhenComparisonMatches()
        {
            ByteTree<string> tree = new ByteTree<string>();
            tree.Add(Key(5), "old");

            bool updated = tree.TryUpdate(Key(5), "new", "old");

            Assert.IsTrue(updated);
            Assert.AreEqual("new", tree[Key(5)]);
        }

        [TestMethod]
        public void TryUpdate_ShouldReturnFalse_WhenComparisonDoesNotMatch()
        {
            ByteTree<string> tree = new ByteTree<string>();
            tree.Add(Key(7), "original");

            bool updated = tree.TryUpdate(Key(7), "attempt", "different");

            Assert.IsFalse(updated);
            Assert.AreEqual("original", tree[Key(7)]);
        }

        // ---------------------------
        // AddOrUpdate
        // ---------------------------
        [TestMethod]
        public void AddOrUpdate_ShouldInsert_WhenMissing()
        {
            ByteTree<string> tree = new ByteTree<string>();

            string val = tree.AddOrUpdate(
                Key(1, 1),
                _ => "create",
                (_, old) => old + "update");

            Assert.AreEqual("create", val);
        }

        [TestMethod]
        public void AddOrUpdate_ShouldModify_WhenExists()
        {
            ByteTree<string> tree = new ByteTree<string>();
            tree.Add(Key(1, 2), "first");

            string updated = tree.AddOrUpdate(
                Key(1, 2),
                _ => "ignored",
                (_, old) => old + "_changed");

            Assert.AreEqual("first_changed", updated);
        }

        // ---------------------------
        // Indexer get/set
        // ---------------------------
        [TestMethod]
        public void Indexer_Get_ShouldReturnExactValue()
        {
            ByteTree<string> tree = new ByteTree<string>();
            tree.Add(Key(99), "stored");

            Assert.AreEqual("stored", tree[Key(99)]);
        }

        [TestMethod]
        public void Indexer_Set_ShouldOverwriteFormerValue()
        {
            ByteTree<string> tree = new ByteTree<string>();
            tree[Key(5, 5)] = "initial";

            tree[Key(5, 5)] = "updated";

            Assert.AreEqual("updated", tree[Key(5, 5)]);
        }

        [TestMethod]
        public void Indexer_Get_ShouldThrow_WhenMissingKey()
        {
            ByteTree<string> tree = new ByteTree<string>();
            Assert.ThrowsExactly<KeyNotFoundException>(() =>
                _ = tree[Key(8, 8)]);
        }

        [TestMethod]
        public void Indexer_ShouldThrow_WhenNullKey()
        {
            ByteTree<string> tree = new ByteTree<string>();
            Assert.ThrowsExactly<ArgumentNullException>(() => tree[null] = "x");
        }

        // ---------------------------
        // Enumeration
        // ---------------------------
        [TestMethod]
        public void Enumerator_ShouldYieldExistingValues()
        {
            ByteTree<string> tree = new ByteTree<string>();
            tree.Add(Key(1), "x");
            tree.Add(Key(2), "y");
            tree.Add(Key(3), "z");

            List<string> values = tree.ToList();

            Assert.HasCount(3, values);
            CollectionAssert.AreEquivalent(new[] { "x", "y", "z" }, values);
        }

        [TestMethod]
        public void ReverseEnumerable_ShouldYieldInReverseOrder()
        {
            ByteTree<string> tree = new ByteTree<string>();
            tree.Add(Key(0), "a");
            tree.Add(Key(1), "b");
            tree.Add(Key(255), "c");

            List<string> result = tree.GetReverseEnumerable().ToList();

            Assert.HasCount(3, result);
            Assert.AreEqual("c", result[0]); // last sorted key
            Assert.AreEqual("b", result[1]);
            Assert.AreEqual("a", result[2]);
        }

        // ---------------------------
        // Clear
        // ---------------------------
        [TestMethod]
        public void Clear_ShouldEraseAllData()
        {
            ByteTree<string> tree = new ByteTree<string>();
            tree.Add(Key(1), "x");
            tree.Add(Key(2), "y");

            tree.Clear();

            Assert.IsTrue(tree.IsEmpty);
            Assert.IsFalse(tree.ContainsKey(Key(1)));
        }
    }
}
