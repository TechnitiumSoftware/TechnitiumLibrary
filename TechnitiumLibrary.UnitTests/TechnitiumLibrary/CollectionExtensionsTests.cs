/*
Technitium Library
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary
{
    [TestClass]
    public sealed class CollectionExtensionsTests
    {
        // -------------------------------------------------------------
        // Shuffle
        // -------------------------------------------------------------

        [TestMethod]
        public void Shuffle_ShouldRearrangeItems_WhenListHasMultipleElements()
        {
            // GIVEN
            int[] input = new[] { 1, 2, 3, 4, 5 };
            int[] original = input.ToArray();

            // WHEN
            input.Shuffle();

            // THEN
            Assert.HasCount(original.Length, input, "Shuffle must not remove items.");
            Assert.IsTrue(input.All(original.Contains), "Shuffle must retain all original items.");
        }

        [TestMethod]
        public void Shuffle_ShouldNotChangeSingleElementList()
        {
            // GIVEN
            int[] input = new[] { 42 };

            // WHEN
            input.Shuffle();

            // THEN
            Assert.AreEqual(42, input[0]);
        }

        [TestMethod]
        public void Shuffle_ShouldNotThrow_WhenEmpty()
        {
            // GIVEN
            int[] input = Array.Empty<int>();

            // WHEN
            input.Shuffle();

            // THEN
            Assert.IsEmpty(input);
        }

        // -------------------------------------------------------------
        // Convert (IReadOnlyList)
        // -------------------------------------------------------------

        [TestMethod]
        public void Convert_List_ShouldTransformElements()
        {
            // GIVEN
            IReadOnlyList<int> input = new ReadOnlyCollection<int>(new[] { 1, 2, 3 });

            // WHEN
            IReadOnlyList<int> result = input.Convert(x => x * 10);

            // THEN
            Assert.HasCount(3, result);
            Assert.AreEqual(10, result[0]);
            Assert.AreEqual(20, result[1]);
            Assert.AreEqual(30, result[2]);
        }

        [TestMethod]
        public void Convert_List_ShouldThrow_WhenArrayIsNull()
        {
            // GIVEN
            IReadOnlyList<int>? input = null;

            // WHEN + THEN
            Assert.ThrowsExactly<NullReferenceException>(
                () => input.Convert<int, int>(x => x * 10)
            );
        }

        // -------------------------------------------------------------
        // Convert (IReadOnlyCollection)
        // -------------------------------------------------------------

        [TestMethod]
        public void Convert_Collection_ShouldPreserveCount()
        {
            // GIVEN
            IReadOnlyCollection<string> input = new[] { "A", "BB", "CCC" };

            // WHEN
            IReadOnlyCollection<int> result = input.Convert(str => str.Length);

            // THEN
            Assert.HasCount(3, result);
        }

        [TestMethod]
        public void Convert_Collection_ShouldThrow_WhenCollectionIsNull()
        {
            // GIVEN
            IReadOnlyCollection<int> input = null;

            // WHEN + THEN
            Assert.ThrowsExactly<NullReferenceException>(
                () => input.Convert<int, int>(x => x * 10)
            );
        }

        [TestMethod]
        public void Convert_Collection_ShouldThrow_WhenConverterIsNull()
        {
            // GIVEN
            IReadOnlyCollection<int> input = new[] { 1, 2 };

            // WHEN + THEN
            Assert.ThrowsExactly<NullReferenceException>(
                () => input.Convert<int, int>(null)
            );
        }

        // -------------------------------------------------------------
        // ListEquals
        // -------------------------------------------------------------

        [TestMethod]
        public void ListEquals_ShouldReturnTrue_WhenSequencesMatchExactly()
        {
            // GIVEN
            int[] a = new[] { 1, 2, 3 };
            int[] b = new[] { 1, 2, 3 };

            // WHEN
            bool equal = a.ListEquals(b);

            // THEN
            Assert.IsTrue(equal);
        }

        [TestMethod]
        public void ListEquals_ShouldReturnFalse_WhenLengthDiffers()
        {
            // GIVEN
            int[] a = new[] { 1, 2 };
            int[] b = new[] { 1, 2, 3 };

            // WHEN
            bool equal = a.ListEquals(b);

            // THEN
            Assert.IsFalse(equal);
        }

        [TestMethod]
        public void ListEquals_ShouldReturnFalse_WhenElementDiffers()
        {
            // GIVEN
            int[] a = new[] { 1, 2, 3 };
            int[] b = new[] { 1, 9, 3 };

            // WHEN
            bool equal = a.ListEquals(b);

            // THEN
            Assert.IsFalse(equal);
        }

        [TestMethod]
        public void ListEquals_ShouldReturnFalse_WhenSecondIsNull()
        {
            // GIVEN
            string[] a = new[] { "X" };

            // WHEN
            bool equal = a.ListEquals(null);

            // THEN
            Assert.IsFalse(equal);
        }

        // -------------------------------------------------------------
        // HasSameItems
        // -------------------------------------------------------------

        [TestMethod]
        public void HasSameItems_ShouldReturnTrue_WhenSameElementsUnordered()
        {
            // GIVEN
            int[] a = new[] { 3, 1, 2 };
            int[] b = new[] { 2, 3, 1 };

            // WHEN
            bool equal = a.HasSameItems(b);

            // THEN
            Assert.IsTrue(equal);
        }

        [TestMethod]
        public void HasSameItems_ShouldReturnFalse_WhenDifferentItemsPresent()
        {
            // GIVEN
            int[] a = new[] { 1, 2, 3 };
            int[] b = new[] { 1, 2, 4 };

            // WHEN
            bool equal = a.HasSameItems(b);

            // THEN
            Assert.IsFalse(equal);
        }

        // -------------------------------------------------------------
        // GetArrayHashCode
        // -------------------------------------------------------------

        [TestMethod]
        public void GetArrayHashCode_ShouldReturnZero_WhenNull()
        {
            // WHEN
            int hash = CollectionExtensions.GetArrayHashCode<int>(null);

            // THEN
            Assert.AreEqual(0, hash);
        }

        [TestMethod]
        public void GetArrayHashCode_ShouldMatchRegardlessOfOrder()
        {
            // GIVEN
            int[] a = new[] { 10, 20, 30 };
            int[] b = new[] { 30, 10, 20 };

            // WHEN
            int hashA = a.GetArrayHashCode();
            int hashB = b.GetArrayHashCode();

            // THEN
            Assert.AreEqual(hashA, hashB, "XOR hash should not depend on order.");
        }
    }
}
