using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Threading.Tasks;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.IO
{
    [TestClass]
    public sealed class JointTests
    {
        private static async Task WaitForCopyCompletion()
        {
            // The copy tasks run asynchronously and Joint.Dispose() executes
            // when either side reaches EOF. Wait slightly longer than default buffering time.
            await Task.Delay(80);
        }

        // ---------------------------------------
        // Constructor and property access
        // ---------------------------------------

        [TestMethod]
        public void Constructor_ShouldStoreStreams()
        {
            // GIVEN
            MemoryStream s1 = new MemoryStream();
            MemoryStream s2 = new MemoryStream();

            // WHEN
            Joint joint = new Joint(s1, s2);

            // THEN
            Assert.AreSame(s1, joint.Stream1);
            Assert.AreSame(s2, joint.Stream2);
        }

        // ---------------------------------------
        // Data transfer behavior
        // ---------------------------------------

        [TestMethod]
        public async Task Start_ShouldCopyData_FromStream1ToStream2()
        {
            // GIVEN
            byte[] sourceData = new byte[] { 1, 2, 3, 4 };
            using MemoryStream s1 = new MemoryStream(sourceData);
            using MemoryStream s2 = new MemoryStream();
            using Joint joint = new Joint(s1, s2);

            // WHEN
            joint.Start();
            await WaitForCopyCompletion();

            // THEN
            byte[] result = s2.ToArray();
            CollectionAssert.AreEqual(sourceData, result);
        }

        [TestMethod]
        public async Task Start_ShouldCopyData_FromStream2ToStream1()
        {
            // GIVEN
            byte[] sourceData = new byte[] { 7, 8, 9 };
            using MemoryStream s1 = new MemoryStream();
            using MemoryStream s2 = new MemoryStream(sourceData);
            using Joint joint = new Joint(s1, s2);

            // WHEN
            joint.Start();
            await WaitForCopyCompletion();

            // THEN
            byte[] result = s2.ToArray();
            CollectionAssert.AreEqual(sourceData, result);
        }

        // ---------------------------------------
        // Empty stream scenarios
        // ---------------------------------------

        [TestMethod]
        public async Task Start_ShouldSupportEmptyStreams()
        {
            // GIVEN
            using MemoryStream s1 = new MemoryStream();
            using MemoryStream s2 = new MemoryStream();
            using Joint joint = new Joint(s1, s2);

            // WHEN
            joint.Start();
            await WaitForCopyCompletion();

            // THEN
            byte[] buff1 = s1.ToArray();
            byte[] buff2 = s2.ToArray();

            CollectionAssert.AreEqual(Array.Empty<byte>(), buff1);
            CollectionAssert.AreEqual(Array.Empty<byte>(), buff2);
        }

        // ---------------------------------------
        // Disposal semantics
        // ---------------------------------------

        [TestMethod]
        public async Task Dispose_ShouldCloseStreams()
        {
            // GIVEN
            MemoryStream s1 = new MemoryStream(new byte[] { 10 });
            MemoryStream s2 = new MemoryStream(new byte[] { 20 });
            Joint joint = new Joint(s1, s2);

            // WHEN
            joint.Dispose();
            await WaitForCopyCompletion();

            // THEN
            Assert.ThrowsExactly<ObjectDisposedException>(() => { _ = s1.Length; });
            Assert.ThrowsExactly<ObjectDisposedException>(() => { _ = s2.Length; });
        }

        [TestMethod]
        public void Dispose_ShouldBeIdempotent()
        {
            // GIVEN
            MemoryStream s1 = new MemoryStream();
            MemoryStream s2 = new MemoryStream();
            Joint joint = new Joint(s1, s2);

            // WHEN
            joint.Dispose();
            joint.Dispose();
            joint.Dispose(); // Should not throw

            // THEN
            Assert.IsTrue(true); // No exception was thrown
        }

        // ---------------------------------------
        // Disposal callback behavior
        // ---------------------------------------

        [TestMethod]
        public void Dispose_ShouldRaiseDisposingEvent()
        {
            // GIVEN
            using MemoryStream s1 = new MemoryStream();
            using MemoryStream s2 = new MemoryStream();
            Joint joint = new Joint(s1, s2);

            bool raised = false;
            joint.Disposing += (_, __) => raised = true;

            // WHEN
            joint.Dispose();

            // THEN
            Assert.IsTrue(raised);
        }

        // ---------------------------------------
        // Concurrency semantics
        // ---------------------------------------

        [TestMethod]
        public async Task Start_ShouldDisposeOnce_WhenBothDirectionsComplete()
        {
            // GIVEN
            using MemoryStream s1 = new MemoryStream(new byte[] { 1 });
            using MemoryStream s2 = new MemoryStream(new byte[] { 2 });

            using Joint joint = new Joint(s1, s2);

            int disposedCount = 0;
            joint.Disposing += (_, __) => disposedCount++;

            // WHEN
            joint.Start();
            await WaitForCopyCompletion();

            // THEN
            Assert.AreEqual(1, disposedCount, "Disposing must fire only once");
        }
    }
}
