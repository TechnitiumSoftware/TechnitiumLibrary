using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary
{
    [TestClass]
    public sealed class TaskExtensionsTests
    {
        // Helper allowing deterministic near-timeout simulation
        private static Task NeverCompletes(CancellationToken _) =>
            new TaskCompletionSource<object?>().Task;

        // ---------------------------------------------
        // TimeoutAsync (non-returning)
        // ---------------------------------------------

        [TestMethod]
        public async Task TimeoutAsync_ShouldComplete_WhenTaskFinishesBeforeTimeout()
        {
            // GIVEN
            Func<CancellationToken, Task> func = _ => Task.Delay(50, TestContext.CancellationToken);

            // WHEN-THEN
            await TaskExtensions.TimeoutAsync(func, timeout: 500, TestContext.CancellationToken);
        }

        [TestMethod]
        public async Task TimeoutAsync_ShouldThrowTimeoutException_WhenOperationExceedsTimeout()
        {
            // GIVEN
            Func<CancellationToken, Task> func = NeverCompletes;

            // WHEN-THEN
            await Assert.ThrowsExactlyAsync<TimeoutException>(() =>
                TaskExtensions.TimeoutAsync(func, timeout: 50, TestContext.CancellationToken));
        }

        [TestMethod]
        public async Task TimeoutAsync_ShouldThrowOriginalException_WhenTaskFails()
        {
            // GIVEN
            Func<CancellationToken, Task> func = _ => throw new InvalidOperationException("boom");

            // WHEN-THEN
            await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
                TaskExtensions.TimeoutAsync(func, timeout: 500, TestContext.CancellationToken));
        }

        [TestMethod]
        public async Task TimeoutAsync_ShouldThrowOperationCanceled_WhenRootTokenCancelled()
        {
            // GIVEN
            using CancellationTokenSource cts = new CancellationTokenSource();
            Func<CancellationToken, Task> func = NeverCompletes;

            // WHEN
            await cts.CancelAsync();

            // THEN
            await Assert.ThrowsExactlyAsync<OperationCanceledException>(() =>
                TaskExtensions.TimeoutAsync(func, timeout: 200, cancellationToken: cts.Token));
        }

        // ---------------------------------------------
        // TimeoutAsync<T> (generic)
        // ---------------------------------------------

        [TestMethod]
        public async Task TimeoutAsync_Generic_ShouldReturnValue_WhenCompletedWithinTimeout()
        {
            // GIVEN
            Func<CancellationToken, Task<int>> func = _ => Task.FromResult(42);

            // WHEN
            int result = await TaskExtensions.TimeoutAsync(func, timeout: 300, TestContext.CancellationToken);

            // THEN
            Assert.AreEqual(42, result);
        }

        [TestMethod]
        public async Task TimeoutAsync_Generic_ShouldThrowTimeoutException_WhenTaskRunsTooLong()
        {
            // GIVEN
            Func<CancellationToken, Task<int>> func = async _ =>
            {
                await Task.Delay(2000, TestContext.CancellationToken);
                return 5;
            };

            // WHEN-THEN
            await Assert.ThrowsExactlyAsync<TimeoutException>(() =>
                TaskExtensions.TimeoutAsync(func, timeout: 50, TestContext.CancellationToken));
        }

        [TestMethod]
        public async Task TimeoutAsync_Generic_ShouldPropagateSourceException()
        {
            // GIVEN
            Func<CancellationToken, Task<int>> func =
                _ => throw new FormatException("fail");

            // WHEN-THEN
            await Assert.ThrowsExactlyAsync<FormatException>(() =>
                TaskExtensions.TimeoutAsync(func, timeout: 500, TestContext.CancellationToken));
        }

        // ---------------------------------------------
        // Sync() Task
        // ---------------------------------------------

        [TestMethod]
        public void Sync_ShouldBlockUntilCompleted()
        {
            // GIVEN
            Task task = Task.Delay(50, TestContext.CancellationToken);

            // WHEN-THEN
            task.Sync();
        }

        [TestMethod]
        public void Sync_ShouldRethrowOriginalException()
        {
            // GIVEN
            Task task = Task.FromException(new InvalidOperationException("bad"));

            // WHEN-THEN
            Assert.ThrowsExactly<InvalidOperationException>(() => task.Sync());
        }

        [TestMethod]
        public void Sync_ShouldThrowNullReference_WhenTaskIsNull()
        {
            // GIVEN
            Task? task = null;

            // WHEN-THEN
            Assert.ThrowsExactly<NullReferenceException>(() => task!.Sync());
        }

        // ---------------------------------------------
        // Sync() Task<T>
        // ---------------------------------------------

        [TestMethod]
        public void Sync_Generic_ShouldReturnValue()
        {
            // GIVEN
            Task<int> task = Task.FromResult(123);

            // WHEN
            int result = task.Sync();

            // THEN
            Assert.AreEqual(123, result);
        }

        [TestMethod]
        public void Sync_Generic_ShouldSurfaceException()
        {
            // GIVEN
            Task<int> task = Task.FromException<int>(new FormatException());

            // WHEN-THEN
            Assert.ThrowsExactly<FormatException>(() => task.Sync());
        }

        [TestMethod]
        public void Sync_Generic_ShouldThrowOnNullTask()
        {
            // GIVEN
            Task<int>? task = null;

            // WHEN-THEN
            Assert.ThrowsExactly<NullReferenceException>(() => task!.Sync());
        }

        // ---------------------------------------------
        // Sync() ValueTask / ValueTask<T>
        // ---------------------------------------------

        [TestMethod]
        public void Sync_ValueTask_ShouldBlockUntilCompletion()
        {
            // GIVEN
            ValueTask vt = new ValueTask(Task.Delay(50, TestContext.CancellationToken));

            // WHEN-THEN
            vt.Sync();
        }

        [TestMethod]
        public void Sync_ValueTask_Generic_ShouldReturnValue()
        {
            // GIVEN
            ValueTask<int> vt = new ValueTask<int>(987);

            // WHEN
            int result = vt.Sync();

            // THEN
            Assert.AreEqual(987, result);
        }

        public TestContext TestContext { get; set; }
    }
}
