using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Threading.Tasks;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary
{
    [TestClass]
    public sealed class TaskPoolTests
    {
        [TestMethod]
        public async Task TryQueueTask_ShouldExecuteQueuedTask()
        {
            // GIVEN
            TaskPool pool = new TaskPool(queueSize: 10, maximumConcurrencyLevel: 2);
            TaskCompletionSource<bool> completer = new TaskCompletionSource<bool>();

            // WHEN
            bool queued = pool.TryQueueTask(_ =>
            {
                completer.SetResult(true);
                return Task.CompletedTask;
            });

            // THEN
            Assert.IsTrue(queued, "Task should be accepted into queue.");
            Assert.IsTrue(await completer.Task, "Task must execute.");
        }

        [TestMethod]
        public async Task ShouldProcessMultipleTasksConcurrently_WhenAllowed()
        {
            // GIVEN
            int parallelism = Environment.ProcessorCount;
            TaskPool pool = new TaskPool(queueSize: 64, maximumConcurrencyLevel: parallelism);

            int counter = 0;
            TaskCompletionSource<bool> completion = new TaskCompletionSource<bool>();
            object lockObj = new object();

            int total = parallelism;

            // WHEN
            for (int i = 0; i < total; i++)
            {
                pool.TryQueueTask(_ =>
                {
                    lock (lockObj)
                        counter++;

                    if (counter == total)
                        completion.SetResult(true);

                    return Task.CompletedTask;
                });
            }

            // THEN
            Assert.IsTrue(await completion.Task, "All tasks must execute.");
            Assert.AreEqual(total, counter, "All queued tasks must run.");
        }

        [TestMethod]
        public async Task TasksShouldStopAfterDispose()
        {
            // GIVEN
            TaskPool pool = new TaskPool(queueSize: 10, maximumConcurrencyLevel: 1);

            TaskCompletionSource<bool> executedBeforeDispose = new TaskCompletionSource<bool>();
            bool wasExecutedAfterDispose = false;

            pool.TryQueueTask(_ =>
            {
                executedBeforeDispose.SetResult(true);
                return Task.CompletedTask;
            });

            await executedBeforeDispose.Task;

            // WHEN
            pool.Dispose();
            bool acceptedPostDispose = pool.TryQueueTask(_ =>
            {
                wasExecutedAfterDispose = true;
                return Task.CompletedTask;
            });

            // THEN
            Assert.IsFalse(acceptedPostDispose, "After disposal, queue must reject writes.");
            Assert.IsFalse(wasExecutedAfterDispose, "Tasks queued after Dispose must not run.");
        }

        [TestMethod]
        public void Ctor_ShouldUseDefaultConcurrency_WhenValueIsLessThanOne()
        {
            // GIVEN + WHEN
            TaskPool pool = new TaskPool(queueSize: 10, maximumConcurrencyLevel: -1);

            // THEN
            Assert.IsGreaterThanOrEqualTo(1,
pool.MaximumConcurrencyLevel, "Concurrency must fallback to processor count.");
        }

        [TestMethod]
        public async Task TaskShouldReceiveStateObject()
        {
            // GIVEN
            TaskPool pool = new TaskPool();
            TaskCompletionSource<bool> completion = new TaskCompletionSource<bool>();

            string expectedState = "STATE";
            string? capturedState = default(string);

            // WHEN
            pool.TryQueueTask(obj =>
            {
                capturedState = obj as string;
                completion.SetResult(true);
                return Task.CompletedTask;
            }, expectedState);

            await completion.Task;

            // THEN
            Assert.AreEqual(expectedState, capturedState, "State parameter must propagate through execution.");
        }

        [TestMethod]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "MSTEST0032:Assertion condition is always true", Justification = "Multiple Dispose must not throw")]
        public void DisposeMustBeIdempotent()
        {
            // GIVEN
            TaskPool pool = new TaskPool();

            // WHEN
            pool.Dispose();
            pool.Dispose();
            pool.Dispose();

            // THEN
            Assert.IsTrue(true, "Dispose must not throw.");
        }
    }
}
