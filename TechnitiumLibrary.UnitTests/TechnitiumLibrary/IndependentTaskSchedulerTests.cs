using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Threading;
using System.Threading.Tasks;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary
{
    [TestClass]
    public sealed class IndependentTaskSchedulerTests
    {
        [TestMethod]
        public async Task Task_ShouldExecute_WhenQueued()
        {
            // GIVEN
            using IndependentTaskScheduler scheduler = new IndependentTaskScheduler(maximumConcurrencyLevel: 1);
            TaskCompletionSource<bool> completion = new TaskCompletionSource<bool>();

            // WHEN
            Task t = new Task(_ => completion.SetResult(true), null);
            t.Start(scheduler);

            // THEN
            Assert.IsTrue(await completion.Task);
        }

        [TestMethod]
        public void MaximumConcurrencyLevel_ShouldMatchRequested()
        {
            // GIVEN
            using IndependentTaskScheduler scheduler = new IndependentTaskScheduler(3);

            // WHEN
            int level = scheduler.MaximumConcurrencyLevel;

            // THEN
            Assert.AreEqual(3, level);
        }

        [TestMethod]
        public async Task Tasks_ShouldRunInParallel_WhenConcurrencyGreaterThanOne()
        {
            // GIVEN
            using IndependentTaskScheduler scheduler = new IndependentTaskScheduler(maximumConcurrencyLevel: 2);
            TaskCompletionSource<bool> parallelStarted = new TaskCompletionSource<bool>();
            int runningCount = 0;

            Task Body() =>
                Task.Run(() =>
                {
                    if (Interlocked.Increment(ref runningCount) == 2)
                    {
                        parallelStarted.SetResult(true);
                    }
                    Thread.Sleep(40);
                });

            // WHEN
            _ = Task.Factory.StartNew(() => Body(), CancellationToken.None, TaskCreationOptions.None, scheduler).Unwrap();
            _ = Task.Factory.StartNew(() => Body(), CancellationToken.None, TaskCreationOptions.None, scheduler).Unwrap();

            // THEN
            Assert.IsTrue(await parallelStarted.Task);
        }

        [TestMethod]
        public void LongRunningOption_ShouldExecuteOnDedicatedThread()
        {
            // GIVEN
            using IndependentTaskScheduler scheduler = new IndependentTaskScheduler(1);
            int factoryThreadId = Thread.CurrentThread.ManagedThreadId;
            int schedulerThreadId = -1;

            // WHEN
            Task task = new Task(
                _ => schedulerThreadId = Thread.CurrentThread.ManagedThreadId,
                null,
                TaskCreationOptions.LongRunning);

            task.Start(scheduler);
            task.Wait();

            // THEN
            Assert.AreNotEqual(factoryThreadId, schedulerThreadId);
        }

        [TestMethod]
        public async Task InlineExecution_ShouldRun_WhenCalledInsideSchedulerThread()
        {
            // GIVEN
            using IndependentTaskScheduler scheduler = new IndependentTaskScheduler(1);

            TaskCompletionSource<bool> executedInline = new TaskCompletionSource<bool>();

            // WHEN
            Task driver = new Task(() =>
            {
                // Attempt inline execution from scheduler thread
                Task child = new Task(() => executedInline.SetResult(true));
                // This will execute inline because we are already inside scheduler thread
                child.RunSynchronously(TaskScheduler.Current);
            });

            // Run the driver task inside scheduler
            driver.Start(scheduler);
            await driver;

            // THEN
            Assert.IsTrue(await executedInline.Task, "Task must execute inline in scheduler thread.");
        }

        [TestMethod]
        public void Dispose_ShouldPreventFutureExecution()
        {
            // GIVEN
            IndependentTaskScheduler scheduler = new IndependentTaskScheduler(1);
            scheduler.Dispose();
            Task task = new Task(() => { });

            // WHEN
            Task continuation = Task.Factory.StartNew(
                () => task.Start(scheduler),
                CancellationToken.None,
                TaskCreationOptions.None,
                TaskScheduler.Default);

            continuation.Wait();

            // THEN
            Assert.IsFalse(task.IsCompleted);
        }

        [TestMethod]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "MSTEST0032:Assertion condition is always true", Justification = "Double Dispose must not throw")]
        public void Dispose_CanBeCalledMultipleTimes_Safely()
        {
            // GIVEN
            IndependentTaskScheduler scheduler = new IndependentTaskScheduler();

            // WHEN
            scheduler.Dispose();
            scheduler.Dispose();

            // THEN
            Assert.IsTrue(true); // simply must not throw
        }
    }
}
