using System;
using System.Threading.Tasks;
using Xunit;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary
{
    public class IndependentTaskSchedulerTests
    {
        [Fact]
        public async Task TaskScheduled_OnSchedulerExecutes()
        {
            using var scheduler = new IndependentTaskScheduler(1);
            var tcs = new TaskCompletionSource<int>();

            await Task.Factory.StartNew(() =>
            {
                tcs.SetResult(5);
            }, System.Threading.CancellationToken.None, TaskCreationOptions.None, scheduler);

            var result = await tcs.Task.TimeoutAfter(1000);
            Assert.Equal(5, result);
        }

        [Fact]
        public void MaximumConcurrencyLevel_Property()
        {
            using var scheduler = new IndependentTaskScheduler(3);
            Assert.Equal(3, scheduler.MaximumConcurrencyLevel);
        }

        [Fact]
        public async Task LongRunningTask_ExecutesOnDedicatedThread()
        {
            using IndependentTaskScheduler scheduler = new IndependentTaskScheduler(maximumConcurrencyLevel: 1);
            Task<int> task = Task.Factory.StartNew(
                () => Environment.CurrentManagedThreadId,
                System.Threading.CancellationToken.None,
                TaskCreationOptions.LongRunning,
                scheduler);

            Assert.True(await task.TimeoutAfter(1000) > 0);
        }

        [Fact]
        public void Dispose_IsIdempotent()
        {
            IndependentTaskScheduler scheduler = new IndependentTaskScheduler(maximumConcurrencyLevel: 1);

            scheduler.Dispose();
            scheduler.Dispose();

            Assert.Equal(1, scheduler.MaximumConcurrencyLevel);
        }
    }
}

// reuse TestHelpers.TimeoutAfter from TaskPoolTests
