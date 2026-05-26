using System;
using System.Threading.Tasks;
using Xunit;

namespace TechnitiumLibrary.Tests
{
    public class IndependentTaskSchedulerTests
    {
        [Fact]
        public async Task TaskScheduled_OnSchedulerExecutes()
        {
            using var scheduler = new IndependentTaskScheduler(1);
            var tcs = new TaskCompletionSource<int>();

            Task.Factory.StartNew(async () =>
            {
                tcs.SetResult(5);
                await Task.CompletedTask;
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
    }
}

// reuse TestHelpers.TimeoutAfter from TaskPoolTests
