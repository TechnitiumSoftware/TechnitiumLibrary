using System;
using System.Threading.Tasks;
using Xunit;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary
{
    public class TaskPoolTests
    {
        [Fact]
        public async Task TryQueueTask_ExecutesQueuedTask()
        {
            using var pool = new TaskPool();
            var tcs = new TaskCompletionSource<int>();

            bool queued = pool.TryQueueTask(async _ => { tcs.SetResult(7); await Task.CompletedTask; });
            Assert.True(queued);

            var result = await tcs.Task.TimeoutAfter(1000);
            Assert.Equal(7, result);
        }

        [Fact]
        public async Task TryQueueTask_WithState_ExecutesQueuedTask()
        {
            using TaskPool pool = new TaskPool(queueSize: 4, maximumConcurrencyLevel: 1);
            TaskCompletionSource<string> tcs = new TaskCompletionSource<string>();

            Assert.Equal(4, pool.QueueSize);
            Assert.Equal(1, pool.MaximumConcurrencyLevel);
            Assert.True(pool.TryQueueTask(state =>
            {
                tcs.SetResult((string)state);
                return Task.CompletedTask;
            }, "state-value"));

            Assert.Equal("state-value", await tcs.Task.TimeoutAfter(1000));
        }

        [Fact]
        public void Dispose_IsIdempotentAndRejectsFurtherWrites()
        {
            TaskPool pool = new TaskPool(queueSize: 1, maximumConcurrencyLevel: 1);

            pool.Dispose();
            pool.Dispose();

            Assert.False(pool.TryQueueTask(_ => Task.CompletedTask));
        }
    }
}

public static class TestHelpers
{
    public static async Task<T> TimeoutAfter<T>(this Task<T> task, int ms)
    {
        var delay = Task.Delay(ms);
        var finished = await Task.WhenAny(task, delay);
        if (finished == delay) throw new TimeoutException();
        return await task;
    }
}
