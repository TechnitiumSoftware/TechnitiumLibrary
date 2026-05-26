using System;
using System.Threading.Tasks;
using Xunit;

namespace TechnitiumLibrary.Tests
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
