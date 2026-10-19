using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary
{
    public class TaskExtensionsTests
    {
        [Fact]
        public async Task TimeoutAsync_CompletesBeforeTimeout()
        {
            await TaskExtensions.TimeoutAsync(ct => Task.CompletedTask, 100);
        }

        [Fact]
        public async Task TimeoutAsync_ThrowsOnTimeout()
        {
            await Assert.ThrowsAsync<TimeoutException>(() => TaskExtensions.TimeoutAsync(async ct => await Task.Delay(500, ct), 50));
        }

        [Fact]
        public void Sync_ReturnsValue()
        {
            var t = Task.FromResult(42);
            Assert.Equal(42, t.Sync());
        }

        [Fact]
        public async Task TimeoutAsync_GenericCompletesBeforeTimeout()
        {
            int result = await TaskExtensions.TimeoutAsync(ct => Task.FromResult(123), 100);

            Assert.Equal(123, result);
        }

        [Fact]
        public async Task TimeoutAsync_GenericThrowsOnTimeout()
        {
            await Assert.ThrowsAsync<TimeoutException>(() => TaskExtensions.TimeoutAsync(async ct =>
            {
                await Task.Delay(500, ct);
                return 123;
            }, 50));
        }

        [Fact]
        public async Task TimeoutAsync_ExternalCancellationThrowsOperationCanceled()
        {
            using CancellationTokenSource cts = new CancellationTokenSource();
            cts.Cancel();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => TaskExtensions.TimeoutAsync(ct => Task.Delay(500, ct), 50, cts.Token));
        }

        [Fact]
        public void Sync_WaitsForTaskAndValueTasks()
        {
            bool completed = false;
            Task.Run(() => completed = true).Sync();
            global::TechnitiumLibrary.TaskExtensions.Sync((Task)Task.CompletedTask);

            Assert.True(completed);
            new ValueTask(Task.CompletedTask).Sync();
            Assert.Equal(7, new ValueTask<int>(7).Sync());
        }
    }
}
