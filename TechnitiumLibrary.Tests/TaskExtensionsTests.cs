using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace TechnitiumLibrary.Tests
{
    public class TaskExtensionsTests
    {
        [Fact]
        public async Task TimeoutAsync_CompletesBeforeTimeout()
        {
            await TaskExtensions.TimeoutAsync(ct => Task.Delay(10, ct), 100);
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
    }
}
