using TechnitiumLibrary.Net.BitTorrent;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.BitTorrent
{
    public class TrackerClientExceptionTests
    {
        [Fact]
        public void ConstructorsSetMessageAndInnerException()
        {
            TrackerClientException empty = new TrackerClientException();
            TrackerClientException withMessage = new TrackerClientException("message");
            InvalidOperationException inner = new InvalidOperationException("inner");
            TrackerClientException withInner = new TrackerClientException("outer", inner);

            Assert.NotNull(empty.Message);
            Assert.Equal("message", withMessage.Message);
            Assert.Equal("outer", withInner.Message);
            Assert.Same(inner, withInner.InnerException);
        }
    }
}
