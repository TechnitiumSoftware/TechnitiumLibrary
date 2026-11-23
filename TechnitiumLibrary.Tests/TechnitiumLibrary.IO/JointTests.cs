using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.IO
{
    public class JointTests
    {
        [Fact]
        public void Dispose_IsIdempotentAndDisposesBothStreams()
        {
            MemoryStream stream1 = new MemoryStream();
            MemoryStream stream2 = new MemoryStream();
            using Joint joint = new Joint(stream1, stream2);
            int disposingCount = 0;
            joint.Disposing += (_, _) => disposingCount++;

            Assert.Same(stream1, joint.Stream1);
            Assert.Same(stream2, joint.Stream2);

            joint.Dispose();
            joint.Dispose();

            Assert.Equal(1, disposingCount);
            Assert.False(stream1.CanRead);
            Assert.False(stream2.CanRead);
        }
    }
}
