using TechnitiumLibrary.ByteTree;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.ByteTree
{
    internal sealed class RejectingByteTree : ByteTree<string, string>
    {
        public RejectingByteTree()
            : base(256)
        { }

        protected override byte[] ConvertToByteKey(string key, bool throwException = true)
        {
            if (key.StartsWith("reject"))
                return null!;

            return key.Select(c => (byte)c).ToArray();
        }
    }
}
