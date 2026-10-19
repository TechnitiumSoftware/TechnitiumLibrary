using System.Text;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.IO
{
    public class PackageItemTests
    {
        [Fact]
        public void WriteParseExtractAndProperties_Work()
        {
            DateTime modified = DateTime.UnixEpoch.AddSeconds(1000);
            using MemoryStream data = new MemoryStream(Encoding.UTF8.GetBytes("payload"));
            PackageItem item = new PackageItem("file.txt", modified, data, PackageItemAttributes.FixedExtractLocation, ExtractLocation.Custom, Path.GetTempPath());

            using MemoryStream serialized = new MemoryStream();
            item.WriteTo(serialized);
            serialized.Position = 0;

            PackageItem parsed = PackageItem.Parse(serialized);
            Assert.Equal("file.txt", parsed.Name);
            Assert.Equal(modified, parsed.LastModifiedUTC);
            Assert.Equal(PackageItemAttributes.FixedExtractLocation, parsed.Attribute);
            Assert.Equal(ExtractLocation.Custom, parsed.ExtractTo);
            Assert.Equal(Path.GetTempPath(), parsed.ExtractToCustomLocation);
            Assert.True(parsed.IsAttributeSet(PackageItemAttributes.FixedExtractLocation));

            using StreamReader reader = new StreamReader(parsed.DataStream, Encoding.UTF8, leaveOpen: true);
            Assert.Equal("payload", reader.ReadToEnd());

            string dir = Path.Combine(Path.GetTempPath(), "TechnitiumLibraryTests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                string filePath = Path.Combine(dir, "file.txt");
                PackageItemTransactionLog log = parsed.Extract(filePath);
                Assert.Equal(filePath, log.FilePath);
                Assert.Null(log.OriginalFilePath);
                Assert.Equal("payload", File.ReadAllText(filePath));
                Assert.Null(parsed.Extract(filePath));

                File.WriteAllText(filePath, "old");
                PackageItemTransactionLog overwriteLog = parsed.Extract(filePath, overwrite: true);
                Assert.Equal(filePath, overwriteLog.FilePath);
                Assert.NotNull(overwriteLog.OriginalFilePath);
                Assert.True(File.Exists(overwriteLog.OriginalFilePath));
            }
            finally
            {
                Directory.Delete(dir, recursive: true);
            }
        }

        [Fact]
        public void InvalidVersionsThrowOrReturnNull()
        {
            Assert.Throws<EndOfStreamException>(() => PackageItem.Parse(new MemoryStream()));
            Assert.Null(PackageItem.Parse(new MemoryStream(new byte[] { 0 })));
            Assert.Throws<IOException>(() => PackageItem.Parse(new MemoryStream(new byte[] { 99 })));
        }
    }
}
