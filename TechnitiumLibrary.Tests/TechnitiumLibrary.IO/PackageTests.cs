using System.Text;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.IO
{
    public class PackageTests
    {
        [Fact]
        public void CreateOpenItemsAndExtractAll_Work()
        {
            string dir = Path.Combine(Path.GetTempPath(), "TechnitiumLibraryTests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                string packagePath = Path.Combine(dir, "test.pkg");
                string extractDir = Path.Combine(dir, "extract");
                Directory.CreateDirectory(extractDir);

                using (Package package = new Package(packagePath, PackageMode.Create))
                {
                    Assert.Throws<IOException>(() => _ = package.Items);
                    package.AddItem(new PackageItem("a.txt", DateTime.UnixEpoch, new MemoryStream(Encoding.UTF8.GetBytes("a")), extractTo: ExtractLocation.Custom, extractToCustomLocation: extractDir));
                    package.Close();
                    Assert.Throws<ObjectDisposedException>(() => package.AddItem(new PackageItem("b.txt", new MemoryStream())));
                }

                using Package opened = new Package(packagePath, PackageMode.Open);
                Assert.Single(opened.Items);
                Assert.Equal("a.txt", opened.Items[0].Name);
                Assert.Throws<IOException>(() => opened.AddItem(new PackageItem("b.txt", new MemoryStream())));

                opened.ExtractAll(overwrite: true);
                Assert.Equal("a", File.ReadAllText(Path.Combine(extractDir, "a.txt")));
            }
            finally
            {
                Directory.Delete(dir, recursive: true);
            }
        }

        [Fact]
        public void InvalidHeadersAndVersionsThrow()
        {
            Assert.Throws<IOException>(() => new Package(new MemoryStream(new byte[] { (byte)'X', (byte)'Y', 1 }), PackageMode.Open));
            Assert.Throws<EndOfStreamException>(() => new Package(new MemoryStream(new byte[] { (byte)'T', (byte)'P' }), PackageMode.Open));
            Assert.Throws<IOException>(() => new Package(new MemoryStream(new byte[] { (byte)'T', (byte)'P', 99 }), PackageMode.Open));
        }

        [Fact]
        public void GetExtractLocation_CoversStableLocations()
        {
            string custom = Path.Combine(Path.GetTempPath(), "custom");

            Assert.Null(Package.GetExtractLocation(ExtractLocation.None, null));
            Assert.Equal(Path.GetTempPath(), Package.GetExtractLocation(ExtractLocation.Temp, null));
            Assert.Equal(custom, Package.GetExtractLocation(ExtractLocation.Custom, custom));
        }
    }
}
