using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Linq;
using System.Text;
using TechnitiumLibrary.IO;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.IO
{
    [TestClass]
    public sealed class PackageTests
    {
        private static MemoryStream CreateWritableStream() => new MemoryStream();

        private static byte[] BuildEmptyPackageFile()
        {
            // Header:
            //  TP   format id
            //  01   version
            //  00   EOF (no items)
            return "TP"u8.ToArray()
                .Append((byte)1)
                .Append((byte)0)
                .ToArray();
        }

        /// <summary>
        /// Creates a serialized single PackageItem with name "A" and empty content.
        /// </summary>
        private static byte[] CreateMinimalItem()
        {
            using MemoryStream ms = new MemoryStream();
            using BinaryWriter writer = new BinaryWriter(ms);

            // Write NAME field (short)
            writer.Write((byte)1);          // length
            writer.Write("A"u8.ToArray());  // ASCII name

            // Extract location = 0
            writer.Write((byte)0);

            // Flags = 0
            writer.Write((byte)0);

            // File size = 0 (Int64)
            writer.Write((long)0);

            // Because file size = 0, Write no content
            return ms.ToArray();
        }

        private static void WriteItem(Stream stream)
        {
            using MemoryStream data = new MemoryStream(); // empty payload
            using PackageItem item = new PackageItem("A", data);

            item.WriteTo(stream);
        }



        // -------------------------------------------------------------
        // CONSTRUCTION
        // -------------------------------------------------------------

        [TestMethod]
        public void Constructor_ShouldWriteHeader_WhenCreating()
        {
            using MemoryStream backing = CreateWritableStream();

            using (Package pkg = new Package(backing, PackageMode.Create))
            {
                pkg.Close();
            }

            byte[] data = backing.ToArray();

            Assert.IsGreaterThanOrEqualTo(3, data.Length);
            Assert.AreEqual("TP", Encoding.ASCII.GetString(data[..2]));
            Assert.AreEqual(1, data[2]); // version marker
        }

        [TestMethod]
        public void Constructor_ShouldReadExisting_WhenOpening()
        {
            byte[] bytes = BuildEmptyPackageFile();
            using MemoryStream backing = new MemoryStream(bytes);

            using Package pkg = new Package(backing, PackageMode.Open);

            Assert.IsEmpty(pkg.Items);
        }

        [TestMethod]
        public void Constructor_ShouldThrow_WhenInvalidHeader()
        {
            using MemoryStream backing = new MemoryStream("XY"u8.ToArray());

            Assert.ThrowsExactly<IOException>(() =>
                new Package(backing, PackageMode.Open));
        }

        // -------------------------------------------------------------
        // MODE RESTRICTION
        // -------------------------------------------------------------

        [TestMethod]
        public void AddItem_ShouldThrow_WhenNotInCreateMode()
        {
            using MemoryStream backing = new MemoryStream(BuildEmptyPackageFile());
            using Package pkg = new Package(backing, PackageMode.Open);

            Assert.ThrowsExactly<IOException>(() =>
            {
                // simulate write by raw call — not allowed in Open mode
                pkg.AddItem(null);
            });
        }

        [TestMethod]
        public void Items_ShouldThrow_WhenNotInOpenMode()
        {
            using MemoryStream backing = CreateWritableStream();
            using Package pkg = new Package(backing, PackageMode.Create);

            Assert.ThrowsExactly<IOException>(() =>
            {
                System.Collections.ObjectModel.ReadOnlyCollection<PackageItem> _ = pkg.Items;
            });
        }

        // -------------------------------------------------------------
        // WRITE AND READ BACK
        // -------------------------------------------------------------

        [TestMethod]
        public void WriteAndRead_ShouldReturnSameItems()
        {
            using MemoryStream backing = CreateWritableStream();

            // Write
            using (Package pkg = new Package(backing, PackageMode.Create))
            {
                WriteItem(backing);
                pkg.Close();
            }

            // Reopen
            backing.Position = 0;
            using Package pkg2 = new Package(backing, PackageMode.Open);

            Assert.HasCount(1, pkg2.Items);
        }

        [TestMethod]
        public void Close_ShouldWriteEOF_Once()
        {
            using MemoryStream backing = CreateWritableStream();
            using Package pkg = new Package(backing, PackageMode.Create);
            WriteItem(backing);
            pkg.Close();
            long len1 = backing.Length;
            pkg.Close();
            long len2 = backing.Length;
            Assert.AreEqual(len1, len2);
        }

        // -------------------------------------------------------------
        // STREAM OWNERSHIP
        // -------------------------------------------------------------

        [TestMethod]
        public void Dispose_ShouldCloseOwnedStream()
        {
            // secure temp file creation
            string tempFile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

            // create file exclusively before passing to Package
            using (FileStream fs = new FileStream(
                tempFile,
                FileMode.CreateNew,          // guarantees file does not exist
                FileAccess.ReadWrite,
                FileShare.None))             // no external access allowed
            {
                fs.WriteByte(99); // write something so the file exists
            }

            try
            {
                using (Package pkg = new Package(tempFile, PackageMode.Create))
                    pkg.Close(); // Close → flush EOF marker → close underlying stream

                using FileStream fs = new FileStream(tempFile, FileMode.Open, FileAccess.Read);
                Assert.IsGreaterThanOrEqualTo(3, fs.Length);
            }
            finally
            {
                if (File.Exists(tempFile))
                    File.Delete(tempFile);
            }
        }

        [TestMethod]
        public void Dispose_ShouldNotCloseExternalStream()
        {
            using MemoryStream backing = CreateWritableStream();
            using (Package pkg = new Package(backing, PackageMode.Create, ownsStream: false))
                pkg.Close();

            // external stream still usable
            backing.WriteByte(255);
            backing.Position = 0;
        }

        // -------------------------------------------------------------
        // INVALID FORMATS
        // -------------------------------------------------------------

        [TestMethod]
        public void ShouldThrow_WhenMissingVersion()
        {
            using MemoryStream backing = new MemoryStream("TP"u8.ToArray());

            Assert.ThrowsExactly<EndOfStreamException>(() =>
                new Package(backing, PackageMode.Open));
        }

        [TestMethod]
        public void ShouldThrow_WhenUnsupportedVersion()
        {
            byte[] bytes = "TP"u8.ToArray()
                .Concat("*"u8.ToArray()) // bogus version
                .Concat(new byte[] { 0 })
                .ToArray();

            using MemoryStream backing = new MemoryStream(bytes);

            Assert.ThrowsExactly<IOException>(() =>
                new Package(backing, PackageMode.Open));
        }
    }
}
