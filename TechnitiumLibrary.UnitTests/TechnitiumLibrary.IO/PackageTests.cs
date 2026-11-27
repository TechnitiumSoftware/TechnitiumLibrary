/*
Technitium Library
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

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

        // -------------------------------------------------------------
        // CONSTRUCTION
        // -------------------------------------------------------------

        [TestMethod]
        public void Constructor_ShouldWriteHeader_WhenCreating()
        {
            using MemoryStream backing = new MemoryStream();

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
            using MemoryStream backing = new MemoryStream();
            using Package pkg = new Package(backing, PackageMode.Create);

            Assert.ThrowsExactly<IOException>(() =>
            {
                _ = pkg.Items;
            });
        }

        // -------------------------------------------------------------
        // WRITE AND READ BACK
        // -------------------------------------------------------------

        [TestMethod]
        public void WriteAndRead_ShouldReturnSameItems()
        {
            using MemoryStream backing = new MemoryStream();

            // Write
            using (Package pkg = new Package(backing, PackageMode.Create))
            {
                pkg.AddItem(new PackageItem("A", Stream.Null));
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
            using MemoryStream backing = new MemoryStream();
            using Package pkg = new Package(backing, PackageMode.Create);
            pkg.AddItem(new PackageItem("A", Stream.Null));
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
            using MemoryStream backing = new MemoryStream();
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
