using System.Text;
using TechnitiumLibrary.Security.Cryptography;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Security.Cryptography
{
    public class CryptoContainerTests
    {
        [Fact]
        public void PlainTextContainerRoundTripsThroughStreamAndFile()
        {
            TestCryptoContainer container = new TestCryptoContainer("plain text");
            using MemoryStream stream = new MemoryStream();

            container.WriteTo(stream);
            stream.Position = 0;
            using TestCryptoContainer parsed = new TestCryptoContainer(stream);

            Assert.Equal("plain text", parsed.Value);

            string file = Path.Combine(Path.GetTempPath(), "crypto-container-" + Guid.NewGuid() + ".bin");
            try
            {
                container.SaveAs(file);
                using FileStream fileStream = File.OpenRead(file);
                using TestCryptoContainer parsedFile = new TestCryptoContainer(fileStream);
                Assert.Equal("plain text", parsedFile.Value);
            }
            finally
            {
                if (File.Exists(file))
                    File.Delete(file);
            }
        }

        [Fact]
        public void PasswordProtectedContainerRoundTripsAndDetectsWrongPasswordOrTampering()
        {
            TestCryptoContainer container = new TestCryptoContainer("secret", "password");
            using MemoryStream stream = new MemoryStream();

            container.WriteTo(stream);
            byte[] protectedBytes = stream.ToArray();

            using TestCryptoContainer parsed = new TestCryptoContainer(new MemoryStream(protectedBytes), "password");
            Assert.Equal("secret", parsed.Value);

            Assert.Throws<CryptoException>(() => new TestCryptoContainer(new MemoryStream(protectedBytes), "wrong"));

            byte[] tampered = protectedBytes.ToArray();
            tampered[^1] ^= 0x01;
            Assert.Throws<CryptoException>(() => new TestCryptoContainer(new MemoryStream(tampered), "password"));
        }

        [Fact]
        public void PasswordCanBeAddedChangedAndRemoved()
        {
            TestCryptoContainer container = new TestCryptoContainer("secret");

            Assert.Throws<CryptoException>(() => container.ChangePassword("new"));

            container.SetPassword(SymmetricEncryptionAlgorithm.Rijndael, 256, "first");
            using MemoryStream protectedStream = new MemoryStream();
            container.WriteTo(protectedStream);
            using TestCryptoContainer protectedParsed = new TestCryptoContainer(new MemoryStream(protectedStream.ToArray()), "first");
            Assert.Equal("secret", protectedParsed.Value);

            container.ChangePassword(null);
            using MemoryStream plainStream = new MemoryStream();
            container.WriteTo(plainStream);
            using TestCryptoContainer plainParsed = new TestCryptoContainer(new MemoryStream(plainStream.ToArray()));
            Assert.Equal("secret", plainParsed.Value);
        }

        [Fact]
        public void InvalidContainerFormatThrows()
        {
            Assert.Throws<InvalidCryptoContainerException>(() => new TestCryptoContainer(new MemoryStream([0, 1, 2])));
            Assert.Throws<InvalidCryptoContainerException>(() => new TestCryptoContainer(new MemoryStream([.. Encoding.ASCII.GetBytes("CC"), 255])));
        }

        private sealed class TestCryptoContainer : CryptoContainer
        {
            public TestCryptoContainer(string value)
            {
                Value = value;
            }

            public TestCryptoContainer(string value, string password)
                : base(SymmetricEncryptionAlgorithm.Rijndael, 256, password)
            {
                Value = value;
            }

            public TestCryptoContainer(Stream stream, string? password = null)
                : base(stream, password)
            { }

            public string? Value { get; private set; }

            protected override void ReadPlainTextFrom(Stream s)
            {
                using StreamReader reader = new StreamReader(s, Encoding.UTF8, leaveOpen: true);
                Value = reader.ReadToEnd();
            }

            protected override void WritePlainTextTo(Stream s)
            {
                byte[] data = Encoding.UTF8.GetBytes(Value ?? string.Empty);
                s.Write(data);
            }
        }
    }
}
