using System.Net.Mail;
using TechnitiumLibrary.Security.Cryptography;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Security.Cryptography
{
    public class CertificateProfileTests
    {
        [Fact]
        public void ProfileRoundTripsAllFieldsAndVerificationFlags()
        {
            CertificateProfile profile = new CertificateProfile(
                name: "Alice",
                type: CertificateProfileType.Individual,
                emailAddress: new MailAddress("alice@example.test"),
                website: new Uri("https://example.test/"),
                phoneNumber: "+1 555 0100",
                streetAddress: "1 Main St",
                city: "Vienna",
                state: "Vienna",
                country: "AT",
                postalCode: "1010",
                verificationFlags: CertificateProfileFlags.Name | CertificateProfileFlags.EmailAddress | CertificateProfileFlags.Country);
            using MemoryStream stream = new MemoryStream();

            profile.WriteTo(stream);
            stream.Position = 0;
            CertificateProfile parsed = new CertificateProfile(stream);

            Assert.Equal(profile, parsed);
            Assert.Equal(1, parsed.Version);
            Assert.Equal(CertificateProfileType.Individual, parsed.Type);
            Assert.Equal("Alice", parsed.Name);
            Assert.Equal("alice@example.test", parsed.EmailAddress.Address);
            Assert.Equal(new Uri("https://example.test/"), parsed.Website);
            Assert.Equal("+1 555 0100", parsed.PhoneNumber);
            Assert.Equal("1 Main St", parsed.StreetAddress);
            Assert.Equal("Vienna", parsed.City);
            Assert.Equal("Vienna", parsed.State);
            Assert.Equal("AT", parsed.Country);
            Assert.Equal("1010", parsed.PostalCode);
            Assert.True(parsed.FieldExists(CertificateProfileFlags.Name));
            Assert.True(parsed.IsFieldVerified(CertificateProfileFlags.Name));
            Assert.False(parsed.IsFieldVerified(CertificateProfileFlags.PhoneNumber));
            Assert.Contains("Name (verified): Alice", parsed.ToString());
            Assert.Contains("Email Address (verified): alice@example.test", parsed.ToString());
        }

        [Fact]
        public void ProfileMasksVerificationFlagsToExistingFields()
        {
            CertificateProfile profile = new CertificateProfile(name: "Bob", verificationFlags: CertificateProfileFlags.All);

            Assert.True(profile.FieldExists(CertificateProfileFlags.Name));
            Assert.True(profile.IsFieldVerified(CertificateProfileFlags.Name));
            Assert.False(profile.FieldExists(CertificateProfileFlags.EmailAddress));
            Assert.False(profile.IsFieldVerified(CertificateProfileFlags.EmailAddress));
            Assert.NotEqual(profile, new CertificateProfile(name: "Alice"));
            Assert.False(profile.Equals(null));
            Assert.True(profile.Equals(profile));
            Assert.False(profile.Equals("profile"));
            Assert.NotEqual(0, profile.GetHashCode());
        }

        [Fact]
        public void InvalidProfileFormatThrows()
        {
            Assert.Throws<CryptoException>(() => new CertificateProfile(new MemoryStream([0, 1, 2])));
            Assert.Throws<CryptoException>(() => new CertificateProfile(new MemoryStream([.. System.Text.Encoding.ASCII.GetBytes("CP"), 255])));
        }
    }
}
