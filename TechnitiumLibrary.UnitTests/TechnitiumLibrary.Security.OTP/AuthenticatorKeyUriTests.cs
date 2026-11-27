using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using TechnitiumLibrary.Security.OTP;

namespace TechnitiumLibrary.UnitTests.TechnitiumLibrary.Security.OTP
{
    [TestClass]
    public sealed class AuthenticatorKeyUriTests
    {
        [TestMethod]
        public void Constructor_ShouldAssignFieldsProperly()
        {
            AuthenticatorKeyUri uri = new AuthenticatorKeyUri(
                "totp",
                "ExampleCorp",
                "user@example.com",
                "SECRET123",
                algorithm: "SHA256",
                digits: 8,
                period: 45);

            Assert.AreEqual("totp", uri.Type);
            Assert.AreEqual("ExampleCorp", uri.Issuer);
            Assert.AreEqual("user@example.com", uri.AccountName);
            Assert.AreEqual("SECRET123", uri.Secret);
            Assert.AreEqual("SHA256", uri.Algorithm);
            Assert.AreEqual(8, uri.Digits);
            Assert.AreEqual(45, uri.Period);
        }

        [TestMethod]
        public void Constructor_ShouldRejectInvalidDigitRange()
        {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
                _ = new AuthenticatorKeyUri("totp", "X", "Y", "ABC", digits: 5));
        }

        [TestMethod]
        public void Constructor_ShouldRejectNegativePeriod()
        {
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
                _ = new AuthenticatorKeyUri("totp", "X", "Y", "ABC", period: -1));
        }

        [TestMethod]
        public void Generate_ShouldProduceValidInstance()
        {
            AuthenticatorKeyUri uri = AuthenticatorKeyUri.Generate(
                issuer: "Corp",
                accountName: "user@example.com",
                keySize: 10);

            Assert.AreEqual("totp", uri.Type);
            Assert.AreEqual("Corp", uri.Issuer);
            Assert.AreEqual("user@example.com", uri.AccountName);
            Assert.IsNotNull(uri.Secret);
            Assert.IsGreaterThanOrEqualTo(8, uri.Secret.Length, "Base32 length must be greater than raw bytes");
        }

        [TestMethod]
        public void ToString_ShouldContainEncodedParameters()
        {
            AuthenticatorKeyUri uri = new AuthenticatorKeyUri(
                "totp", "ACME", "alice@example.com", "SECRETKEY");

            string uriString = uri.ToString();

            Assert.Contains("otpauth://", uriString);
            Assert.Contains("issuer=ACME", uriString);
            Assert.Contains("alice%40example.com", uriString); // corrected expectation
        }

        [TestMethod]
        public void Parse_ShouldRoundTripFromToString()
        {
            AuthenticatorKeyUri original = new AuthenticatorKeyUri(
                "totp",
                "Example",
                "bob@example.com",
                "BASESECRET",
                algorithm: "SHA512",
                digits: 8,
                period: 45);

            string serialized = original.ToString();
            AuthenticatorKeyUri parsed = AuthenticatorKeyUri.Parse(serialized);

            Assert.AreEqual(original.Type, parsed.Type);
            Assert.AreEqual(original.Issuer, parsed.Issuer);
            Assert.AreEqual(original.AccountName, parsed.AccountName);
            Assert.AreEqual(original.Secret, parsed.Secret);
            Assert.AreEqual(original.Algorithm, parsed.Algorithm);
            Assert.AreEqual(original.Digits, parsed.Digits);
            Assert.AreEqual(original.Period, parsed.Period);
        }

        [TestMethod]
        public void Parse_ShouldRejectInvalidUriScheme()
        {
            Assert.ThrowsExactly<ArgumentException>(() =>
                AuthenticatorKeyUri.Parse("http://notvalid"));
        }

        [TestMethod]
        public void Parse_ShouldRejectMalformedUri()
        {
            Assert.ThrowsExactly<ArgumentNullException>(() =>
                AuthenticatorKeyUri.Parse("otpauth://totp/INVALID")); // missing secret
        }

        [TestMethod]
        public void GetQRCodePngImage_ShouldReturnNonEmptyByteArray()
        {
            AuthenticatorKeyUri uri = new AuthenticatorKeyUri(
                "totp", "Issuer", "bob@example.com", "SECRETABC");

            byte[] result = uri.GetQRCodePngImage();

            Assert.IsNotNull(result);
            Assert.IsGreaterThan(32, result.Length, "QR PNG must contain image bytes");
        }
    }
}
