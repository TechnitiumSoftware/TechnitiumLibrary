using System.Text;
using TechnitiumLibrary.Security.OTP;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Security.OTP
{
    public class OTPProjectTests
    {
        [Fact]
        public void AuthenticatorKeyUri_ToStringAndParse_RoundtripEscapedValues()
        {
            AuthenticatorKeyUri expected = new AuthenticatorKeyUri(
                "totp",
                "Example Issuer",
                "user@example.com",
                "JBSWY3DPEHPK3PXP",
                "SHA256",
                8,
                45);

            AuthenticatorKeyUri actual = AuthenticatorKeyUri.Parse(expected.ToString());

            Assert.Equal(expected.Type, actual.Type);
            Assert.Equal(expected.Issuer, actual.Issuer);
            Assert.Equal(expected.AccountName, actual.AccountName);
            Assert.Equal(expected.Secret, actual.Secret);
            Assert.Equal(expected.Algorithm, actual.Algorithm);
            Assert.Equal(expected.Digits, actual.Digits);
            Assert.Equal(expected.Period, actual.Period);
        }

        [Fact]
        public void Authenticator_GeneratesRfc6238TotpVector()
        {
            AuthenticatorKeyUri keyUri = new AuthenticatorKeyUri(
                "totp",
                "RFC",
                "test",
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                "SHA1",
                8,
                30);
            Authenticator authenticator = new Authenticator(keyUri);

            string totp = authenticator.GetTOTP(DateTime.UnixEpoch.AddSeconds(59));

            Assert.Equal("94287082", totp);
        }

        [Theory]
        [InlineData("SHA1", "12345678901234567890", "94287082")]
        [InlineData("SHA256", "12345678901234567890123456789012", "46119246")]
        [InlineData("SHA512", "1234567890123456789012345678901234567890123456789012345678901234", "90693936")]
        public void Authenticator_GeneratesRfc6238VectorsForSupportedAlgorithms(string algorithm, string key, string expected)
        {
            string secret = Base32.ToBase32String(Encoding.ASCII.GetBytes(key), skipPadding: true);
            AuthenticatorKeyUri keyUri = new AuthenticatorKeyUri("totp", "RFC", "test", secret, algorithm, 8, 30);
            Authenticator authenticator = new Authenticator(keyUri);

            Assert.Equal(expected, authenticator.GetTOTP(DateTime.UnixEpoch.AddSeconds(59)));
        }

        [Fact]
        public void AuthenticatorKeyUri_GenerateCreatesValidTotpUri()
        {
            AuthenticatorKeyUri keyUri = AuthenticatorKeyUri.Generate("issuer", "account", keySize: 20, algorithm: "SHA512", digits: 7, period: 60);

            Assert.Equal("totp", keyUri.Type);
            Assert.Equal("issuer", keyUri.Issuer);
            Assert.Equal("account", keyUri.AccountName);
            Assert.Equal("SHA512", keyUri.Algorithm);
            Assert.Equal(7, keyUri.Digits);
            Assert.Equal(60, keyUri.Period);
            Assert.Equal(32, keyUri.Secret.Length);
            Assert.NotNull(new Authenticator(keyUri).GetTOTP(DateTime.UnixEpoch.AddSeconds(59)));
        }

        [Fact]
        public void AuthenticatorKeyUri_ParseRejectsInvalidValues()
        {
            Assert.Throws<ArgumentException>(() => AuthenticatorKeyUri.Parse("https://issuer/account?secret=JBSWY3DPEHPK3PXP"));
            Assert.Throws<ArgumentException>(() => AuthenticatorKeyUri.Parse("otpauth://totp/issuer/account?secret=JBSWY3DPEHPK3PXP"));
            Assert.Throws<ArgumentException>(() => AuthenticatorKeyUri.Parse("otpauth://totp/issuer:account?secret=JBSWY3DPEHPK3PXP&digits=abc"));
            Assert.Throws<ArgumentException>(() => AuthenticatorKeyUri.Parse("otpauth://totp/issuer:account?secret=JBSWY3DPEHPK3PXP&period=abc"));
        }

        [Fact]
        public void Authenticator_RejectsUnsupportedTypeAndAlgorithm()
        {
            Assert.Throws<NotSupportedException>(() => new Authenticator(new AuthenticatorKeyUri("hotp", "issuer", "account", "JBSWY3DPEHPK3PXP")));

            Authenticator authenticator = new Authenticator(new AuthenticatorKeyUri("totp", "issuer", "account", "JBSWY3DPEHPK3PXP", "MD5"));
            Assert.Throws<NotSupportedException>(() => authenticator.GetTOTP(DateTime.UnixEpoch));
        }

        [Fact]
        public void Authenticator_IsTOTPValid_AcceptsCurrentCodeAndRejectsInvalidCode()
        {
            Authenticator authenticator = new Authenticator(new AuthenticatorKeyUri("totp", "issuer", "account", "JBSWY3DPEHPK3PXP"));
            string currentTotp = authenticator.GetTOTP();

            Assert.True(authenticator.IsTOTPValid(currentTotp, fudge: 0));
            Assert.False(authenticator.IsTOTPValid("000000", fudge: 0));
        }

        [Fact]
        public void AuthenticatorKeyUri_NullAlgorithmDefaultsToSha1()
        {
            AuthenticatorKeyUri keyUri = new AuthenticatorKeyUri("totp", "issuer", "account", "JBSWY3DPEHPK3PXP", algorithm: null);

            Assert.Equal("SHA1", keyUri.Algorithm);
        }

        [Fact]
        public void AuthenticatorKeyUri_GetQRCodePngImage_ReturnsPngBytes()
        {
            AuthenticatorKeyUri keyUri = new AuthenticatorKeyUri("totp", "issuer", "account", "JBSWY3DPEHPK3PXP");

            byte[] png = keyUri.GetQRCodePngImage();

            Assert.Equal(new byte[] { 137, 80, 78, 71 }, png.Take(4).ToArray());
        }

        [Theory]
        [InlineData(5)]
        [InlineData(9)]
        public void AuthenticatorKeyUri_InvalidDigitsThrows(int digits)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new AuthenticatorKeyUri("totp", "issuer", "account", "JBSWY3DPEHPK3PXP", digits: digits));
        }

        [Fact]
        public void AuthenticatorKeyUri_InvalidPeriodThrows()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new AuthenticatorKeyUri("totp", "issuer", "account", "JBSWY3DPEHPK3PXP", period: -1));
        }
    }
}
