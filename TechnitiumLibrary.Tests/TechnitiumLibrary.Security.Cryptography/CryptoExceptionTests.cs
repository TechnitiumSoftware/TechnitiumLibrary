using TechnitiumLibrary.Security.Cryptography;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Security.Cryptography
{
    public class CryptoExceptionTests
    {
        [Theory]
        [MemberData(nameof(ExceptionFactories))]
        public void ExceptionsPreserveMessagesAndInnerExceptions(Func<Exception> defaultFactory, Func<string, Exception> messageFactory, Func<string, Exception, Exception> innerFactory)
        {
            InvalidOperationException inner = new InvalidOperationException("inner");

            Exception defaultException = defaultFactory();
            Exception messageException = messageFactory("message");
            Exception innerException = innerFactory("message", inner);

            Assert.NotNull(defaultException.Message);
            Assert.Equal("message", messageException.Message);
            Assert.Equal("message", innerException.Message);
            Assert.Same(inner, innerException.InnerException);
        }

        public static IEnumerable<object[]> ExceptionFactories()
        {
            yield return
            [
                new Func<Exception>(() => new CryptoException()),
                new Func<string, Exception>(message => new CryptoException(message)),
                new Func<string, Exception, Exception>((message, inner) => new CryptoException(message, inner))
            ];

            yield return
            [
                new Func<Exception>(() => new InvalidCryptoContainerException()),
                new Func<string, Exception>(message => new InvalidCryptoContainerException(message)),
                new Func<string, Exception, Exception>((message, inner) => new InvalidCryptoContainerException(message, inner))
            ];

            yield return
            [
                new Func<Exception>(() => new InvalidCertificateException()),
                new Func<string, Exception>(message => new InvalidCertificateException(message)),
                new Func<string, Exception, Exception>((message, inner) => new InvalidCertificateException(message, inner))
            ];
        }
    }
}
