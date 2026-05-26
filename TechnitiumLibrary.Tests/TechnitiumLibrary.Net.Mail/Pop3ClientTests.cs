using System.Net.Security;
using System.Reflection;
using System.Text;
using TechnitiumLibrary.Net.Mail;
using TechnitiumLibrary.Tests.Simulators.TechnitiumLibrary.Net.Mail;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Mail
{
    public class Pop3ClientTests
    {
        [Fact]
        public void StatsFieldsCanBeAssigned()
        {
            Pop3Stats stats = new Pop3Stats
            {
                TotalMessages = 3,
                TotalSize = 4096
            };

            Assert.Equal(3, stats.TotalMessages);
            Assert.Equal(4096, stats.TotalSize);
        }

        [Fact]
        public void MessageInfoFieldsCanBeAssigned()
        {
            Pop3MessageInfo info = new Pop3MessageInfo
            {
                MessageNumber = 2,
                MessageSize = 1024
            };

            Assert.Equal(2, info.MessageNumber);
            Assert.Equal(1024, info.MessageSize);
        }

        [Fact]
        public void ExceptionsPreserveMessageAndInnerException()
        {
            Exception inner = new Exception("inner");

            Pop3Exception baseException = new Pop3Exception("base", inner);
            Pop3InvalidUsernamePasswordException invalidCredentials = new Pop3InvalidUsernamePasswordException("bad credentials", inner);

            Assert.Equal("base", baseException.Message);
            Assert.Same(inner, baseException.InnerException);
            Assert.IsAssignableFrom<Pop3Exception>(invalidCredentials);
            Assert.Equal("bad credentials", invalidCredentials.Message);
            Assert.Same(inner, invalidCredentials.InnerException);
            Assert.NotNull(new Pop3Exception().Message);
            Assert.NotNull(new Pop3InvalidUsernamePasswordException().Message);
            Assert.Equal("bad", new Pop3InvalidUsernamePasswordException("bad").Message);
        }

        [Fact]
        public void DisposeCanBeCalledMoreThanOnce()
        {
            Pop3Client client = new Pop3Client("127.0.0.1", 110, "user", "pass");

            client.Dispose();
            client.Dispose();
        }

        [Fact]
        public void RemoteCertificateValidationCallbackAlwaysAllowsCertificate()
        {
            using Pop3Client client = new Pop3Client("127.0.0.1", 110, "user", "pass");
            MethodInfo callback = typeof(Pop3Client).GetMethod("RemoteCertificateValidationCallback", BindingFlags.NonPublic | BindingFlags.Instance)!;

            bool result = (bool)callback.Invoke(client, [new object(), null, null, SslPolicyErrors.RemoteCertificateChainErrors])!;

            Assert.True(result);
        }

        [Fact]
        public async Task ConnectAuthenticatesWithUserPassWhenSecureAuthIsNotPreferred()
        {
            using Pop3TestServer server = new Pop3TestServer("+OK ready");
            server.Enqueue("+OK user");
            server.Enqueue("+OK pass");
            await server.StartAsync();

            using Pop3Client client = new Pop3Client("127.0.0.1", server.Port, "user", "pass", preferSecureAuth: false);

            client.Connect();

            Assert.Equal(["USER user", "PASS pass"], server.Commands);
        }

        [Fact]
        public async Task ConnectAuthenticatesWithApopWhenTimestampIsAvailable()
        {
            using Pop3TestServer server = new Pop3TestServer("+OK ready <12345@example>");
            server.Enqueue("+OK apop");
            await server.StartAsync();

            using Pop3Client client = new Pop3Client("127.0.0.1", server.Port, "user", "pass");

            client.Connect();

            string command = Assert.Single(server.Commands);
            Assert.StartsWith("APOP user ", command);
            Assert.Equal("APOP user " + Convert.ToHexString(System.Security.Cryptography.MD5.HashData(Encoding.ASCII.GetBytes("<12345@example>pass"))).ToLowerInvariant(), command);
        }

        [Fact]
        public async Task CommandsParseSuccessfulResponses()
        {
            using Pop3TestServer server = new Pop3TestServer("+OK ready");
            server.Enqueue("+OK user");
            server.Enqueue("+OK pass");
            server.Enqueue("+OK 2 512");
            server.Enqueue("+OK list follows", "1 100", "2 412", ".");
            server.Enqueue("+OK message follows", "Subject: Test", "", "Body", ".");
            server.Enqueue("+OK top follows", "Subject: Test", ".");
            server.Enqueue("+OK deleted");
            server.Enqueue("+OK noop");
            server.Enqueue("+OK reset");
            server.Enqueue("+OK bye");
            await server.StartAsync();

            using Pop3Client client = new Pop3Client("127.0.0.1", server.Port, "user", "pass", preferSecureAuth: false);

            client.Connect();
            Pop3Stats stats = client.STAT();
            Pop3MessageInfo[] list = client.LIST();
            byte[] message = client.RETR(1);
            byte[] top = client.TOP(1, 2);
            client.DELE(1);
            client.NOOP();
            client.RSET();
            client.QUIT();

            Assert.Equal(2, stats.TotalMessages);
            Assert.Equal(512, stats.TotalSize);
            Assert.Equal(2, list.Length);
            Assert.Equal(1, list[0].MessageNumber);
            Assert.Equal(100, list[0].MessageSize);
            Assert.Equal("Subject: Test\r\n\r\nBody\r\n", Encoding.ASCII.GetString(message));
            Assert.Equal("Subject: Test\r\n", Encoding.ASCII.GetString(top));
            Assert.Contains("STAT", server.Commands);
            Assert.Contains("LIST", server.Commands);
            Assert.Contains("RETR 1", server.Commands);
            Assert.Contains("TOP 1 2", server.Commands);
            Assert.Contains("DELE 1", server.Commands);
            Assert.Contains("NOOP", server.Commands);
            Assert.Contains("RSET", server.Commands);
            Assert.Contains("QUIT", server.Commands);
        }

        [Fact]
        public async Task ConnectRejectsSecondConnectionUntilClosed()
        {
            using Pop3TestServer server = new Pop3TestServer("+OK ready");
            server.Enqueue("+OK user");
            server.Enqueue("+OK pass");
            await server.StartAsync();

            using Pop3Client client = new Pop3Client("127.0.0.1", server.Port, "user", "pass", preferSecureAuth: false);

            client.Connect();

            Assert.Throws<Pop3Exception>(() => client.Connect());
            client.Close();
            client.Close();
        }

        [Fact]
        public async Task ConnectThrowsWhenGreetingIsError()
        {
            using Pop3TestServer server = new Pop3TestServer("-ERR down");
            await server.StartAsync();

            using Pop3Client client = new Pop3Client("127.0.0.1", server.Port, "user", "pass");

            Pop3Exception exception = Assert.Throws<Pop3Exception>(() => client.Connect());
            Assert.Equal("Server returned: down", exception.Message);
        }

        [Theory]
        [InlineData("-ERR bad user", typeof(Pop3InvalidUsernamePasswordException))]
        [InlineData("+OK user", typeof(Pop3InvalidUsernamePasswordException))]
        public async Task ConnectThrowsInvalidCredentialsWhenAuthenticationFails(string firstAuthResponse, Type expectedExceptionType)
        {
            using Pop3TestServer server = new Pop3TestServer("+OK ready");
            server.Enqueue(firstAuthResponse);
            if (firstAuthResponse.StartsWith("+OK", StringComparison.Ordinal))
                server.Enqueue("-ERR bad pass");
            await server.StartAsync();

            using Pop3Client client = new Pop3Client("127.0.0.1", server.Port, "user", "pass", preferSecureAuth: false);

            Exception exception = Assert.Throws(expectedExceptionType, () => client.Connect());
            Assert.StartsWith("Server returned: bad", exception.Message);
        }

        [Fact]
        public async Task CommandThrowsWhenServerReturnsError()
        {
            using Pop3TestServer server = new Pop3TestServer("+OK ready");
            server.Enqueue("+OK user");
            server.Enqueue("+OK pass");
            server.Enqueue("-ERR stat failed");
            await server.StartAsync();

            using Pop3Client client = new Pop3Client("127.0.0.1", server.Port, "user", "pass", preferSecureAuth: false);

            client.Connect();
            Pop3Exception exception = Assert.Throws<Pop3Exception>(() => client.STAT());

            Assert.Equal("Server returned: stat failed", exception.Message);
        }

        [Theory]
        [InlineData("QUIT")]
        [InlineData("LIST")]
        [InlineData("RETR")]
        [InlineData("TOP")]
        [InlineData("DELE")]
        [InlineData("NOOP")]
        [InlineData("RSET")]
        public async Task CommandsThrowWhenServerReturnsError(string commandName)
        {
            using Pop3TestServer server = new Pop3TestServer("+OK ready");
            server.Enqueue("+OK user");
            server.Enqueue("+OK pass");
            server.Enqueue("-ERR command failed");
            await server.StartAsync();

            using Pop3Client client = new Pop3Client("127.0.0.1", server.Port, "user", "pass", preferSecureAuth: false);

            client.Connect();
            Pop3Exception exception = Assert.Throws<Pop3Exception>(() => InvokeCommand(client, commandName));

            Assert.Equal("Server returned: command failed", exception.Message);
        }

        [Fact]
        public async Task CommandThrowsWhenServerClosesConnection()
        {
            using Pop3TestServer server = new Pop3TestServer("+OK ready");
            server.Enqueue("+OK user");
            server.Enqueue("+OK pass");
            await server.StartAsync();

            using Pop3Client client = new Pop3Client("127.0.0.1", server.Port, "user", "pass", preferSecureAuth: false);

            client.Connect();
            Exception exception = Record.Exception(() => client.STAT());

            Assert.True(exception is Pop3Exception or IOException);
            if (exception is Pop3Exception pop3Exception)
                Assert.Equal("No response from server.", pop3Exception.Message);
        }

        [Fact]
        public async Task ConnectThrowsInvalidCredentialsWhenApopFails()
        {
            using Pop3TestServer server = new Pop3TestServer("+OK ready <12345@example>");
            server.Enqueue("-ERR bad apop");
            await server.StartAsync();

            using Pop3Client client = new Pop3Client("127.0.0.1", server.Port, "user", "pass");

            Pop3InvalidUsernamePasswordException exception = Assert.Throws<Pop3InvalidUsernamePasswordException>(() => client.Connect());

            Assert.Equal("Server returned: bad apop", exception.Message);
        }

        private static void InvokeCommand(Pop3Client client, string commandName)
        {
            switch (commandName)
            {
                case "QUIT":
                    client.QUIT();
                    break;

                case "LIST":
                    client.LIST();
                    break;

                case "RETR":
                    client.RETR(1);
                    break;

                case "TOP":
                    client.TOP(1, 1);
                    break;

                case "DELE":
                    client.DELE(1);
                    break;

                case "NOOP":
                    client.NOOP();
                    break;

                case "RSET":
                    client.RSET();
                    break;
            }
        }
    }
}
