using System.Net;
using System.Net.Mail;
using System.Net.Security;
using System.Reflection;
using TechnitiumLibrary.Net.Mail;

namespace TechnitiumLibrary.Tests.TechnitiumLibrary.Net.Mail
{
    public class SmtpClientExTests
    {
        [Fact]
        public void ConstructorsAndPropertiesExposeConfiguredValues()
        {
            using SmtpClientEx defaultClient = new SmtpClientEx();
            using SmtpClientEx hostClient = new SmtpClientEx("smtp.example");
            using SmtpClientEx hostPortClient = new SmtpClientEx("smtp.example", 2525);

            Assert.Null(defaultClient.Host);
            Assert.Equal("smtp.example", hostClient.Host);
            Assert.Equal(25, hostClient.Port);
            Assert.Equal("smtp.example", hostPortClient.Host);
            Assert.Equal(2525, hostPortClient.Port);

            hostPortClient.Host = "mail.example";
            hostPortClient.Port = 587;
            hostPortClient.SmtpOverTls = true;
            hostPortClient.IgnoreCertificateErrors = true;
            hostPortClient.DnsClient = null;
            hostPortClient.Proxy = null;

            Assert.Equal("mail.example", hostPortClient.Host);
            Assert.Equal(587, hostPortClient.Port);
            Assert.True(hostPortClient.SmtpOverTls);
            Assert.True(hostPortClient.IgnoreCertificateErrors);
            Assert.Null(hostPortClient.DnsClient);
            Assert.Null(hostPortClient.Proxy);
        }

        [Fact]
        public void LocalHostNameCanBeSetAndRandomized()
        {
            using SmtpClientEx client = new SmtpClientEx();

            client.LocalHostName = "local.example";
            Assert.Equal("local.example", client.LocalHostName);

            client.SetRandomLocalHostName();

            Assert.False(string.IsNullOrWhiteSpace(client.LocalHostName));
            Assert.Equal(8, client.LocalHostName.Length);
        }

        [Fact]
        public void StaticIgnoreCertificateErrorsForProxyCanBeChanged()
        {
            bool original = SmtpClientEx.IgnoreCertificateErrorsForProxy;

            try
            {
                SmtpClientEx.IgnoreCertificateErrorsForProxy = true;
                Assert.True(SmtpClientEx.IgnoreCertificateErrorsForProxy);

                SmtpClientEx.IgnoreCertificateErrorsForProxy = false;
                Assert.False(SmtpClientEx.IgnoreCertificateErrorsForProxy);
            }
            finally
            {
                SmtpClientEx.IgnoreCertificateErrorsForProxy = original;
            }
        }

        [Fact]
        public void SendAsyncOverloadsAreNotSupported()
        {
            using SmtpClientEx client = new SmtpClientEx();
            using MailMessage message = new MailMessage();

            Assert.Throws<NotSupportedException>(() => client.SendAsync("from@example.com", "to@example.com", "subject", "body", new object()));
            Assert.Throws<NotSupportedException>(() => client.SendAsync(message, new object()));
        }

        [Fact]
        public async Task SendMailAsyncRejectsMessageWithoutRecipientsBeforeNetworkAccess()
        {
            using SmtpClientEx client = new SmtpClientEx("smtp.example", 25);
            using MailMessage message = new MailMessage();
            message.From = new MailAddress("from@example.com");

            ArgumentException exception = await Assert.ThrowsAsync<ArgumentException>(() => client.SendMailAsync(message));

            Assert.Equal("Message does not contain receipent email address.", exception.Message);
        }

        [Fact]
        public async Task SendMailAsyncThrowsWhenDisposed()
        {
            SmtpClientEx client = new SmtpClientEx("smtp.example", 25);
            using MailMessage message = new MailMessage("from@example.com", "to@example.com", "subject", "body");

            client.Dispose();
            client.Dispose();

            await Assert.ThrowsAsync<ObjectDisposedException>(() => client.SendMailAsync(message));
        }

        [Fact]
        public async Task SendMailAsyncUsesBaseClientForPickupDirectoryDelivery()
        {
            string pickupDirectory = Path.Combine(Path.GetTempPath(), "TechnitiumLibraryTests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(pickupDirectory);

            try
            {
                using SmtpClientEx client = new SmtpClientEx("smtp.example", 25);
                client.DeliveryMethod = SmtpDeliveryMethod.SpecifiedPickupDirectory;
                client.PickupDirectoryLocation = pickupDirectory;

                await client.SendMailAsync("from@example.com", "to@example.com", "subject", "body");

                string messageFile = Assert.Single(Directory.GetFiles(pickupDirectory));
                string message = File.ReadAllText(messageFile);
                Assert.Contains("subject", message, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("body", message, StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                if (Directory.Exists(pickupDirectory))
                    Directory.Delete(pickupDirectory, recursive: true);
            }
        }

        [Fact]
        public void SendUsesBaseClientForPickupDirectoryDelivery()
        {
            string pickupDirectory = Path.Combine(Path.GetTempPath(), "TechnitiumLibraryTests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(pickupDirectory);

            try
            {
                using SmtpClientEx client = new SmtpClientEx("smtp.example", 25);
                client.DeliveryMethod = SmtpDeliveryMethod.SpecifiedPickupDirectory;
                client.PickupDirectoryLocation = pickupDirectory;

                client.Send("from@example.com", "to@example.com", "subject", "body");

                Assert.Single(Directory.GetFiles(pickupDirectory));
            }
            finally
            {
                if (Directory.Exists(pickupDirectory))
                    Directory.Delete(pickupDirectory, recursive: true);
            }
        }

        [Fact]
        public void ServerCertificateValidationCallbackHandlesSmtpClientAndFallbackSender()
        {
            using SmtpClientEx client = new SmtpClientEx();
            MethodInfo callback = typeof(SmtpClientEx).GetMethod("ServerCertificateValidationCallback", BindingFlags.NonPublic | BindingFlags.Static)!;

            Assert.True(InvokeCertificateCallback(callback, client, SslPolicyErrors.None));
            Assert.False(InvokeCertificateCallback(callback, client, SslPolicyErrors.RemoteCertificateChainErrors));

            client.IgnoreCertificateErrors = true;
            Assert.True(InvokeCertificateCallback(callback, client, SslPolicyErrors.RemoteCertificateChainErrors));

            Assert.True(InvokeCertificateCallback(callback, new object(), SslPolicyErrors.None));
            Assert.False(InvokeCertificateCallback(callback, new object(), SslPolicyErrors.RemoteCertificateChainErrors));
        }

        private static bool InvokeCertificateCallback(MethodInfo callback, object sender, SslPolicyErrors sslPolicyErrors)
        {
            return (bool)callback.Invoke(null, [sender, null, null, sslPolicyErrors])!;
        }
    }
}
