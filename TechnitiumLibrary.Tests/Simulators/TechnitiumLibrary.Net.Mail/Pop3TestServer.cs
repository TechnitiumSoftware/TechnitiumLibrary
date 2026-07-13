using System.Net;
using System.Net.Sockets;
using System.Text;

namespace TechnitiumLibrary.Tests.Simulators.TechnitiumLibrary.Net.Mail
{
    internal sealed class Pop3TestServer : IDisposable
    {
        private readonly TcpListener _listener = new TcpListener(IPAddress.Loopback, 0);
        private readonly string _greeting;
        private readonly Queue<string[]> _responses = new Queue<string[]>();
        private readonly List<string> _commands = new List<string>();
        private Task? _serverTask;

        public Pop3TestServer(string greeting)
        {
            _greeting = greeting;
        }

        public int Port
        { get { return ((IPEndPoint)_listener.LocalEndpoint).Port; } }

        public IReadOnlyList<string> Commands
        { get { return _commands; } }

        public void Enqueue(params string[] lines)
        {
            _responses.Enqueue(lines);
        }

        public Task StartAsync()
        {
            _listener.Start();
            _serverTask = Task.Run(ServeAsync);
            return Task.CompletedTask;
        }

        private async Task ServeAsync()
        {
            using TcpClient client = await _listener.AcceptTcpClientAsync();
            using NetworkStream stream = client.GetStream();
            using StreamReader reader = new StreamReader(stream, Encoding.ASCII, false, 1024, leaveOpen: true);
            using StreamWriter writer = new StreamWriter(stream, Encoding.ASCII, 1024, leaveOpen: true) { AutoFlush = true, NewLine = "\r\n" };

            await writer.WriteLineAsync(_greeting);

            while (_responses.Count > 0)
            {
                string? command = await reader.ReadLineAsync();
                if (command is null)
                    break;

                _commands.Add(command);

                foreach (string line in _responses.Dequeue())
                    await writer.WriteLineAsync(line);
            }
        }

        public void Dispose()
        {
            _listener.Stop();

            try
            {
                _serverTask?.Wait(TimeSpan.FromSeconds(2));
            }
            catch (AggregateException)
            { }
        }
    }
}
