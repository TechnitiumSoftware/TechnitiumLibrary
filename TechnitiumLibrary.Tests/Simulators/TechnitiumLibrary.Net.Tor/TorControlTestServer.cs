using System.Net;
using System.Net.Sockets;
using System.Text;

namespace TechnitiumLibrary.Tests.Simulators.TechnitiumLibrary.Net.Tor
{
    internal sealed class TorControlTestServer : IDisposable
    {
        private readonly TcpListener _listener = new TcpListener(IPAddress.Loopback, 0);
        private readonly Queue<string[]> _responses = new Queue<string[]>();
        private readonly List<string> _commands = new List<string>();
        private readonly CancellationTokenSource _cancellationTokenSource = new CancellationTokenSource();
        private Task? _serverTask;
        private TcpClient? _client;

        public int Port
        { get { return ((IPEndPoint)_listener.LocalEndpoint).Port; } }

        public IReadOnlyList<string> Commands
        { get { return _commands; } }

        public void Enqueue(params string[] lines)
        {
            _responses.Enqueue(lines);
        }

        public void Start()
        {
            _listener.Start();
            _serverTask = Task.Run(ServeAsync);
        }

        private async Task ServeAsync()
        {
            try
            {
                _client = await _listener.AcceptTcpClientAsync(_cancellationTokenSource.Token);

                using NetworkStream stream = _client.GetStream();
                using StreamReader reader = new StreamReader(stream, Encoding.ASCII, false, 1024, leaveOpen: true);
                using StreamWriter writer = new StreamWriter(stream, Encoding.ASCII, 1024, leaveOpen: true) { AutoFlush = true, NewLine = "\n" };

                while (!_cancellationTokenSource.IsCancellationRequested && (_responses.Count > 0))
                {
                    string? command = await reader.ReadLineAsync(_cancellationTokenSource.Token);
                    if (command is null)
                        break;

                    _commands.Add(command);

                    foreach (string line in _responses.Dequeue())
                        await writer.WriteLineAsync(line);
                }
            }
            catch (OperationCanceledException)
            { }
            catch (ObjectDisposedException)
            { }
            catch (IOException)
            { }
        }

        public void Dispose()
        {
            _cancellationTokenSource.Cancel();
            _client?.Dispose();
            _listener.Stop();

            try
            {
                _serverTask?.Wait(TimeSpan.FromSeconds(2));
            }
            catch
            { }

            _cancellationTokenSource.Dispose();
        }
    }
}
