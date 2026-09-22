using System.Net;
using System.Net.Sockets;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace TechnitiumLibrary.Tests.Simulators.TechnitiumLibrary.Net
{
    internal sealed class DnsTestServer : IDisposable
    {
        private readonly TcpListener _tcpListener;
        private readonly UdpClient _udpClient;
        private readonly Dictionary<QuestionKey, Func<DnsQuestionRecord, IReadOnlyList<DnsResourceRecord>>> _answers = new Dictionary<QuestionKey, Func<DnsQuestionRecord, IReadOnlyList<DnsResourceRecord>>>();
        private readonly Dictionary<QuestionKey, DnsResponseCode> _responseCodes = new Dictionary<QuestionKey, DnsResponseCode>();
        private readonly CancellationTokenSource _cancellationTokenSource = new CancellationTokenSource();
        private Task? _udpTask;
        private Task? _tcpTask;

        public DnsTestServer()
        {
            for (int i = 0; ; i++)
            {
                TcpListener tcpListener = new TcpListener(IPAddress.Loopback, 0);
                tcpListener.Start();
                int port = ((IPEndPoint)tcpListener.LocalEndpoint).Port;

                try
                {
                    _udpClient = new UdpClient(new IPEndPoint(IPAddress.Loopback, port));
                    _tcpListener = tcpListener;
                    Port = port;
                    break;
                }
                catch (SocketException) when (i < 10)
                {
                    tcpListener.Stop();
                }
            }
        }

        public int Port { get; }

        public int UdpQueryCount { get; private set; }

        public int TcpQueryCount { get; private set; }

        public bool TruncateUdpResponses { get; set; }

        public bool DropUdpResponses { get; set; }

        public void AddAddress(string domain, IPAddress address)
        {
            DnsResourceRecordType type = address.AddressFamily == AddressFamily.InterNetwork ? DnsResourceRecordType.A : DnsResourceRecordType.AAAA;

            _answers[new QuestionKey(domain, type)] = question =>
            [
                new DnsResourceRecord(
                    question.Name,
                    type,
                    DnsClass.IN,
                    60,
                    type == DnsResourceRecordType.A ? new DnsARecordData(address) : new DnsAAAARecordData(address))
            ];
        }

        public void AddCNameAddress(string aliasDomain, string canonicalDomain, IPAddress address)
        {
            _answers[new QuestionKey(aliasDomain, DnsResourceRecordType.A)] = question =>
            [
                new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, DnsClass.IN, 60, new DnsCNAMERecordData(canonicalDomain)),
                new DnsResourceRecord(canonicalDomain, DnsResourceRecordType.A, DnsClass.IN, 60, new DnsARecordData(address))
            ];
        }

        public void AddMx(string domain, ushort preference, string exchange)
        {
            _answers[new QuestionKey(domain, DnsResourceRecordType.MX)] = question =>
            [
                new DnsResourceRecord(question.Name, DnsResourceRecordType.MX, DnsClass.IN, 60, new DnsMXRecordData(preference, exchange))
            ];
        }

        public void SetResponseCode(string domain, DnsResourceRecordType type, DnsResponseCode responseCode)
        {
            _responseCodes[new QuestionKey(domain, type)] = responseCode;
        }

        public void Start()
        {
            _udpTask = Task.Run(ServeUdpAsync);
            _tcpTask = Task.Run(ServeTcpAsync);
        }

        private async Task ServeUdpAsync()
        {
            while (!_cancellationTokenSource.IsCancellationRequested)
            {
                try
                {
                    UdpReceiveResult result = await _udpClient.ReceiveAsync(_cancellationTokenSource.Token);
                    UdpQueryCount++;

                    if (DropUdpResponses)
                        continue;

                    using MemoryStream requestStream = new MemoryStream(result.Buffer);
                    DnsDatagram request = DnsDatagram.ReadFrom(requestStream);
                    DnsDatagram response = TruncateUdpResponses ? CreateTruncatedResponse(request) : CreateResponse(request);
                    using MemoryStream responseStream = new MemoryStream();
                    response.WriteTo(responseStream);

                    await _udpClient.SendAsync(responseStream.ToArray(), result.RemoteEndPoint, _cancellationTokenSource.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
            }
        }

        private async Task ServeTcpAsync()
        {
            while (!_cancellationTokenSource.IsCancellationRequested)
            {
                try
                {
                    TcpClient client = await _tcpListener.AcceptTcpClientAsync(_cancellationTokenSource.Token);
                    _ = Task.Run(() => ServeTcpClientAsync(client));
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
            }
        }

        private async Task ServeTcpClientAsync(TcpClient client)
        {
            using (client)
            using (NetworkStream stream = client.GetStream())
            {
                while (!_cancellationTokenSource.IsCancellationRequested)
                {
                    DnsDatagram request;

                    try
                    {
                        request = await DnsDatagram.ReadFromTcpAsync(stream, cancellationToken: _cancellationTokenSource.Token);
                    }
                    catch
                    {
                        break;
                    }

                    TcpQueryCount++;

                    DnsDatagram response = CreateResponse(request);
                    await response.WriteToTcpAsync(stream, cancellationToken: _cancellationTokenSource.Token);
                    await stream.FlushAsync(_cancellationTokenSource.Token);
                }
            }
        }

        private DnsDatagram CreateTruncatedResponse(DnsDatagram request)
        {
            return new DnsDatagram(
                request.Identifier,
                true,
                DnsOpcode.StandardQuery,
                true,
                true,
                request.RecursionDesired,
                true,
                false,
                false,
                DnsResponseCode.NoError,
                request.Question);
        }

        private DnsDatagram CreateResponse(DnsDatagram request)
        {
            DnsResponseCode responseCode = DnsResponseCode.NoError;
            IReadOnlyList<DnsResourceRecord> answers = Array.Empty<DnsResourceRecord>();

            if (request.Question.Count > 0)
            {
                DnsQuestionRecord question = request.Question[0];
                QuestionKey key = new QuestionKey(question.Name, question.Type);

                if (_responseCodes.TryGetValue(key, out DnsResponseCode configuredResponseCode))
                    responseCode = configuredResponseCode;

                if ((responseCode == DnsResponseCode.NoError) && _answers.TryGetValue(key, out var answerFactory))
                    answers = answerFactory(question);
            }

            return new DnsDatagram(
                request.Identifier,
                true,
                DnsOpcode.StandardQuery,
                true,
                false,
                request.RecursionDesired,
                true,
                false,
                false,
                responseCode,
                request.Question,
                answers);
        }

        public void Dispose()
        {
            _cancellationTokenSource.Cancel();
            _udpClient.Dispose();
            _tcpListener.Stop();

            try
            {
                Task.WaitAll(new[] { _udpTask, _tcpTask }.Where(task => task is not null).Cast<Task>().ToArray(), TimeSpan.FromSeconds(2));
            }
            catch
            { }

            _cancellationTokenSource.Dispose();
        }

        private readonly struct QuestionKey : IEquatable<QuestionKey>
        {
            private readonly string _domain;
            private readonly DnsResourceRecordType _type;

            public QuestionKey(string domain, DnsResourceRecordType type)
            {
                _domain = domain.TrimEnd('.').ToLowerInvariant();
                _type = type;
            }

            public bool Equals(QuestionKey other)
            {
                return (_domain == other._domain) && (_type == other._type);
            }

            public override bool Equals(object? obj)
            {
                return obj is QuestionKey other && Equals(other);
            }

            public override int GetHashCode()
            {
                return HashCode.Combine(_domain, _type);
            }
        }
    }
}
