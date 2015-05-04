using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace Library.Net
{
    //enum PeerSocketState
    //{
    //    Closed = 0,
    //    SYN_SENT_1,
    //    SYN_ACK_SENT_2,
    //    CERT_ACK_SENT_1,
    //    CERT_ACK_SENT_2,
    //    KEY_ACK_SENT_1,
    //    KEY_ACK_SENT_2,
    //    Established,
    //    FIN_SENT,
    //    FIN_ACK_SENT
    //}

    //enum PeerSocketCryptoOptionFlags
    //{
    //    None = 0,
    //    RSA_SHA1_AES256 = 1
    //}

    //partial class PeerSocket : IDisposable
    //{
    //    #region Event

    //    public event EventHandler Connected;

    //    #endregion

    //    #region Variables

    //    IPEndPoint _remotePeerEP;
    //    byte[] _remotePeerID;
    //    Certificate _remoteCertificate;

    //    PeerSocketState _state = PeerSocketState.Closed;

    //    UInt32 _localSequenceNumber;
    //    UInt32 _remoteSequenceNumber;

    //    UInt32 _bytesSentToQueue = 0;
    //    UInt32 _bytesSent = 0;
    //    UInt32 _bytesReceived = 0;

    //    SymmetricCryptoKey _encryptionKey;
    //    SymmetricCryptoKey _decryptionKey;

    //    //transmission buffers
    //    byte[] _transmitBuffer = new byte[MESSAGE_BUFFER_MAX_SIZE + 100];
    //    MemoryStream _transmitStream;

    //    #endregion

    //    #region Constructor

    //    public PeerSocket(IPEndPoint remotePeerEP, byte[] remotePeerID = null)
    //    {
    //        _remotePeerEP = remotePeerEP;
    //        _remotePeerID = remotePeerID;

    //        _transmitStream = new MemoryStream(_transmitBuffer);
    //    }

    //    public PeerSocket(PeerInfo remotePeer)
    //    {
    //        _remotePeerEP = remotePeer.PeerEP;
    //        _remotePeerID = remotePeer.PeerID;

    //        _transmitStream = new MemoryStream(_transmitBuffer);
    //    }

    //    #endregion

    //    #region IDisposable

    //    ~PeerSocket()
    //    {
    //        Dispose(false);
    //    }

    //    public void Dispose()
    //    {
    //        Dispose(true);
    //        GC.SuppressFinalize(this);
    //    }

    //    void Dispose(bool Disposing)
    //    {
    //        Reset();
    //    }

    //    #endregion

    //    #region Public

    //    public void Connect()
    //    {
    //        Debug.Write("PeerSocket.Connect", "");

    //        if (_state != PeerSocketState.Closed)
    //            throw new BitChatException("Invalid PeerSocket state.");

    //        InitializePacketQueue();

    //        _localSequenceNumber = PeerSocket.GetRandomSeqNumber();
    //        _state = PeerSocketState.SYN_SENT_1;
    //        SendSYNPacket();
    //    }

    //    public void Disconnect()
    //    {
    //        Debug.Write("PeerSocket.Disconnect", "");

    //        if (_state == PeerSocketState.Established)
    //        {
    //            _state = PeerSocketState.FIN_SENT;
    //            SendPacketToQueue(PacketFlags.FIN);
    //        }
    //    }

    //    public void SendData(ChatMessage message)
    //    {
    //        if (_state == PeerSocketState.Established)
    //        {
    //            using (MemoryStream cipherText = new MemoryStream())
    //            {
    //                CryptoStream cW = _encryptionKey.GetCryptoStreamWriter(cipherText);

    //                message.WriteTo(cW);

    //                cW.Flush();
    //                cW.FlushFinalBlock();

    //                SendPacketToQueue(PacketFlags.DATA, cipherText.ToArray());
    //            }
    //        }
    //    }

    //    public void Reset()
    //    {
    //        if (_state > PeerSocketState.SYN_SENT_1)
    //        {
    //            TransmitPacket(new Packet(_localPeerID, _remotePeerID, PacketFlags.RST, 0, _remoteSequenceNumber + _bytesReceived + 1));
    //            CloseSocket();
    //        }
    //    }

    //    public PeerInfo GetInfo()
    //    {
    //        return new PeerInfo(_remotePeerID, _remotePeerEP);
    //    }

    //    public override bool Equals(object obj)
    //    {
    //        PeerSocket peerSock = obj as PeerSocket;

    //        if (peerSock == null)
    //            return false;

    //        if ((_remotePeerID == null) || (peerSock._remotePeerID == null))
    //            return base.Equals(obj);

    //        for (int i = 0; i < 20; i++)
    //            if (_remotePeerID[i] != peerSock._remotePeerID[i])
    //                return false;

    //        return true;
    //    }

    //    public override int GetHashCode()
    //    {
    //        return base.GetHashCode();
    //    }

    //    #endregion

    //    #region Private

    //    private byte[] GetLocalCertAndCryptoOptions()
    //    {
    //        using (MemoryStream mS = new MemoryStream(5120))
    //        {
    //            //cert
    //            byte[] cert = _localCryptoContainer.Certificate.ToArray();
    //            mS.Write(cert, 0, cert.Length);

    //            //crypto options
    //            byte options = (byte)PeerSocketCryptoOptionFlags.RSA_SHA1_AES256;
    //            mS.WriteByte(options);

    //            return mS.ToArray();
    //        }
    //    }

    //    private bool GenerateEncryptionKey(PeerSocketCryptoOptionFlags cryptoOptions)
    //    {
    //        if ((cryptoOptions & PeerSocketCryptoOptionFlags.RSA_SHA1_AES256) > 0)
    //        {
    //            _encryptionKey = new SymmetricCryptoKey("Rijndael", 256);
    //            return true;
    //        }
    //        else
    //            return false;
    //    }

    //    private byte[] GetEncryptedEncryptionKey()
    //    {
    //        return AsymmetricCryptoKey.Encrypt(_encryptionKey.ToArray(), _remoteCertificate.PublicKeyEncryptionAlgorithm, _remoteCertificate.PublicKey);
    //    }

    //    private byte[] GetDecryptedEncryptionKey(byte[] data)
    //    {
    //        return _localCryptoContainer.Key.Decrypt(data);
    //    }

    //    private bool IsThisPeer(byte[] peerID)
    //    {
    //        if (_remotePeerID == null)
    //            return false;

    //        for (int i = 0; i < 20; i++)
    //            if (_remotePeerID[i] != peerID[i])
    //                return false;

    //        return true;
    //    }

    //    private void Accept(Packet synPacket, IPEndPoint remotePeerEP)
    //    {
    //        if (synPacket.Flags != PacketFlags.SYN)
    //            throw new BitChatException("Packet must be SYN for Accepting.");

    //        InitializePacketQueue();

    //        _bytesReceived = synPacket.DataSize;

    //        _remotePeerID = synPacket.FromPeerID;
    //        _remotePeerEP = remotePeerEP;

    //        _remoteSequenceNumber = synPacket.SeqNumber;
    //        _localSequenceNumber = PeerSocket.GetRandomSeqNumber();

    //        _state = PeerSocketState.SYN_ACK_SENT_2;
    //        SendSYNPacket(synPacket);
    //    }

    //    private void ProcessRecvPacket(Packet recvPacket, IPEndPoint remotePeerEP, byte[] bufferedData = null)
    //    {
    //        Debug.Write("PeerSocket.ProcessRecvPacket [" + recvPacket.Flags + "]", "");

    //        switch (_state)
    //        {
    //            case PeerSocketState.Closed:
    //                #region CLOSED

    //                if (recvPacket.Flags == PacketFlags.SYN)
    //                    Accept(recvPacket, remotePeerEP);

    //                break;

    //                #endregion

    //            case PeerSocketState.SYN_SENT_1:
    //                #region SYN

    //                if (recvPacket.Flags == PacketFlags.RST)
    //                {
    //                    CloseSocket();

    //                    //check if remote peer is already connected as RST was received
    //                    _peerSockListLock.AcquireReaderLock(500);
    //                    try
    //                    {
    //                        foreach (PeerSocket peerSock in _peerSockList)
    //                        {
    //                            if (peerSock.IsThisPeer(recvPacket.FromPeerID))
    //                            {
    //                                //join this peer
    //                                Connected(peerSock, EventArgs.Empty);
    //                                break;
    //                            }
    //                        }
    //                    }
    //                    finally
    //                    {
    //                        _peerSockListLock.ReleaseLock();
    //                    }

    //                    return;
    //                }

    //                if ((recvPacket.Flags & PacketFlags.SYN) == 0)
    //                {
    //                    RSTPacketAndCloseSocket(recvPacket);
    //                    return;
    //                }

    //                _remotePeerID = recvPacket.FromPeerID;
    //                _remoteSequenceNumber = recvPacket.SeqNumber;

    //                _state = PeerSocketState.CERT_ACK_SENT_1;
    //                SendPacketToQueue(PacketFlags.CERT | PacketFlags.ACK, GetLocalCertAndCryptoOptions());

    //                break;

    //                #endregion

    //            case PeerSocketState.SYN_ACK_SENT_2:
    //                #region SYN + ACK 2

    //                if (recvPacket.Flags == PacketFlags.SYN)
    //                    return;

    //                if ((recvPacket.Flags & PacketFlags.CERT) == 0)
    //                {
    //                    RSTPacketAndCloseSocket(recvPacket);
    //                    return;
    //                }

    //                try
    //                {
    //                    Certificate cert;
    //                    PeerSocketCryptoOptionFlags cryptoOptions;

    //                    using (Stream data = new MemoryStream(bufferedData, false))
    //                    {
    //                        cert = new Certificate(data);
    //                        cryptoOptions = (PeerSocketCryptoOptionFlags)data.ReadByte();
    //                    }

    //                    cert.Verify(_trustedRootCertificates);
    //                    _remoteCertificate = cert;

    //                    if (!GenerateEncryptionKey(cryptoOptions))
    //                    {
    //                        RSTPacketAndCloseSocket(recvPacket);
    //                        return;
    //                    }

    //                    _state = PeerSocketState.CERT_ACK_SENT_2;
    //                    SendPacketToQueue(PacketFlags.CERT | PacketFlags.ACK, GetLocalCertAndCryptoOptions());
    //                }
    //                catch (InvalidCertificateException)
    //                {
    //                    RSTPacketAndCloseSocket(recvPacket);
    //                }

    //                break;

    //                #endregion

    //            case PeerSocketState.CERT_ACK_SENT_1:
    //                #region CERT + ACK

    //                if (recvPacket.Flags == PacketFlags.ACK)
    //                    return;

    //                if ((recvPacket.Flags & PacketFlags.CERT) > 0)
    //                {
    //                    try
    //                    {
    //                        Certificate cert;
    //                        PeerSocketCryptoOptionFlags cryptoOptions;

    //                        using (Stream data = new MemoryStream(bufferedData, false))
    //                        {
    //                            cert = new Certificate(data);
    //                            cryptoOptions = (PeerSocketCryptoOptionFlags)data.ReadByte();
    //                        }

    //                        cert.Verify(_trustedRootCertificates);
    //                        _remoteCertificate = cert;

    //                        if (!GenerateEncryptionKey(cryptoOptions))
    //                        {
    //                            RSTPacketAndCloseSocket(recvPacket);
    //                            return;
    //                        }

    //                        _state = PeerSocketState.KEY_ACK_SENT_1;
    //                        SendPacketToQueue(PacketFlags.KEY | PacketFlags.ACK, GetEncryptedEncryptionKey());
    //                    }
    //                    catch (InvalidCertificateException)
    //                    {
    //                        RSTPacketAndCloseSocket(recvPacket);
    //                    }
    //                }
    //                else
    //                    RSTPacketAndCloseSocket(recvPacket);

    //                break;

    //                #endregion

    //            case PeerSocketState.CERT_ACK_SENT_2:
    //                #region CERT + ACK 2

    //                if (recvPacket.Flags == PacketFlags.ACK)
    //                    return;

    //                if ((recvPacket.Flags & PacketFlags.KEY) > 0)
    //                {
    //                    using (MemoryStream data = new MemoryStream(GetDecryptedEncryptionKey(bufferedData)))
    //                    {
    //                        _decryptionKey = new SymmetricCryptoKey(data);
    //                    }

    //                    _state = PeerSocketState.KEY_ACK_SENT_2;
    //                    SendPacketToQueue(PacketFlags.KEY | PacketFlags.ACK, GetEncryptedEncryptionKey());
    //                }
    //                else
    //                    RSTPacketAndCloseSocket(recvPacket);

    //                break;

    //                #endregion

    //            case PeerSocketState.KEY_ACK_SENT_1:
    //                #region KEY + ACK

    //                if (recvPacket.Flags == PacketFlags.ACK)
    //                    return;

    //                if ((recvPacket.Flags & PacketFlags.KEY) > 0)
    //                {
    //                    using (MemoryStream data = new MemoryStream(GetDecryptedEncryptionKey(bufferedData)))
    //                    {
    //                        _decryptionKey = new SymmetricCryptoKey(data);
    //                    }

    //                    _state = PeerSocketState.Established;
    //                    ACKPacket(recvPacket);
    //                    _NOOPTimer = new Timer(NOOPTimerCallback, null, NOOP_PACKET_TIME_SECONDS * 1000, Timeout.Infinite);

    //                    Debug.Write("PeerSocket.ProcessRecvPacket - ESTABLISHED!", "");

    //                    if (Connected != null)
    //                        Connected(this, EventArgs.Empty);
    //                }
    //                else
    //                    RSTPacketAndCloseSocket(recvPacket);

    //                break;

    //                #endregion

    //            case PeerSocketState.KEY_ACK_SENT_2:
    //                #region KEY + ACK 2

    //                if (recvPacket.Flags == PacketFlags.ACK)
    //                {
    //                    if (_bytesSent == _bytesSentToQueue)
    //                    {
    //                        _state = PeerSocketState.Established;
    //                        _NOOPTimer = new Timer(NOOPTimerCallback, null, NOOP_PACKET_TIME_SECONDS * 1000, Timeout.Infinite);

    //                        Debug.Write("PeerSocket.ProcessRecvPacket - ESTABLISHED!", "");

    //                        if (Connected != null)
    //                            Connected(this, EventArgs.Empty);
    //                    }
    //                }
    //                else
    //                    RSTPacketAndCloseSocket(recvPacket);

    //                break;

    //                #endregion

    //            case PeerSocketState.Established:
    //                #region Connected

    //                if ((recvPacket.Flags & PacketFlags.DATA) > 0)
    //                {
    //                    using (MemoryStream cipherText = new MemoryStream(bufferedData, false))
    //                    {
    //                        using (MemoryStream clearText = new MemoryStream())
    //                        {
    //                            _decryptionKey.Decrypt(cipherText, clearText);
    //                            clearText.Position = 0;

    //                            BitChat.DataReceived(this, new ChatMessage(clearText));
    //                        }
    //                    }
    //                }
    //                else if ((recvPacket.Flags & PacketFlags.FIN) > 0)
    //                {
    //                    _state = PeerSocketState.FIN_ACK_SENT;
    //                    SendPacketToQueue(PacketFlags.FIN);
    //                }

    //                break;

    //                #endregion

    //            case PeerSocketState.FIN_SENT:
    //                #region FIN

    //                if ((recvPacket.Flags & PacketFlags.DATA) > 0)
    //                {
    //                    using (MemoryStream cipherText = new MemoryStream(bufferedData, false))
    //                    {
    //                        using (MemoryStream clearText = new MemoryStream())
    //                        {
    //                            _decryptionKey.Decrypt(cipherText, clearText);
    //                            clearText.Position = 0;

    //                            BitChat.DataReceived(this, new ChatMessage(clearText));
    //                        }
    //                    }
    //                }
    //                else if ((recvPacket.Flags & PacketFlags.FIN) > 0)
    //                {
    //                    CloseSocket();
    //                }

    //                break;

    //                #endregion

    //            case PeerSocketState.FIN_ACK_SENT:
    //                #region FIN + ACK

    //                if ((recvPacket.Flags & PacketFlags.ACK) > 0)
    //                    CloseSocket();
    //                else
    //                    RSTPacketAndCloseSocket(recvPacket);

    //                break;

    //                #endregion
    //        }
    //    }

    //    private void RecvPacket(Packet recvPacket, IPEndPoint remotePeerEP)
    //    {
    //        Debug.Write("PeerSocket.RecvPacket [" + recvPacket.Flags + "]", "seq: " + recvPacket.SeqNumber + ", ack: " + recvPacket.AckNumber);

    //        if ((_state == PeerSocketState.Closed) && (recvPacket.Flags != PacketFlags.SYN))
    //            return; //reject packets if closed


    //        if ((recvPacket.Flags & (PacketFlags.ACK | PacketFlags.RST)) > 0)
    //        {
    //            #region Process ACK RST

    //            //find expected ack
    //            uint expectedAckNumber;

    //            lock (_packetQueue)
    //            {
    //                if (_packetQueue.Count > 0)
    //                    expectedAckNumber = _localSequenceNumber + _bytesSent + _packetQueue.Peek().DataSize + 1;
    //                else
    //                    expectedAckNumber = _localSequenceNumber + _bytesSent + 1;
    //            }

    //            if ((recvPacket.Flags & PacketFlags.RST) > 0)
    //            {
    //                //check ack number
    //                if (expectedAckNumber != recvPacket.AckNumber)
    //                {
    //                    Debug.Write("PeerSocket.RecvPacket [" + recvPacket.Flags + "]", "ack miss match; drop RST; expected: " + expectedAckNumber + ", ack: " + recvPacket.AckNumber);
    //                    return;  //reject old re-transmitted or unknown packet silently
    //                }

    //                CloseSocket();
    //                return;
    //            }

    //            if ((recvPacket.Flags & PacketFlags.ACK) > 0)
    //            {
    //                //check ack number
    //                if (expectedAckNumber != recvPacket.AckNumber)
    //                {
    //                    Debug.Write("PeerSocket.RecvPacket [" + recvPacket.Flags + "]", "ack miss match; drop ACK; expected: " + expectedAckNumber + ", ack: " + recvPacket.AckNumber);
    //                    return;  //reject old re-transmitted or unknown packet silently
    //                }

    //                lock (_packetQueue)
    //                {
    //                    if (_packetQueue.Count == 0)
    //                    {
    //                        if (recvPacket.Flags != PacketFlags.ACK)
    //                            ACKPacket(recvPacket);

    //                        return; //old packet; reject packet with ack to help remote dequeue process
    //                    }

    //                    //de-queue packet from packet queue
    //                    _bytesSent += _packetQueue.Dequeue().DataSize;
    //                    _packetRetransmitCount = 0;
    //                    _packetQueueTimer.Change(0, Timeout.Infinite);
    //                }

    //                if ((recvPacket.Flags == PacketFlags.ACK) && (_state == PeerSocketState.Established))
    //                    return; // only ack packets are for dequeuing in established state, so return.
    //            }

    //            #endregion
    //        }


    //        if (((recvPacket.Flags & (PacketFlags.CERT | PacketFlags.KEY | PacketFlags.DATA | PacketFlags.FIN)) > 0) || (recvPacket.Flags == PacketFlags.NOOP))
    //        {
    //            #region Check SEQ number

    //            //check seq number
    //            if (recvPacket.SeqNumber > _remoteSequenceNumber + _bytesReceived + 1)
    //            {
    //                // invalid seq number; close socket
    //                Debug.Write("PeerSocket.RecvPacket [" + recvPacket.Flags + "]", "invalid seq; rst conn; remote seq: " + recvPacket.SeqNumber + ", expected seq: " + (_remoteSequenceNumber + _bytesReceived + 1));

    //                RSTPacketAndCloseSocket(recvPacket);
    //                return;
    //            }
    //            else if (recvPacket.SeqNumber < _remoteSequenceNumber + _bytesReceived + 1)
    //            {
    //                Debug.Write("PeerSocket.RecvPacket [" + recvPacket.Flags + "]", "invalid seq; ack & drop packet; remote seq: " + recvPacket.SeqNumber + ", expected seq: " + (_remoteSequenceNumber + _bytesReceived + 1));

    //                if ((recvPacket.Flags & (PacketFlags.CERT | PacketFlags.DATA)) > 0)
    //                    ACKPacket(recvPacket);

    //                return; //old packet; reject packet with ack
    //            }

    //            #endregion
    //        }

    //        _bytesReceived += recvPacket.DataSize;
    //        //_remotePeerEP = new IPEndPoint(remotePeerEP.Address, _remotePeerEP.Port);

    //        if ((recvPacket.Flags & (PacketFlags.CERT | PacketFlags.KEY | PacketFlags.DATA)) > 0)
    //        {
    //            receivedDataBuffer.Write(recvPacket.Data, recvPacket.DataOffset, recvPacket.DataSize);

    //            if ((recvPacket.Flags & PacketFlags.PSH) > 0)
    //            {
    //                if ((recvPacket.Flags & PacketFlags.DATA) > 0)
    //                    ACKPacket(recvPacket);

    //                //assemble fragments and process
    //                byte[] buffer = receivedDataBuffer.ToArray();
    //                receivedDataBuffer.Position = 0;
    //                receivedDataBuffer.SetLength(0);

    //                ProcessRecvPacket(recvPacket, remotePeerEP, buffer);
    //            }
    //            else
    //            {
    //                ACKPacket(recvPacket);
    //            }
    //        }
    //        else if (recvPacket.Flags == PacketFlags.NOOP)
    //        {
    //            ACKPacket(recvPacket);
    //        }
    //        else
    //        {
    //            //process other flag packets
    //            ProcessRecvPacket(recvPacket, remotePeerEP, recvPacket.Data);
    //        }
    //    }

    //    private void SendPacketToQueue(PacketFlags flags, byte[] data = null, int dataSize = 0)
    //    {
    //        if (data != null)
    //        {
    //            if (dataSize == 0)
    //                dataSize = Convert.ToUInt16(data.Length);

    //            Debug.Write("PeerSocket.SendPacket [" + flags + "]", "sent " + dataSize + " bytes to " + _remotePeerEP.ToString());

    //            //fragment data and send
    //            int position = 0;

    //            while (position < dataSize)
    //            {
    //                int bytesRemaining = dataSize - position;
    //                ushort packetDataSize;

    //                if (bytesRemaining > MESSAGE_BUFFER_MAX_SIZE)
    //                    packetDataSize = MESSAGE_BUFFER_MAX_SIZE;
    //                else
    //                {
    //                    packetDataSize = Convert.ToUInt16(bytesRemaining);
    //                    flags = flags | PacketFlags.PSH;
    //                }

    //                EnqueuePacket(new Packet(_localPeerID, _remotePeerID, flags, _localSequenceNumber + _bytesSentToQueue + 1, _remoteSequenceNumber + _bytesReceived + 1, data, position, packetDataSize));
    //                position += packetDataSize;

    //                flags = flags & (~PacketFlags.ACK); // remove ACK after first packet. dont repeat ack.
    //            }
    //        }
    //        else
    //        {
    //            //no data to sent here
    //            Debug.Write("PeerSocket.SendPacket [" + flags + "]", "sent to " + _remotePeerEP.ToString());

    //            EnqueuePacket(new Packet(_localPeerID, _remotePeerID, flags, _localSequenceNumber + _bytesSentToQueue + 1, _remoteSequenceNumber + _bytesReceived + 1));
    //        }
    //    }

    //    private void Reconnect()
    //    {
    //        Debug.Write("PeerSocket.Reconnect", "");

    //        //remove this PeerSocket from all chats as its not connected anymores
    //        BitChat.RemovePeerSocket(this);

    //        _state = PeerSocketState.Closed;
    //        _localSequenceNumber = 0;
    //        _remoteSequenceNumber = 0;
    //        _bytesSent = 0;
    //        _bytesSentToQueue = 0;
    //        _bytesReceived = 0;

    //        Connect();
    //    }

    //    private void CloseSocket()
    //    {
    //        Debug.Write("PeerSocket.CloseSocket", "");

    //        _state = PeerSocketState.Closed;
    //        _localSequenceNumber = 0;
    //        _remoteSequenceNumber = 0;
    //        _bytesSent = 0;
    //        _bytesSentToQueue = 0;
    //        _bytesReceived = 0;

    //        //stop NOOP
    //        if (_NOOPTimer != null)
    //        {
    //            _NOOPTimer.Dispose();
    //            _NOOPTimer = null;
    //        }

    //        //stop packet queuing
    //        lock (_packetQueue)
    //        {
    //            _packetQueue.Clear();
    //            _packetRetransmitCount = 0;

    //            if (_packetQueueTimer != null)
    //            {
    //                _packetQueueTimer.Dispose();
    //                _packetQueueTimer = null;
    //            }
    //        }

    //        //remove socket from peer list
    //        _peerSockListLock.AcquireWriterLock(500);
    //        _peerSockList.Remove(this);
    //        _peerSockListLock.ReleaseWriterLock();

    //        BitChat.RemovePeerSocket(this);
    //    }

    //    private void SendSYNPacket(Packet synPacket = null)
    //    {
    //        Debug.Write("PeerSocket.SendSYNPacket", "local seq: " + _localSequenceNumber);

    //        if (synPacket == null)
    //            EnqueuePacket(new Packet(_localPeerID, null, PacketFlags.SYN, _localSequenceNumber));
    //        else
    //            EnqueuePacket(new Packet(_localPeerID, synPacket.FromPeerID, PacketFlags.SYN | PacketFlags.ACK, _localSequenceNumber, synPacket.SeqNumber + synPacket.DataSize + 1));
    //    }

    //    private void ACKPacket(Packet recvPacket)
    //    {
    //        Debug.Write("PeerSocket.ACKPacket", "");

    //        TransmitPacket(new Packet(_localPeerID, recvPacket.FromPeerID, PacketFlags.ACK, 0, recvPacket.SeqNumber + recvPacket.DataSize));
    //    }

    //    private void RSTPacketAndCloseSocket(Packet recvPacket)
    //    {
    //        Debug.Write("PeerSocket.RSTPacketAndCloseSocket", "");

    //        TransmitPacket(new Packet(_localPeerID, recvPacket.FromPeerID, PacketFlags.RST, 0, recvPacket.SeqNumber + recvPacket.DataSize));
    //        CloseSocket();
    //    }

    //    #endregion

    //    #region Properties

    //    public byte[] RemotePeerID
    //    { get { return _remotePeerID; } }

    //    public Certificate RemoteCertificate
    //    { get { return _remoteCertificate; } }

    //    public IPEndPoint RemotePeerEP
    //    { get { return _remotePeerEP; } }

    //    public PeerSocketState State
    //    { get { return _state; } }

    //    #endregion
    //}

    //partial class PeerSocket
    //{
    //    #region Variables

    //    const int PACKET_RETRY_TIME_SECONDS = 5;
    //    const int PACKET_RETRY_MAX_COUNT = 5;

    //    const int NOOP_PACKET_TIME_SECONDS = 30;

    //    Queue<Packet> _packetQueue;
    //    int _packetRetransmitCount;
    //    Timer _packetQueueTimer;

    //    MemoryStream receivedDataBuffer = new MemoryStream(64 * 1024);

    //    Timer _NOOPTimer;

    //    #endregion

    //    #region Packet Queuing

    //    private void InitializePacketQueue()
    //    {
    //        if (_packetQueue == null)
    //            _packetQueue = new Queue<Packet>();
    //        else
    //            _packetQueue.Clear();

    //        _packetRetransmitCount = 0;

    //        if (_packetQueueTimer == null)
    //            _packetQueueTimer = new Timer(TransmitNextPacket, null, Timeout.Infinite, Timeout.Infinite);
    //    }

    //    private void EnqueuePacket(Packet p)
    //    {
    //        lock (_packetQueue)
    //        {
    //            _bytesSentToQueue += p.DataSize;
    //            _packetQueue.Enqueue(p);
    //            if (_packetQueue.Count == 1)
    //                _packetQueueTimer.Change(0, Timeout.Infinite);
    //        }
    //    }

    //    private void TransmitNextPacket(object state)
    //    {
    //        bool RestartTimer = true;
    //        bool ReconnectSocket = false;

    //        try
    //        {
    //            Monitor.Enter(_packetQueue);
    //            try
    //            {
    //                if (_packetQueue.Count == 0)
    //                {
    //                    RestartTimer = false;
    //                    return;
    //                }

    //                if (_packetRetransmitCount >= PACKET_RETRY_MAX_COUNT)
    //                {
    //                    ReconnectSocket = true;
    //                    RestartTimer = false;
    //                    return;
    //                }

    //                TransmitPacket(_packetQueue.Peek());
    //                _packetRetransmitCount++;
    //            }
    //            finally
    //            {
    //                if (RestartTimer && (_packetQueueTimer != null))
    //                    _packetQueueTimer.Change(PACKET_RETRY_TIME_SECONDS * 1000, Timeout.Infinite);

    //                Monitor.Exit(_packetQueue);
    //            }
    //        }
    //        catch (Exception ex)
    //        {
    //            Debug.Write("PeerSocket.TransmitNextPacket", ex);
    //        }
    //        finally
    //        {
    //            if (ReconnectSocket)
    //                Reconnect();
    //        }
    //    }

    //    private void TransmitPacket(Packet p)
    //    {
    //        try
    //        {
    //            lock (_transmitStream)
    //            {
    //                _transmitStream.Position = 0;
    //                p.WriteTo(_transmitStream);
    //                _udpListener.SendTo(_transmitBuffer, (int)_transmitStream.Position, SocketFlags.None, _remotePeerEP);
    //            }

    //            Debug.Write("PeerSocket.TransmitPacket [" + p.Flags + "]", "seq: " + p.SeqNumber + ", ack: " + p.AckNumber + ", sent " + p.DataSize + " bytes to " + _remotePeerEP.ToString());
    //        }
    //        catch (Exception ex)
    //        {
    //            Debug.Write("PeerSocket.TransmitPacket", ex);
    //        }
    //    }

    //    #endregion

    //    #region NOOP

    //    private void NOOPTimerCallback(object state)
    //    {
    //        try
    //        {
    //            if (_state == PeerSocketState.Established)
    //                SendPacketToQueue(PacketFlags.NOOP);
    //            else
    //                _NOOPTimer = null;
    //        }
    //        finally
    //        {
    //            if (_NOOPTimer != null)
    //                _NOOPTimer.Change(NOOP_PACKET_TIME_SECONDS * 1000, Timeout.Infinite);
    //        }
    //    }

    //    #endregion
    //}

    //partial class PeerSocket
    //{
    //    #region Static Variables

    //    const int MESSAGE_BUFFER_MAX_SIZE = 1024; //1K only

    //    static Socket _udpListener;
    //    static Thread _listeningThread;

    //    static Certificate[] _trustedRootCertificates;

    //    static List<PeerSocket> _peerSockList = new List<PeerSocket>();
    //    static ReaderWriterLock _peerSockListLock = new ReaderWriterLock();

    //    static IPEndPoint _externalSelfEP;
    //    static byte[] _localPeerID;
    //    static TrackerClientID _localClientID;

    //    static CryptoContainer _localCryptoContainer;

    //    static Random _rnd;

    //    #endregion

    //    #region Public Static

    //    public static void Startup(IPEndPoint localEP, TrackerClientID localClientID, Certificate[] trustedRootCertificates, CryptoContainer localCryptoContainer)
    //    {
    //        Debug.Write("PeerSocket.Startup", "");

    //        if (_listeningThread == null)
    //        {
    //            _udpListener = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    //            _udpListener.Bind(localEP);

    //            _trustedRootCertificates = trustedRootCertificates;
    //            _localPeerID = localClientID.PeerID;
    //            _localClientID = localClientID;
    //            _localCryptoContainer = localCryptoContainer;

    //            _rnd = new Random(DateTime.UtcNow.Millisecond);

    //            //start receiving data
    //            _listeningThread = new Thread(PeerSocket.RecvDataAsync);
    //            _listeningThread.IsBackground = true;
    //            _listeningThread.Start();
    //        }
    //    }

    //    public static void Shutdown()
    //    {
    //        if (_listeningThread != null)
    //        {
    //            _udpListener.Shutdown(SocketShutdown.Both);

    //            _listeningThread.Abort();
    //            _listeningThread = null;
    //        }
    //    }

    //    public static PeerSocket[] GetPeerConnections(PeerInfo[] peers, EventHandler ConnectedEvent)
    //    {
    //        Debug.Write("PeerSocket.GetPeerConnections", "");

    //        List<PeerSocket> peerSockets = new List<PeerSocket>(peers.Length);

    //        _peerSockListLock.AcquireReaderLock(500);
    //        try
    //        {
    //            foreach (PeerInfo peer in peers)
    //            {
    //                //check if ep is self external ip
    //                if ((_externalSelfEP != null) && (_externalSelfEP.Equals(peer.PeerEP)))
    //                    continue;

    //                //check for peer if its EP is already connected in peer list 

    //                bool peerExists = false;

    //                foreach (PeerSocket peerSock in _peerSockList)
    //                {
    //                    if ((peerSock._state == PeerSocketState.Established) && (peerSock.IsThisPeer(peer.PeerID) || peerSock._remotePeerEP.Equals(peer.PeerEP)))
    //                    {
    //                        peerExists = true;
    //                        peerSockets.Add(peerSock);
    //                        break;
    //                    }
    //                }

    //                if (!peerExists)
    //                {
    //                    PeerSocket newPeerSock = new PeerSocket(peer);

    //                    LockCookie cookie = _peerSockListLock.UpgradeToWriterLock(500);
    //                    _peerSockList.Add(newPeerSock);
    //                    _peerSockListLock.DowngradeFromWriterLock(ref cookie);

    //                    peerSockets.Add(newPeerSock);

    //                    newPeerSock.Connected += ConnectedEvent;
    //                    newPeerSock.Connect();
    //                }
    //            }
    //        }
    //        finally
    //        {
    //            _peerSockListLock.ReleaseLock();
    //        }

    //        return peerSockets.ToArray();
    //    }

    //    public static PeerSocket[] GetPeerConnections(IPEndPoint[] peerEPs, EventHandler ConnectedEvent)
    //    {
    //        Debug.Write("PeerSocket.GetPeerConnections", "");

    //        List<PeerSocket> peerSockets = new List<PeerSocket>(peerEPs.Length);

    //        _peerSockListLock.AcquireReaderLock(500);
    //        try
    //        {
    //            foreach (IPEndPoint peerEP in peerEPs)
    //            {
    //                //check if ep is self external ip
    //                if ((_externalSelfEP != null) && (_externalSelfEP.Equals(peerEP)))
    //                    continue;

    //                //check for peer if its EP is already connected in peer list 

    //                bool peerExists = false;

    //                foreach (PeerSocket peerSock in _peerSockList)
    //                {
    //                    if ((peerSock._state == PeerSocketState.Established) && peerSock._remotePeerEP.Equals(peerEP))
    //                    {
    //                        peerExists = true;
    //                        peerSockets.Add(peerSock);
    //                        break;
    //                    }
    //                }

    //                if (!peerExists)
    //                {
    //                    PeerSocket newPeerSock = new PeerSocket(peerEP);

    //                    LockCookie cookie = _peerSockListLock.UpgradeToWriterLock(500);
    //                    _peerSockList.Add(newPeerSock);
    //                    _peerSockListLock.DowngradeFromWriterLock(ref cookie);

    //                    peerSockets.Add(newPeerSock);

    //                    newPeerSock.Connected += ConnectedEvent;
    //                    newPeerSock.Connect();
    //                }
    //            }
    //        }
    //        finally
    //        {
    //            _peerSockListLock.ReleaseLock();
    //        }

    //        return peerSockets.ToArray();
    //    }

    //    #endregion

    //    #region Private Static

    //    private static UInt32 GetRandomSeqNumber()
    //    {
    //        return (UInt32)_rnd.Next();
    //    }

    //    private static void RecvDataAsync()
    //    {
    //        EndPoint remoteEP = new IPEndPoint(IPAddress.Any, 0);
    //        byte[] bufferRecv = new byte[MESSAGE_BUFFER_MAX_SIZE + 100];
    //        MemoryStream dataRecv = new MemoryStream(bufferRecv);
    //        int bytesRecv;

    //        while (true)
    //        {
    //            try
    //            {
    //                //receive message from remote
    //                bytesRecv = _udpListener.ReceiveFrom(bufferRecv, ref remoteEP);

    //                if (bytesRecv > 0)
    //                {
    //                    #region Parse & Process

    //                    IPEndPoint fromPeerEP = (IPEndPoint)remoteEP;

    //                    //parse packet
    //                    dataRecv.Position = 0;
    //                    Packet recvPacket = new Packet(dataRecv);

    //                    Debug.Write("PeerSocket.RecvDataAsync [" + recvPacket.Flags + "]", "seq: " + recvPacket.SeqNumber + ", ack: " + recvPacket.AckNumber + ", received " + bytesRecv + " bytes from " + fromPeerEP.ToString());

    //                    //discard packets not ment for local peer id

    //                    if ((recvPacket.Flags != PacketFlags.SYN) && (!PeerSocket.PeerIDEquals(_localPeerID, recvPacket.ToPeerID)))
    //                        continue;

    //                    //check for discarding self packets

    //                    if (PeerSocket.PeerIDEquals(_localPeerID, recvPacket.FromPeerID) && (recvPacket.Flags != PacketFlags.RST))
    //                    {
    //                        _externalSelfEP = fromPeerEP;
    //                        PeerSocket.RSTPacket(recvPacket, fromPeerEP);
    //                        continue;
    //                    }


    //                    //check packet flags

    //                    PeerSocket fromPeerSock = null;

    //                    if ((recvPacket.Flags == (PacketFlags.SYN | PacketFlags.ACK)) || (recvPacket.Flags == PacketFlags.RST))
    //                    {
    //                        _peerSockListLock.AcquireReaderLock(500);
    //                        try
    //                        {
    //                            foreach (PeerSocket peerSock in _peerSockList)
    //                            {
    //                                if ((peerSock._state == PeerSocketState.SYN_SENT_1) && (peerSock._localSequenceNumber + peerSock._bytesSentToQueue + 1 == recvPacket.AckNumber))
    //                                {
    //                                    fromPeerSock = peerSock;
    //                                    break;
    //                                }
    //                            }
    //                        }
    //                        finally
    //                        {
    //                            _peerSockListLock.ReleaseLock();
    //                        }

    //                        if (fromPeerSock == null)
    //                        {
    //                            if (recvPacket.Flags != PacketFlags.RST)
    //                                PeerSocket.RSTPacket(recvPacket, fromPeerEP); //reject packet 

    //                            continue;
    //                        }
    //                    }
    //                    else
    //                    {
    //                        _peerSockListLock.AcquireReaderLock(500);
    //                        try
    //                        {
    //                            foreach (PeerSocket peerSock in _peerSockList)
    //                            {
    //                                if (peerSock.IsThisPeer(recvPacket.FromPeerID))
    //                                {
    //                                    fromPeerSock = peerSock;
    //                                    break;
    //                                }
    //                            }

    //                            if (recvPacket.Flags == PacketFlags.SYN)
    //                            {
    //                                if (fromPeerSock == null)
    //                                {
    //                                    //new peer; create new PeerSocket
    //                                    PeerSocket newPeerSock = new PeerSocket(fromPeerEP, recvPacket.FromPeerID);

    //                                    _peerSockListLock.UpgradeToWriterLock(500);
    //                                    _peerSockList.Add(newPeerSock);

    //                                    newPeerSock.Accept(recvPacket, fromPeerEP);
    //                                }
    //                                else if (fromPeerSock._state == PeerSocketState.SYN_SENT_1)
    //                                {
    //                                    if (recvPacket.SeqNumber > fromPeerSock._localSequenceNumber)
    //                                        fromPeerSock.Accept(recvPacket, fromPeerEP);

    //                                    //else ignore SYN packet of remote peer as its seq number is lower
    //                                }
    //                                else if (fromPeerSock._state == PeerSocketState.Established)
    //                                {
    //                                    //peer already exists & connected
    //                                    if (!IsPrivateIPv4(fromPeerSock._remotePeerEP.Address) && IsPrivateIPv4(fromPeerEP.Address))
    //                                    {
    //                                        //existing connection is from public ip and new request is from private ip
    //                                        //prefer private ip over public ip
    //                                        fromPeerSock.Reset();
    //                                        fromPeerSock.Accept(recvPacket, fromPeerEP);
    //                                    }
    //                                    else
    //                                    {
    //                                        //dont accept new PeerSocket connection
    //                                        PeerSocket.RSTPacket(recvPacket, fromPeerEP); //reject packet
    //                                    }
    //                                }
    //                                else
    //                                {
    //                                    //peer not in connected state; accept SYN
    //                                    fromPeerSock.Accept(recvPacket, fromPeerEP);
    //                                }

    //                                continue;
    //                            }

    //                            if (fromPeerSock == null)
    //                            {
    //                                //unknown packet
    //                                PeerSocket.RSTPacket(recvPacket, fromPeerEP); //reject packet 
    //                                continue;
    //                            }
    //                        }
    //                        finally
    //                        {
    //                            _peerSockListLock.ReleaseLock();
    //                        }
    //                    }

    //                    //process per socket basis
    //                    fromPeerSock.RecvPacket(recvPacket, fromPeerEP);

    //                    #endregion
    //                }
    //            }
    //            catch (ThreadAbortException)
    //            {
    //                break;
    //            }
    //            catch (Exception ex)
    //            {
    //                Debug.Write("PeerSocket.RecvDataAsync", ex);
    //            }
    //        }
    //    }

    //    private static void RSTPacket(Packet recvPacket, IPEndPoint toPeerEP)
    //    {
    //        using (MemoryStream mS = new MemoryStream())
    //        {
    //            Packet p = new Packet(_localPeerID, recvPacket.FromPeerID, PacketFlags.RST, 0, recvPacket.SeqNumber + recvPacket.DataSize + 1);
    //            p.WriteTo(mS);
    //            _udpListener.SendTo(mS.ToArray(), (int)mS.Position, SocketFlags.None, toPeerEP);

    //            Debug.Write("PeerSocket.TransmitPacket [" + p.Flags + "]", "seq: " + p.SeqNumber + ", ack: " + p.AckNumber + ", sent " + p.DataSize + " bytes to " + toPeerEP.ToString());
    //        }
    //    }

    //    private static bool PeerIDEquals(byte[] peerID1, byte[] peerID2)
    //    {
    //        for (int i = 0; i < 20; i++)
    //            if (peerID1[i] != peerID2[i])
    //                return false;

    //        return true;
    //    }

    //    private static bool IsPrivateIPv4(IPAddress address)
    //    {
    //        //127.0.0.0 - 127.255.255.255
    //        //10.0.0.0 - 10.255.255.255
    //        //169.254.0.0 - 169.254.255.255
    //        //172.16.0.0 - 172.16.31.255
    //        //192.168.0.0 - 192.168.255.255

    //        byte[] ip = address.GetAddressBytes();

    //        switch (ip[0])
    //        {
    //            case 127:
    //            case 10:
    //                return true;

    //            case 169:
    //                if (ip[1] == 254)
    //                    return true;

    //                return false;

    //            case 172:
    //                if ((ip[1] == 16) && (ip[2] >= 16) && (ip[2] <= 31))
    //                    return true;

    //                return false;

    //            case 192:
    //                if (ip[1] == 168)
    //                    return true;

    //                return false;

    //            default:
    //                return false;
    //        }
    //    }

    //    #endregion

    //    #region Static Properties

    //    public static IPEndPoint LocalEP
    //    { get { return _udpListener.LocalEndPoint as IPEndPoint; } }

    //    public static Certificate[] TrustedCertificates
    //    { get { return _trustedRootCertificates; } }

    //    public static CryptoContainer LocalCryptoContainer
    //    { get { return _localCryptoContainer; } }

    //    public static TrackerClientID LocalClientID
    //    { get { return _localClientID; } }

    //    public static IPEndPoint ExternalSelfEP
    //    { get { return _externalSelfEP; } }

    //    #endregion
    //}

    //enum PacketFlags : byte
    //{
    //    NOOP = 0, // keep alive; no data in this packet
    //    SYN = 1,
    //    ACK = 2, // contains ack number
    //    CERT = 4, // contains data section
    //    KEY = 8, // contains data section
    //    DATA = 16, // contains data section
    //    PSH = 32, // push buffered data up
    //    FIN = 64,
    //    RST = 128
    //}

    //class Packet
    //{
    //    #region Variables

    //    byte _version; //1byte
    //    PacketFlags _flags; //1byte
    //    byte[] _fromPeerID; //20bytes
    //    byte[] _toPeerID; //20bytes; OPTIONAL - not in SYN initial packet
    //    UInt32 _seqNumber; //4bytes OPTIONAL - valid for SYN / CERT / DATA / KEY packets
    //    UInt32 _ackNumber; //4bytes OPTIONAL - valid for ACK / RST packets
    //    ushort _dataSize; //2 bytes data len OPTIONAL - valid only when CERT / DATA / KEY set
    //    byte[] _data;  //n bytes OPTIONAL  - valid only when CERT / DATA / KEY set
    //    int _dataOffset;

    //    #endregion

    //    #region Constructor

    //    private Packet()
    //    { }

    //    public Packet(byte[] fromPeerID, byte[] toPeerID, PacketFlags type, UInt32 seqNumber = 0, UInt32 ackNumber = 0, byte[] data = null, int dataOffset = 0, ushort dataSize = 0)
    //    {
    //        if (fromPeerID.Length != 20)
    //            throw new BitChatException("FromPeerID must be 20 bytes.");

    //        if ((toPeerID != null) && (toPeerID.Length != 20))
    //            throw new BitChatException("ToPeerID must be 20 bytes.");

    //        _version = 1;
    //        _flags = type;

    //        _fromPeerID = fromPeerID;
    //        _toPeerID = toPeerID;

    //        _seqNumber = seqNumber;
    //        _ackNumber = ackNumber;

    //        _data = data;
    //        _dataOffset = dataOffset;
    //        _dataSize = dataSize;

    //        if ((data != null) && (dataSize == 0))
    //            _dataSize = Convert.ToUInt16(data.Length);
    //    }

    //    public Packet(Stream s)
    //    {
    //        BinaryReader bR = new BinaryReader(s);

    //        _version = bR.ReadByte();

    //        switch (_version)
    //        {
    //            case 1:
    //                _flags = (PacketFlags)bR.ReadByte();
    //                _fromPeerID = bR.ReadBytes(20);

    //                if (_flags != PacketFlags.SYN)
    //                    _toPeerID = bR.ReadBytes(20);

    //                if (_flags == PacketFlags.NOOP)
    //                {
    //                    _seqNumber = bR.ReadUInt32();
    //                    return;
    //                }

    //                if ((_flags & (PacketFlags.SYN | PacketFlags.CERT | PacketFlags.KEY | PacketFlags.DATA | PacketFlags.FIN)) > 0)
    //                    _seqNumber = bR.ReadUInt32();

    //                if ((_flags & (PacketFlags.ACK | PacketFlags.RST)) > 0)
    //                    _ackNumber = bR.ReadUInt32();

    //                if ((_flags & (PacketFlags.CERT | PacketFlags.KEY | PacketFlags.DATA)) > 0)
    //                {
    //                    _dataSize = bR.ReadUInt16();
    //                    _dataOffset = 0;
    //                    _data = bR.ReadBytes(_dataSize);
    //                }

    //                break;

    //            default:
    //                throw new BitChatException("BitChat packet format version '" + _version + "' not supported.");
    //        }
    //    }

    //    #endregion

    //    #region Public

    //    public byte[] ToArray()
    //    {
    //        using (MemoryStream mS = new MemoryStream())
    //        {
    //            WriteTo(mS);
    //            return mS.ToArray();
    //        }
    //    }

    //    public void WriteTo(Stream s)
    //    {
    //        BinaryWriter bW = new BinaryWriter(s);

    //        bW.Write(_version);
    //        bW.Write((byte)_flags);
    //        bW.Write(_fromPeerID);

    //        if (_flags != PacketFlags.SYN)
    //            bW.Write(_toPeerID);

    //        if (_flags == PacketFlags.NOOP)
    //        {
    //            bW.Write(_seqNumber);
    //            return;
    //        }

    //        if ((_flags & (PacketFlags.SYN | PacketFlags.CERT | PacketFlags.KEY | PacketFlags.DATA | PacketFlags.FIN)) > 0)
    //            bW.Write(_seqNumber);

    //        if ((_flags & (PacketFlags.ACK | PacketFlags.RST)) > 0)
    //            bW.Write(_ackNumber);

    //        if ((_flags & (PacketFlags.CERT | PacketFlags.KEY | PacketFlags.DATA)) > 0)
    //        {
    //            bW.Write(_dataSize);
    //            bW.Write(_data, _dataOffset, _dataSize);
    //        }

    //        bW.Flush();
    //    }

    //    #endregion

    //    #region Properties

    //    public byte Version
    //    { get { return _version; } }

    //    public byte[] FromPeerID
    //    { get { return _fromPeerID; } }

    //    public byte[] ToPeerID
    //    { get { return _toPeerID; } }

    //    public PacketFlags Flags
    //    { get { return _flags; } }

    //    public UInt32 SeqNumber
    //    { get { return _seqNumber; } }

    //    public UInt32 AckNumber
    //    { get { return _ackNumber; } }

    //    public byte[] Data
    //    { get { return _data; } }

    //    public int DataOffset
    //    { get { return _dataOffset; } }

    //    public ushort DataSize
    //    { get { return _dataSize; } }

    //    #endregion
    //}
}