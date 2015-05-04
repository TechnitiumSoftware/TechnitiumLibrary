/*
Technitium Library
Copyright (C) 2015  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace TechnitiumLibrary.Net.BitTorrent
{
    class UDPTrackerClient : TrackerClient
    {
        #region variables

        UdpClient _udp;

        Random _rnd = new Random();
        byte[] _connectionID = null;
        byte[] _transactionID = new byte[4];
        DateTime _connectionIDExpires = DateTime.UtcNow;

        #endregion

        #region constructor

        public UDPTrackerClient(Uri trackerURI, byte[] infoHash, TrackerClientID clientID)
            : base(trackerURI, infoHash, clientID)
        {
            _udp = new UdpClient();
            _udp.Client.SendTimeout = 30000;
        }

        #endregion

        #region private

        private byte[] GetConnectionID(byte[] transactionID)
        {
            //Connection_id 64bit 0x41727101980 + action 32bit + transaction_id 32bit (random)
            byte[] requestPacket = new byte[] { 0x0, 0x0, 0x4, 0x17, 0x27, 0x10, 0x19, 0x80, 0x0, 0x0, 0x0, 0x0, transactionID[0], transactionID[1], transactionID[2], transactionID[3] };

            for (int n = 0; n < 8; n++)
            {
                _udp.Client.ReceiveTimeout = Convert.ToInt32(15 * (2 ^ n) * 1000);

                try
                {
                    //SEND CONNECT REQUEST
                    _udp.Send(requestPacket, requestPacket.Length, _trackerURI.Host, _trackerURI.Port);

                    //RECV CONNECT RESPONSE
                    IPEndPoint remoteEP = null;

                    byte[] response = _udp.Receive(ref remoteEP);

                    //check response length
                    if (response.Length < 16)
                        throw new TrackerClientException("Invalid response received for connection request.");

                    //check transaction id
                    for (int j = 0; j < 4; j++)
                        if (response[4 + j] != transactionID[j])
                            throw new TrackerClientException("Invalid transaction id received for connection request.");

                    //check action
                    for (int j = 0; j < 4; j++)
                        if (response[j] != 0)
                            throw new TrackerClientException("Invalid action received for connection request.");

                    byte[] connectionID = new byte[8];

                    Buffer.BlockCopy(response, 8, connectionID, 0, 8);

                    return connectionID;
                }
                catch (SocketException)
                { }
            }

            throw new TrackerClientException("No response from tracker.");
        }

        private byte[] GetAnnounceResponse(byte[] transactionID, byte[] connectionID, TrackerClientEvent @event, IPEndPoint clientEP)
        {
            byte[] request = new byte[98];

            //connection_id 64bit
            Buffer.BlockCopy(connectionID, 0, request, 0, 8);

            //action 32bit
            request[11] = 1;

            //transaction_id 32bit
            Buffer.BlockCopy(transactionID, 0, request, 12, 4);

            //info_hash 20 bytes
            Buffer.BlockCopy(_infoHash, 0, request, 16, 20);

            //peer_id 20 bytes
            Buffer.BlockCopy(_clientID.PeerID, 0, request, 36, 20);

            //downloaded 64bit
            //left 64bit
            //uploaded 64bit

            //event 32bit
            request[83] = Convert.ToByte(@event);

            //ip address 32bit
            if (clientEP.Address.AddressFamily == AddressFamily.InterNetwork)
            {
                switch (clientEP.Address.ToString())
                {
                    case "0.0.0.0":
                    case "127.0.0.1":
                        break;

                    default:
                        Buffer.BlockCopy(clientEP.Address.GetAddressBytes(), 0, request, 84, 4);
                        break;
                }
            }

            //key 32bit
            Buffer.BlockCopy(_clientID.ClientKey, 0, request, 88, 4);

            //num_want
            Buffer.BlockCopy(BitConverter.GetBytes(_clientID.NumWant), 0, request, 92, 4);

            //port 16bit
            byte[] portBuffer = BitConverter.GetBytes(clientEP.Port);
            Array.Reverse(portBuffer);
            Buffer.BlockCopy(portBuffer, 2, request, 96, 2);

            //SEND ANNOUNCE REQUEST
            _udp.Send(request, request.Length, _trackerURI.Host, _trackerURI.Port);

            //RECV ANNOUNCE RESPONSE
            IPEndPoint remoteEP = null;

            byte[] response = _udp.Receive(ref remoteEP);

            //check response length
            if (response.Length < 20)
                throw new TrackerClientException("Invalid response received for announce request.");

            //check response transaction id
            for (int j = 0; j < 4; j++)
                if (response[4 + j] != transactionID[j])
                    throw new TrackerClientException("Invalid transaction id received for announce request.");

            //check response action
            if (response[3] != 1)
                throw new TrackerClientException("Invalid action received for announce request.");

            return response;
        }

        private static List<IPEndPoint> ParsePeers(byte[] response)
        {
            List<IPEndPoint> peers = new List<IPEndPoint>();
            byte[] ipBuffer = new byte[4];
            byte[] portBuffer = new byte[2];
            int n = 0;

            while (response.Length > (25 + 6 * n))
            {
                Buffer.BlockCopy(response, 20 + 6 * n, ipBuffer, 0, 4);
                Buffer.BlockCopy(response, 24 + 6 * n, portBuffer, 0, 2);
                Array.Reverse(portBuffer);

                IPAddress peerIP = new IPAddress(ipBuffer);
                switch (peerIP.ToString())
                {
                    case "0.0.0.0":
                    case "127.0.0.1":
                        break;

                    default:
                        peers.Add(new IPEndPoint(peerIP, BitConverter.ToUInt16(portBuffer, 0)));
                        break;
                }

                n++;
            }

            return peers;
        }

        #endregion

        #region protected

        protected override void UpdateTracker(TrackerClientEvent @event, IPEndPoint clientEP)
        {
            for (int n = 0; n < 8; n++)
            {
                try
                {
                    if ((_connectionID == null) || (_connectionIDExpires <= DateTime.UtcNow))
                    {
                        //GET CONNECTION ID
                        _rnd.NextBytes(_transactionID);
                        _connectionID = GetConnectionID(_transactionID);
                        _connectionIDExpires = DateTime.UtcNow.AddMinutes(1);
                    }
                }
                catch
                { }

                _udp.Client.ReceiveTimeout = Convert.ToInt32(15 * (2 ^ n) * 1000);

                if (_connectionID != null)
                {
                    try
                    {
                        _rnd.NextBytes(_transactionID);
                        byte[] announceResponse = GetAnnounceResponse(_transactionID, _connectionID, @event, clientEP);

                        byte[] buffer = new byte[4];

                        Buffer.BlockCopy(announceResponse, 8, buffer, 0, 4);
                        Array.Reverse(buffer);
                        _interval = BitConverter.ToInt32(buffer, 0);

                        Buffer.BlockCopy(announceResponse, 12, buffer, 0, 4);
                        Array.Reverse(buffer);
                        _leachers = BitConverter.ToInt32(buffer, 0);

                        Buffer.BlockCopy(announceResponse, 16, buffer, 0, 4);
                        Array.Reverse(buffer);
                        _seeders = BitConverter.ToInt32(buffer, 0);

                        _peers = ParsePeers(announceResponse);

                        return;
                    }
                    catch (SocketException)
                    { }
                }
            }

            throw new TrackerClientException("No response from tracker.");
        }

        #endregion
    }
}
