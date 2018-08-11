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
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace TechnitiumLibrary.Net.BitTorrent
{
    public class TrackerClientID
    {
        #region variables

        static RandomNumberGenerator _rnd = new RNGCryptoServiceProvider();

        byte[] _peerID;
        byte[] _clientKey;

        string _httpUserAgent;
        string _httpAcceptEncoding;

        int _numWant;
        bool _compact;
        bool _noPeerID;

        #endregion

        #region constructor

        public TrackerClientID(byte[] peerID, byte[] clientKey, string httpUserAgent, string httpAcceptEncoding, int numWant, bool compact, bool noPeerID)
        {
            _peerID = peerID;
            _clientKey = clientKey;

            _httpUserAgent = httpUserAgent;
            _httpAcceptEncoding = httpAcceptEncoding;

            _numWant = numWant;
            _compact = compact;
            _noPeerID = noPeerID;
        }

        public TrackerClientID(Stream s)
        {
            ReadFrom(new BinaryReader(s));
        }

        #endregion

        #region private

        private void ReadFrom(BinaryReader bR)
        {
            if (Encoding.ASCII.GetString(bR.ReadBytes(2)) != "ID")
                throw new Exception("Invalid TrackerClientID data format.");

            switch (bR.ReadByte())
            {
                case 1:
                    _peerID = bR.ReadBytes(20);
                    _clientKey = bR.ReadBytes(4);

                    _httpUserAgent = bR.ReadString();
                    _httpAcceptEncoding = bR.ReadString();

                    _numWant = bR.ReadInt32();
                    _compact = bR.ReadBoolean();
                    _noPeerID = bR.ReadBoolean();
                    break;

                default:
                    throw new NotSupportedException("TrackerClientID data format version not supported.");
            }
        }

        #endregion

        #region public static

        public static byte[] GenerateClientKey()
        {
            byte[] clientKey = new byte[4];
            _rnd.GetBytes(clientKey);
            return clientKey;
        }

        public static byte[] GeneratePeerID(string AzureusStyleClientID)
        {
            byte[] peerID = new byte[20];

            Buffer.BlockCopy(Encoding.UTF8.GetBytes("-" + AzureusStyleClientID + "-"), 0, peerID, 0, AzureusStyleClientID.Length + 2);

            byte[] buffRnd = new byte[20 - AzureusStyleClientID.Length - 2];
            _rnd.GetBytes(buffRnd);

            Buffer.BlockCopy(buffRnd, 0, peerID, AzureusStyleClientID.Length + 2, buffRnd.Length);

            return peerID;
        }

        public static TrackerClientID CreateDefaultID()
        {
            return new TrackerClientID(GeneratePeerID("UT3430"), GenerateClientKey(), "uTorrent/343(109551416)(40760)", "gzip", 50, true, true);
        }

        #endregion

        #region public

        public void WriteTo(Stream s)
        {
            BinaryWriter bW = new BinaryWriter(s);

            bW.Write(Encoding.ASCII.GetBytes("ID"));
            bW.Write(Convert.ToByte(1));

            bW.Write(_peerID);
            bW.Write(_clientKey);

            bW.Write(_httpUserAgent);
            bW.Write(_httpAcceptEncoding);

            bW.Write(_numWant);
            bW.Write(_compact);
            bW.Write(_noPeerID);
        }

        #endregion

        #region properties

        public byte[] PeerID
        { get { return _peerID; } }

        public byte[] ClientKey
        { get { return _clientKey; } }

        public string HttpUserAgent
        { get { return _httpUserAgent; } }

        public string HttpAcceptEncoding
        { get { return _httpAcceptEncoding; } }

        public int NumWant
        { get { return _numWant; } }

        public bool Compact
        { get { return _compact; } }

        public bool NoPeerID
        { get { return _noPeerID; } }

        #endregion
    }
}
