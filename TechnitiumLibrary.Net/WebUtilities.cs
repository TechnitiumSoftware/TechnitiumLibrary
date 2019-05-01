/*
Technitium Library
Copyright (C) 2019  Shreyas Zare (shreyas@technitium.com)

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
using System.Net;
using System.Net.Mime;
using System.Net.Sockets;
using System.Text;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net
{
    public static class WebUtilities
    {
        public static string GetFormattedSize(double size, int roundToDigits = 2)
        {
            if (size < 1000)
                return Math.Round(size, roundToDigits) + " B";

            size = size / 1024;
            if (size < 1000)
                return Math.Round(size, roundToDigits) + " KB";

            size = size / 1024;
            if (size < 1000)
                return Math.Round(size, roundToDigits) + " MB";

            size = size / 1024;
            return Math.Round(size, roundToDigits) + " GB";
        }

        public static string GetFormattedSpeed(double bytesPerSecond, bool bitsPerSecond = true, int roundToDigits = 1)
        {
            if (bitsPerSecond)
            {
                bytesPerSecond = bytesPerSecond * 8;

                if (bytesPerSecond < 1000)
                    return Math.Round(bytesPerSecond, roundToDigits) + " bps";

                bytesPerSecond = bytesPerSecond / 1000;
                if (bytesPerSecond < 1000)
                    return Math.Round(bytesPerSecond, roundToDigits) + " kbps";

                bytesPerSecond = bytesPerSecond / 1000;
                if (bytesPerSecond < 1000)
                    return Math.Round(bytesPerSecond, roundToDigits) + " mbps";

                bytesPerSecond = bytesPerSecond / 1000;
                return Math.Round(bytesPerSecond, roundToDigits) + " gbps";
            }
            else
            {
                if (bytesPerSecond < 1000)
                    return Math.Round(bytesPerSecond, roundToDigits) + " B/s";

                bytesPerSecond = bytesPerSecond / 1024;
                if (bytesPerSecond < 1000)
                    return Math.Round(bytesPerSecond, roundToDigits) + " KB/s";

                bytesPerSecond = bytesPerSecond / 1024;
                if (bytesPerSecond < 1000)
                    return Math.Round(bytesPerSecond, roundToDigits) + " MB/s";

                bytesPerSecond = bytesPerSecond / 1024;
                return Math.Round(bytesPerSecond, roundToDigits) + " GB/s";
            }
        }

        public static string GetFormattedTime(int seconds)
        {
            TimeSpan timeSpan = new TimeSpan(0, 0, seconds);
            StringBuilder sB = new StringBuilder(35);

            if (timeSpan.Days > 0)
            {
                sB.Append(timeSpan.Days);

                if (timeSpan.Days > 1)
                    sB.Append(" days");
                else
                    sB.Append(" day");
            }

            if (timeSpan.Hours > 0)
            {
                if (sB.Length > 0)
                    sB.Append(' ');

                sB.Append(timeSpan.Hours);
                sB.Append(" hour");

                if (timeSpan.Hours > 1)
                    sB.Append("s");
            }

            if (timeSpan.Minutes > 0)
            {
                if (sB.Length > 0)
                    sB.Append(' ');

                sB.Append(timeSpan.Minutes);
                sB.Append(" min");

                if (timeSpan.Minutes > 1)
                    sB.Append("s");
            }

            if ((timeSpan.Seconds > 0) || (sB.Length < 1))
            {
                if (sB.Length > 0)
                    sB.Append(' ');

                sB.Append(timeSpan.Seconds);
                sB.Append(" sec");
            }

            return sB.ToString();
        }

        public static ContentType GetContentType(string fileName)
        {
            string mimeType = null;

            switch (Path.GetExtension(fileName).ToLower())
            {
                case ".js":
                    mimeType = "application/javascript";
                    break;

                case ".css":
                    mimeType = "text/css";
                    break;

                case ".jpg":
                    mimeType = "image/jpeg";
                    break;
                case ".gif":
                    mimeType = "image/gif";
                    break;
                case ".png":
                    mimeType = "image/png";
                    break;
                case ".bmp":
                    mimeType = "image/bmp";
                    break;
                case ".svg":
                    mimeType = "image/svg+xml";
                    break;

                case ".wmv":
                    mimeType = "video/x-ms-wmv";
                    break;
                case ".avi":
                    mimeType = "video/avi";
                    break;
                case ".mpg":
                case ".mpeg":
                case ".mpe":
                    mimeType = "video/mpeg";
                    break;
                case ".flv":
                    mimeType = "video/x-flv";
                    break;
                case ".mp4":
                    mimeType = "video/mp4";
                    break;
                case ".3gpp":
                    mimeType = "video/3gpp";
                    break;
                case ".vob":
                    mimeType = "video/dvd";
                    break;

                case ".mp3":
                    mimeType = "audio/mpeg";
                    break;
                case ".wav":
                    mimeType = "audio/wav";
                    break;

                case ".zip":
                    mimeType = "application/x-zip-compressed";
                    break;
                case ".rar":
                    mimeType = "application/x-rar-compressed";
                    break;
                case ".7z":
                    mimeType = "application/x-7z-compressed";
                    break;
                case ".gz":
                    mimeType = "application/x-compressed";
                    break;
                case ".gzip":
                    mimeType = "application/x-gzip-compressed";
                    break;

                case ".txt":
                case ".log":
                    mimeType = "text/plain";
                    break;
                case ".html":
                case ".htm":
                case ".hta":
                    mimeType = "text/html";
                    break;
                case ".xml":
                    mimeType = "text/xml";
                    break;

                case ".rtf":
                    mimeType = "text/richtext";
                    break;

                case ".aiff":
                    mimeType = "audio/x-aiff";
                    break;
                case ".mid":
                case ".midi":
                    mimeType = "audio/mid";
                    break;
                case ".tiff":
                    mimeType = "image/tiff";
                    break;
                case ".wmf":
                    mimeType = "image/x-wmf";
                    break;
                case ".ai":
                case ".ps":
                case ".eps":
                    mimeType = "application/postscript";
                    break;
                case ".pdf":
                    mimeType = "application/pdf";
                    break;
                case ".class":
                    mimeType = "application/java";
                    break;

                case ".doc":
                case ".dot":
                    mimeType = "application/msword";
                    break;
                case ".docx":
                    mimeType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
                    break;
                case ".dotx":
                    mimeType = "application/vnd.openxmlformats-officedocument.wordprocessingml.template";
                    break;
                case ".docm":
                    mimeType = "application/vnd.ms-word.document.macroEnabled.12";
                    break;
                case ".dotm":
                    mimeType = "application/vnd.ms-word.template.macroEnabled.12";
                    break;

                case ".xls":
                case ".xlt":
                case ".xla":
                    mimeType = "application/vnd.ms-excel";
                    break;
                case ".xlsx":
                    mimeType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
                    break;
                case ".xltx":
                    mimeType = "application/vnd.openxmlformats-officedocument.spreadsheetml.template";
                    break;
                case ".xlsm":
                    mimeType = "application/vnd.ms-excel.sheet.macroEnabled.12";
                    break;
                case ".xltm":
                    mimeType = "application/vnd.ms-excel.template.macroEnabled.12";
                    break;
                case ".xlam":
                    mimeType = "application/vnd.ms-excel.addin.macroEnabled.12";
                    break;
                case ".xlsb":
                    mimeType = "application/vnd.ms-excel.sheet.binary.macroEnabled.12";
                    break;

                case ".ppt":
                case ".pot":
                case ".pps":
                case ".ppa":
                    mimeType = "application/vnd.ms-powerpoint";
                    break;
                case ".pptx":
                    mimeType = "application/vnd.openxmlformats-officedocument.presentationml.presentation";
                    break;
                case ".potx":
                    mimeType = "application/vnd.openxmlformats-officedocument.presentationml.template";
                    break;
                case ".ppsx":
                    mimeType = "application/vnd.openxmlformats-officedocument.presentationml.slideshow";
                    break;
                case ".ppam":
                    mimeType = "application/vnd.ms-powerpoint.addin.macroEnabled.12";
                    break;
                case ".pptm":
                    mimeType = "application/vnd.ms-powerpoint.presentation.macroEnabled.12";
                    break;
                case ".potm":
                    mimeType = "application/vnd.ms-powerpoint.template.macroEnabled.12";
                    break;
                case ".ppsm":
                    mimeType = "application/vnd.ms-powerpoint.slideshow.macroEnabled.12";
                    break;

                case ".xpi":
                    mimeType = "application/x-xpinstall";
                    break;
                case ".torrent":
                    mimeType = "application/x-bittorrent";
                    break;

                case ".woff":
                    mimeType = "font/x-woff";
                    break;

                default:
                    mimeType = "application/octet-stream";
                    break;
            }

            return new ContentType(mimeType);
        }

        public static Uri GetUriRedirectLocation(Uri sourceUri, WebProxy proxy = null, int timeout = 30000)
        {
            using (TcpClient sock = new TcpClient())
            {
                if (proxy == null)
                    sock.Connect(sourceUri.Host, sourceUri.Port);
                else
                    sock.Connect(proxy.Address.Host, proxy.Address.Port);

                StreamWriter sW = new StreamWriter(sock.GetStream());
                if (sW.BaseStream.CanTimeout)
                    sW.BaseStream.WriteTimeout = timeout;

                sW.WriteLine("GET " + sourceUri.PathAndQuery + " HTTP/1.1\r\nHost: " + sourceUri.Host + "\r\nAccept: */*\r\nConection: close\r\n");
                sW.Flush();

                StreamReader sR = new StreamReader(sock.GetStream());
                if (sR.BaseStream.CanTimeout)
                    sR.BaseStream.ReadTimeout = timeout;

                string TMP = sR.ReadLine();
                string[] RetVal = TMP.Split(' ');

                switch (RetVal[1])
                {
                    case "302":
                        while (true)
                        {
                            TMP = sR.ReadLine();
                            if (string.IsNullOrEmpty(TMP))
                                break;

                            if (TMP.StartsWith("location", StringComparison.OrdinalIgnoreCase))
                            {
                                int i = TMP.IndexOf(':');
                                if (i > -1)
                                    return new Uri(TMP.Substring(i + 1).Trim());
                            }
                        }

                        throw new WebException("Server did not provide redirect location in response header for HTTP location: " + sourceUri.AbsolutePath);

                    case "200":
                        return sourceUri;

                    default:
                        throw new WebException("Error while opening location: " + sourceUri.AbsoluteUri + ", HTTP response: " + TMP);
                }
            }
        }

        public static bool IsWebAccessible(Uri[] uriCheckList = null, NetProxy proxy = null, WebClientExNetworkType networkType = WebClientExNetworkType.Default, int timeout = 10000, bool throwException = false)
        {
            if (uriCheckList == null)
                uriCheckList = new Uri[] { new Uri("https://www.google.com/"), new Uri("https://www.microsoft.com/") };

            using (WebClientEx client = new WebClientEx())
            {
                client.Proxy = proxy;
                client.NetworkType = networkType;
                client.Timeout = timeout;

                Exception lastException = null;

                foreach (Uri uri in uriCheckList)
                {
                    try
                    {
                        client.OpenRead(uri);
                        return true;
                    }
                    catch (WebException ex)
                    {
                        lastException = ex;
                    }
                }

                if (throwException)
                    throw lastException;
            }

            return false;
        }
    }
}