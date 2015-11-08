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
using System.Net;
using System.Net.Mime;
using System.Net.Sockets;
using TechnitiumLibrary.Net.Proxy;

namespace TechnitiumLibrary.Net
{
    public static class WebUtilities
    {
        public static string GetFormattedSize(double size, int roundToDigits = 2)
        {
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

        public static ContentType GetContentType(string fileName)
        {
            string MimeType = null;

            switch (Path.GetExtension(fileName).ToLower())
            {
                case ".jpg":
                    MimeType = "image/jpeg";
                    break;
                case ".gif":
                    MimeType = "image/gif";
                    break;
                case ".png":
                    MimeType = "image/png";
                    break;
                case ".bmp":
                    MimeType = "image/bmp";
                    break;

                case ".wmv":
                    MimeType = "video/x-ms-wmv";
                    break;
                case ".avi":
                    MimeType = "video/avi";
                    break;
                case ".mpg":
                case ".mpeg":
                case ".mpe":
                    MimeType = "video/mpeg";
                    break;
                case ".flv":
                    MimeType = "video/x-flv";
                    break;
                case ".mp4":
                    MimeType = "video/mp4";
                    break;
                case ".3gpp":
                    MimeType = "video/3gpp";
                    break;
                case ".vob":
                    MimeType = "video/dvd";
                    break;

                case ".mp3":
                    MimeType = "audio/mpeg";
                    break;
                case ".wav":
                    MimeType = "audio/wav";
                    break;

                case ".zip":
                    MimeType = "application/x-zip-compressed";
                    break;
                case ".rar":
                    MimeType = "application/x-rar-compressed";
                    break;
                case ".7z":
                    MimeType = "application/x-7z-compressed";
                    break;
                case ".gz":
                    MimeType = "application/x-compressed";
                    break;
                case ".gzip":
                    MimeType = "application/x-gzip-compressed";
                    break;

                case ".txt":
                case ".log":
                    MimeType = "text/plain";
                    break;
                case ".html":
                case ".htm":
                case ".hta":
                    MimeType = "text/html";
                    break;
                case ".xml":
                    MimeType = "text/xml";
                    break;

                case ".rtf":
                    MimeType = "text/richtext";
                    break;

                case ".aiff":
                    MimeType = "audio/x-aiff";
                    break;
                case ".mid":
                case ".midi":
                    MimeType = "audio/mid";
                    break;
                case ".tiff":
                    MimeType = "image/tiff";
                    break;
                case ".wmf":
                    MimeType = "image/x-wmf";
                    break;
                case ".ai":
                case ".ps":
                case ".eps":
                    MimeType = "application/postscript";
                    break;
                case ".pdf":
                    MimeType = "application/pdf";
                    break;
                case ".class":
                    MimeType = "application/java";
                    break;

                case ".doc":
                case ".dot":
                    MimeType = "application/msword";
                    break;
                case ".docx":
                    MimeType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
                    break;
                case ".dotx":
                    MimeType = "application/vnd.openxmlformats-officedocument.wordprocessingml.template";
                    break;
                case ".docm":
                    MimeType = "application/vnd.ms-word.document.macroEnabled.12";
                    break;
                case ".dotm":
                    MimeType = "application/vnd.ms-word.template.macroEnabled.12";
                    break;

                case ".xls":
                case ".xlt":
                case ".xla":
                    MimeType = "application/vnd.ms-excel";
                    break;
                case ".xlsx":
                    MimeType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
                    break;
                case ".xltx":
                    MimeType = "application/vnd.openxmlformats-officedocument.spreadsheetml.template";
                    break;
                case ".xlsm":
                    MimeType = "application/vnd.ms-excel.sheet.macroEnabled.12";
                    break;
                case ".xltm":
                    MimeType = "application/vnd.ms-excel.template.macroEnabled.12";
                    break;
                case ".xlam":
                    MimeType = "application/vnd.ms-excel.addin.macroEnabled.12";
                    break;
                case ".xlsb":
                    MimeType = "application/vnd.ms-excel.sheet.binary.macroEnabled.12";
                    break;

                case ".ppt":
                case ".pot":
                case ".pps":
                case ".ppa":
                    MimeType = "application/vnd.ms-powerpoint";
                    break;
                case ".pptx":
                    MimeType = "application/vnd.openxmlformats-officedocument.presentationml.presentation";
                    break;
                case ".potx":
                    MimeType = "application/vnd.openxmlformats-officedocument.presentationml.template";
                    break;
                case ".ppsx":
                    MimeType = "application/vnd.openxmlformats-officedocument.presentationml.slideshow";
                    break;
                case ".ppam":
                    MimeType = "application/vnd.ms-powerpoint.addin.macroEnabled.12";
                    break;
                case ".pptm":
                    MimeType = "application/vnd.ms-powerpoint.presentation.macroEnabled.12";
                    break;
                case ".potm":
                    MimeType = "application/vnd.ms-powerpoint.template.macroEnabled.12";
                    break;
                case ".ppsm":
                    MimeType = "application/vnd.ms-powerpoint.slideshow.macroEnabled.12";
                    break;

                case ".xpi":
                    MimeType = "application/x-xpinstall";
                    break;
                case ".torrent":
                    MimeType = "application/x-bittorrent";
                    break;

                default:
                    MimeType = "application/octet-stream";
                    break;
            }

            return new ContentType(MimeType);
        }

        public static Uri GetURIRedirectLocation(Uri sourceUri, WebProxy proxy = null, int timeout = 30000)
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

                            if (TMP.StartsWith("location", StringComparison.CurrentCultureIgnoreCase))
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

        public static bool IsWebAccessible(Uri[] uriCheckList = null, NetProxy proxy = null, bool throwException = false)
        {
            if (uriCheckList == null)
                uriCheckList = new Uri[] { new Uri("https://www.google.com/"), new Uri("https://www.microsoft.com/") };

            using (WebClientEx client = new WebClientEx())
            {
                client.Proxy = proxy;

                Exception lastException = null;

                foreach (Uri uri in uriCheckList)
                {
                    try
                    {
                        client.OpenRead(uri);
                        return true;
                    }
                    catch (Exception ex)
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