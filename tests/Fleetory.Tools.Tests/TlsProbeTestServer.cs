using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

// Disposable certificates and a loopback-only TLS listener. No OS trust changes.
public sealed class TlsProbeTestServer : IDisposable
{
    private readonly TcpListener listener;
    private readonly Thread worker;
    private readonly X509Certificate2 certificate;
    private volatile bool stopped;
    private int requests;
    public int Status = 200;
    public string Location = "";
    public string LastError = "";
    public readonly int Port;
    public int Requests { get { return Interlocked.CompareExchange(ref requests, 0, 0); } }

    public static X509Certificate2 CreateCertificate()
    {
        using (RSA key = RSA.Create())
        {
            key.KeySize = 2048;
            var request = new CertificateRequest("CN=localhost",
                key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            var purposes = new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") };
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(purposes, true));
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName("localhost");
            request.CertificateExtensions.Add(names.Build());
            return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(1));
        }
    }

    public TlsProbeTestServer(X509Certificate2 leaf)
    {
        // This fixture pins a self-signed leaf, without a CRL service. The
        // separate gateway wire test covers a root/intermediate/leaf chain.
        // Schannel needs a temporary user key container, deleted on disposal.
        // Reflection keeps the same fixture compatible with .NET Framework and
        // modern .NET, whose typed certificate-loader API is not in Framework.
        var constructor = typeof(X509Certificate2).GetConstructor(new[] {
            typeof(byte[]), typeof(string), typeof(X509KeyStorageFlags) });
        certificate = (X509Certificate2)constructor.Invoke(new object[] {
            leaf.Export(X509ContentType.Pfx), "", X509KeyStorageFlags.UserKeySet });
        listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        worker = new Thread(Serve) { IsBackground = true };
        worker.Start();
    }

    private void Serve()
    {
        while (!stopped)
        {
            try
            {
                using (TcpClient client = listener.AcceptTcpClient())
                using (var tls = new SslStream(client.GetStream(), false))
                {
                    tls.ReadTimeout = 3000;
                    tls.WriteTimeout = 3000;
                    tls.AuthenticateAsServer(certificate, false, SslProtocols.Tls12, false);
                    using (var reader = new StreamReader(tls, Encoding.ASCII, false, 1024, true))
                    {
                        string requestLine = reader.ReadLine();
                        if (requestLine == null || !requestLine.StartsWith("HEAD / HTTP/1.1", StringComparison.Ordinal))
                            throw new IOException("Expected an HTTP HEAD request.");
                        string line = null;
                        int length = requestLine.Length;
                        while ((line = reader.ReadLine()) != null && line.Length != 0)
                        {
                            length += line.Length;
                            if (length > 4096) throw new IOException("Request headers are too large.");
                        }
                        if (line == null) throw new IOException("Incomplete HTTP headers.");
                    }
                    Interlocked.Increment(ref requests);
                    string headers = "HTTP/1.1 " + Status + " Test\r\nContent-Length: 0\r\nConnection: close\r\n";
                    if (Location.Length != 0) headers += "Location: " + Location + "\r\n";
                    byte[] response = Encoding.ASCII.GetBytes(headers + "\r\n");
                    tls.Write(response, 0, response.Length);
                }
            }
            catch (SocketException error) { LastError = error.Message; return; }
            catch (IOException error) { LastError = error.Message; }
            catch (AuthenticationException error) { LastError = error.ToString(); }
        }
    }

    public void Dispose()
    {
        stopped = true;
        listener.Stop();
        worker.Join(5000);
        certificate.Dispose();
    }
}
