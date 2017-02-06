using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace sslendpoint {
	static class MainClass {
		private static string SslIp;
		private static int SslPort;
		private static string PlainIp;
		private static int PlainPort;
		private static X509Certificate2 Cert;

		private static void ParseArgs(string[] args) {
			if (args.Length < 1) {
				Console.Error.WriteLine("Invalid ssl IP address");
				Environment.Exit(1);
			}
			SslIp = args[0];
			if (args.Length < 2 || !int.TryParse(args[1], out SslPort)) {
				Console.Error.WriteLine("Invalid ssl port");
				Environment.Exit(1);
			}
			if (SslPort < IPEndPoint.MinPort || SslPort > IPEndPoint.MaxPort) {
				Console.Error.WriteLine("Invalid ssl port");
				Environment.Exit(1);
			}
			if (args.Length < 3) {
				Console.Error.WriteLine("Invalid plain IP address");
				Environment.Exit(1);
			}
			PlainIp = args[2];
			if (args.Length < 4 || !int.TryParse(args[3], out PlainPort)) {
				Console.Error.WriteLine("Invalid plain port");
				Environment.Exit(1);
			}
			if (PlainPort < IPEndPoint.MinPort || PlainPort > IPEndPoint.MaxPort) {
				Console.Error.WriteLine("Invalid plain port");
				Environment.Exit(1);
			}
		}

		private static void GenerateSSLCert() {
			CspParameters cp = new CspParameters();
			cp.KeyContainerName = string.Format("github-zachdeibert-ssl-endpoint-", SslIp);
			RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(cp);
			Mono.Security.X509.X509CertificateBuilder bldr = new Mono.Security.X509.X509CertificateBuilder();
			DateTime now = DateTime.UtcNow;
			bldr.NotAfter = now.AddYears(10);
			bldr.NotBefore = now;
			bldr.IssuerName = bldr.SubjectName = string.Concat("CN=", SslIp);
			bldr.SubjectPublicKey = rsa;
			byte[] cert = bldr.Sign(rsa);
			Cert = new X509Certificate2(cert);
			Cert.PrivateKey = rsa;
		}

		private static void ReadSSLCert() {
			X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
			store.Open(OpenFlags.ReadWrite);
			X509CertificateCollection certs = store.Certificates.Find(X509FindType.FindBySubjectName, SslIp, false);
			if (certs.Count > 0) {
				Cert = (X509Certificate2) certs[0];
				CspParameters cp = new CspParameters();
				cp.KeyContainerName = string.Format("github-zachdeibert-ssl-endpoint-", SslIp);
				Cert.PrivateKey = new RSACryptoServiceProvider(cp);
			} else {
				GenerateSSLCert();
				store.Add(Cert);
			}
			store.Close();
		}

		private static bool Ping(string ip, int port) {
			try {
				using (TcpClient client = new TcpClient(ip, port)) {
					return client.Connected;
				}
			} catch (SocketException) {
			}
			return false;
		}

		private static void WriteCallback(IAsyncResult iar) {
			AsyncData data = (AsyncData) iar.AsyncState;
			data.To.EndWrite(iar);
			if (data.Client.Connected) {
				data.From.BeginRead(data.Buffer, 0, data.Buffer.Length, ReadCallback, data);
			}
		}

		private static void ReadCallback(IAsyncResult iar) {
			AsyncData data = (AsyncData) iar.AsyncState;
			int length = data.From.EndRead(iar);
			if (data.Proxy.Connected) {
				data.To.BeginWrite(data.Buffer, 0, length, WriteCallback, data);
			}
		}

		private static void MainLoop(string listenIp, int listenPort, string toIp, int toPort, Func<Stream, Stream> listenStream, Func<Stream, Stream> toStream) {
			IPAddress[] addrs = Dns.GetHostAddresses(listenIp);
			if (addrs.Length > 0) {
				TcpListener listener = new TcpListener(addrs[0], listenPort);
				try {
					listener.Start();
					TcpClient client;
					while ((client = listener.AcceptTcpClient()) != null) {
						TcpClient proxy = new TcpClient(toIp, toPort);
						Stream listen = listenStream(client.GetStream());
						Stream to = toStream(proxy.GetStream());
						AsyncData listenData = new AsyncData(client, proxy, listen, to);
						listen.BeginRead(listenData.Buffer, 0, listenData.Buffer.Length, ReadCallback, listenData);
						AsyncData toData = new AsyncData(client, proxy, to, listen);
						to.BeginRead(toData.Buffer, 0, toData.Buffer.Length, ReadCallback, toData);
					}
				} finally {
					listener.Stop();
				}
			} else {
				Console.Error.WriteLine("Unable to resolve domain name '{0}'", listenIp);
			}
		}

		public static void Main(string[] args) {
			ParseArgs(args);
			ReadSSLCert();
			int lastMessage = 0;
			while (true) {
				try {
					if (Ping(SslIp, SslPort)) {
						if (Ping(PlainIp, PlainPort)) {
							// Both addresses are bound
							if (lastMessage != 1) {
								Console.Error.WriteLine("Both addresses are bound");
								lastMessage = 1;
							}
						} else {
							// Start SSL -> Plain
							if (lastMessage != 2) {
								Console.WriteLine("Listening on the plain port and connecting to the SSL port");
								lastMessage = 2;
							}
							MainLoop(PlainIp, PlainPort, SslIp, SslPort, s => s, s => {
								SslStream ssl = new SslStream(s);
								ssl.AuthenticateAsClient(SslIp);
								return ssl;
							});
						}
					} else if (Ping(PlainIp, PlainPort)) {
						// Start Plain -> SSL
						if (lastMessage != 3) {
							Console.WriteLine("Listening on the SSL port and connecting to the plain port");
							lastMessage = 3;
						}
						MainLoop(SslIp, SslPort, PlainIp, PlainPort, s => {
							SslStream ssl = new SslStream(s);
							ssl.AuthenticateAsServer(Cert);
							return ssl;
						}, s => s);
					} else {
						// Neither address is bound
						if (lastMessage != 4) {
							Console.Error.WriteLine("Neither address is bound");
							lastMessage = 4;
						}
					}
					Thread.Sleep(10000);
				} catch (IOException ex) {
					Console.Error.WriteLine(ex);
				}
			}
		}
	}
}
