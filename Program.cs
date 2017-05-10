using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Threading;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace sslendpoint {
	static class MainClass {
		private static string SslIp;
		private static int SslPort;
		private static string PlainIp;
		private static int PlainPort;
		private static System.Security.Cryptography.X509Certificates.X509Certificate2 Cert;

		private static void ParseArgs(string[] args) {
			if (args.Length == 0) {
				ServiceBase.Run(new Service());
			}
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
			CryptoApiRandomGenerator randomGenerator = new CryptoApiRandomGenerator();
			SecureRandom random = new SecureRandom(randomGenerator);
			X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
			X509Name subjectDN = new X509Name(string.Concat("CN=", SslIp));
			certificateGenerator.SetIssuerDN(subjectDN);
			certificateGenerator.SetSubjectDN(subjectDN);
			DateTime now = DateTime.UtcNow;
			certificateGenerator.SetNotBefore(now);
			certificateGenerator.SetNotAfter(now.AddYears(10));
			certificateGenerator.SetSerialNumber(BigInteger.One);
			KeyGenerationParameters genParams = new KeyGenerationParameters(random, 2048);
			RsaKeyPairGenerator generator = new RsaKeyPairGenerator();
			generator.Init(genParams);
			AsymmetricCipherKeyPair kp = generator.GenerateKeyPair();
			certificateGenerator.SetPublicKey(kp.Public);
			X509Certificate cert = certificateGenerator.Generate(new Asn1SignatureFactory("SHA512WITHRSA", kp.Private, random));
			PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp.Private);
			Cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(DotNetUtilities.ToX509Certificate(cert));
			Asn1Sequence seq = (Asn1Sequence) Asn1Object.FromByteArray(info.ParsePrivateKey().GetDerEncoded());
			RsaPrivateKeyStructure rsa = RsaPrivateKeyStructure.GetInstance(seq);
			RsaPrivateCrtKeyParameters rsaParams = new RsaPrivateCrtKeyParameters(rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1, rsa.Exponent2, rsa.Coefficient);
			RSA priv = DotNetUtilities.ToRSA(rsaParams);
			Cert.PrivateKey = priv;
			CspParameters csp = new CspParameters();
			csp.KeyContainerName = string.Concat("github-zachdeibert-ssl-endpoint-", SslIp);
			RSACryptoServiceProvider store = new RSACryptoServiceProvider(csp);
			store.ImportParameters(priv.ExportParameters(true));
			store.PersistKeyInCsp = true;
		}

		private static void ReadSSLCert() {
			System.Security.Cryptography.X509Certificates.X509Store store = new System.Security.Cryptography.X509Certificates.X509Store(System.Security.Cryptography.X509Certificates.StoreName.My, System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser);
			store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadWrite);
			System.Security.Cryptography.X509Certificates.X509CertificateCollection certs = store.Certificates.Find(System.Security.Cryptography.X509Certificates.X509FindType.FindBySubjectName, SslIp, false);
			do {
				if (certs.Count > 0) {
					Cert = (System.Security.Cryptography.X509Certificates.X509Certificate2) certs[0];
					if (Cert.NotAfter < DateTime.Now) {
						store.Remove(Cert);
						Cert = null;
						continue;
					}
					CspParameters csp = new CspParameters();
					csp.KeyContainerName = string.Concat("github-zachdeibert-ssl-endpoint-", SslIp);
					Cert.PrivateKey = new RSACryptoServiceProvider(csp);
				} else {
					GenerateSSLCert();
					store.Add(Cert);
				}
			} while (Cert == null);
			store.Close();
		}

		private static bool Ping(string ip, int port) {
			try {
				using (TcpClient client = new TcpClient(ip, port)) {
					return client.Connected;
				}
			} catch (Exception) {
			}
			return false;
		}

		private static void WriteCallback(IAsyncResult iar) {
			AsyncData data = (AsyncData) iar.AsyncState;
			try {
				data.To.EndWrite(iar);
				if (data.Client.Connected) {
					data.From.BeginRead(data.Buffer, 0, data.Buffer.Length, ReadCallback, data);
				}
			} catch (Exception ex) {
				Console.Error.WriteLine(ex);
				try {
					data.To.Close();
					data.From.Close();
					data.Client.Close();
					data.Proxy.Close();
					data.To.Dispose();
					data.From.Dispose();
				} catch {
				}
			}
		}

		private static void ReadCallback(IAsyncResult iar) {
			AsyncData data = (AsyncData) iar.AsyncState;
			try {
				int length = data.From.EndRead(iar);
				if (data.Proxy.Connected) {
					data.To.BeginWrite(data.Buffer, 0, length, WriteCallback, data);
				}
			} catch (Exception ex) {
				Console.Error.WriteLine(ex);
				try {
					data.To.Close();
					data.From.Close();
					data.Client.Close();
					data.Proxy.Close();
					data.To.Dispose();
					data.From.Dispose();
				} catch {
				}
			}
		}

		private static void MainLoop(string listenIp, int listenPort, string toIp, int toPort, Func<Stream, Stream> listenStream, Func<Stream, Stream> toStream) {
            IPAddress[] addrs;
            try {
                addrs = Dns.GetHostAddresses(listenIp);
            } catch (Exception) {
				try {
	                addrs = new IPAddress[] {
	                    IPAddress.Parse(listenIp)
	                };
				} catch (Exception ex) {
					Console.Error.WriteLine(ex);
					addrs = new IPAddress[] {
						IPAddress.Any
					};
				}
            }
			if (addrs.Length > 0) {
				TcpListener listener = new TcpListener(addrs[0], listenPort);
				try {
					listener.Start();
					TcpClient client;
					while ((client = listener.AcceptTcpClient()) != null) {
						try {
							TcpClient proxy = new TcpClient(toIp, toPort);
							Stream listen = listenStream(client.GetStream());
							Stream to = toStream(proxy.GetStream());
							AsyncData listenData = new AsyncData(client, proxy, listen, to);
							listen.BeginRead(listenData.Buffer, 0, listenData.Buffer.Length, ReadCallback, listenData);
							AsyncData toData = new AsyncData(client, proxy, to, listen);
							to.BeginRead(toData.Buffer, 0, toData.Buffer.Length, ReadCallback, toData);
						} catch (Exception ex) {
							Console.Error.WriteLine(ex);
						}
					}
				} finally {
					listener.Stop();
				}
			} else {
				Console.Error.WriteLine("Unable to resolve domain name '{0}'", listenIp);
			}
		}

		private static void Start() {
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

		public static void ServiceMain() {
            try {
                Logging.Init();
                string asm = Uri.UnescapeDataString(new UriBuilder(Assembly.GetExecutingAssembly().CodeBase).Path);
                string config = Path.Combine(Path.GetDirectoryName(asm), string.Concat(Path.GetFileName(asm), ".txt"));
                ParseArgs(File.ReadAllLines(config));
                Start();
            } catch (Exception ex) {
                Console.Error.WriteLine(ex);
            }
		}

		public static void Main(string[] args)
        {
            try {
                Logging.Init();
			    ParseArgs(args);
			    Start();
            } catch (Exception ex) {
                Console.Error.WriteLine(ex);
            }
        }
	}
}
