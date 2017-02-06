using System;
using System.IO;
using System.Net.Sockets;

namespace sslendpoint {
	public class AsyncData {
		public TcpClient Client;
		public TcpClient Proxy;
		public Stream From;
		public Stream To;
		public byte[] Buffer;

		public AsyncData(TcpClient client, TcpClient proxy, Stream from, Stream to) {
			Client = client;
			Proxy = proxy;
			From = from;
			To = to;
			Buffer = new byte[4096];
		}
	}
}

