using System;
using System.IO;

namespace sslendpoint {
	public class Logging : Stream {
		private static Stream FileStream;
		private Stream StandardStream;

		public override bool CanRead {
			get {
				return false;
			}
		}

		public override bool CanWrite {
			get {
				return true;
			}
		}

		public override bool CanSeek {
			get {
				return false;
			}
		}

		public override long Length {
			get {
				return StandardStream.Length;
			}
		}

		public override long Position {
			get {
				return StandardStream.Position;
			}
			set {
				throw new InvalidOperationException();
			}
		}

		public override void Flush() {
			FileStream.Flush();
			StandardStream.Flush();
		}

		public override int Read(byte[] buffer, int offset, int count) {
			throw new InvalidOperationException();
		}

		public override void Write(byte[] buffer, int offset, int count) {
			FileStream.Write(buffer, offset, count);
			StandardStream.Write(buffer, offset, count);
			Flush();
		}

		public override long Seek(long offset, SeekOrigin origin) {
			throw new InvalidOperationException();
		}

		public override void SetLength(long length) {
			throw new InvalidOperationException();
		}

		public static void Init() {
			FileStream = File.Create("latest.log");
			StreamWriter stdout = new StreamWriter(new Logging(Console.OpenStandardOutput()));
			stdout.AutoFlush = true;
			Console.SetOut(stdout);
			StreamWriter stderr = new StreamWriter(new Logging(Console.OpenStandardError()));
			stderr.AutoFlush = true;
			Console.SetError(stderr);
		}

		private Logging(Stream stream) {
			StandardStream = stream;
		}
	}
}

