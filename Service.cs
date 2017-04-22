using System;
using System.ServiceProcess;
using System.Threading;

namespace sslendpoint {
    partial class Service : ServiceBase {
        private Thread ServiceThread;

        public Service() {
            InitializeComponent();
        }

        private void ServiceMain() {
            try {
				MainClass.ServiceMain();
            } catch (ThreadInterruptedException) {
            }
        }

        protected override void OnStart(string[] args) {
            ServiceThread = new Thread(ServiceMain);
            ServiceThread.Start();
        }

        protected override void OnStop() {
            ServiceThread.Interrupt();
            ServiceThread.Join();
        }
    }
}
