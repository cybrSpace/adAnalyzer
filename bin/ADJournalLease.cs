using System;
using System.IO;
using System.Threading;

namespace ADAnalyzer
{
    public sealed class JournalLease : IDisposable
    {
        private readonly object gate = new object();
        private readonly string path;
        private readonly string planId;
        private readonly string server;
        private readonly object owner;
        private FileStream stream;
        private string journalId;
        private string initialJson;
        private bool fileExpected;

        private JournalLease(string path, string planId, string server, object owner)
        {
            this.path = path;
            this.planId = planId;
            this.server = server;
            this.owner = owner;
            this.stream = File.Open(path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        }

        public static JournalLease Open(string path, string planId, string server, object owner)
        {
            if (String.IsNullOrWhiteSpace(path) || !Path.IsPathRooted(path))
            {
                throw new ArgumentException("An absolute journal path is required.", "path");
            }
            if (owner == null)
            {
                throw new ArgumentNullException("owner");
            }
            return new JournalLease(Path.GetFullPath(path), planId, server, owner);
        }

        public bool IsOwnedBy(object owner)
        {
            return Object.ReferenceEquals(this.owner, owner);
        }

        public void BindInitialRecord(string journalId, string json, bool fileExists)
        {
            RequireOpen();
            if (this.initialJson != null)
            {
                throw new InvalidOperationException("The remediation journal identity is already bound.");
            }
            if (String.IsNullOrEmpty(journalId) || String.IsNullOrEmpty(json))
            {
                throw new ArgumentException("A journal identity and initial record are required.");
            }
            this.journalId = journalId;
            this.initialJson = json;
            this.fileExpected = fileExists;
        }

        public IDisposable EnterOperation()
        {
            if (Monitor.IsEntered(this.gate))
            {
                throw new InvalidOperationException("A remediation journal operation is active.");
            }
            Monitor.Enter(this.gate);
            try
            {
                RequireOpen();
                return new Operation(this.gate);
            }
            catch
            {
                Monitor.Exit(this.gate);
                throw;
            }
        }

        public string GetPath()
        {
            RequireOpen();
            return this.path;
        }

        public string GetInitialJson()
        {
            RequireOpen();
            return this.initialJson;
        }

        public bool ExpectsFile()
        {
            RequireOpen();
            return this.fileExpected;
        }

        public void MarkWritten()
        {
            RequireOpen();
            this.fileExpected = true;
        }

        public bool MatchesIdentity(string planId, string server, string journalId)
        {
            RequireOpen();
            return String.Equals(this.planId, planId, StringComparison.OrdinalIgnoreCase)
                && String.Equals(this.server, server, StringComparison.OrdinalIgnoreCase)
                && String.Equals(this.journalId, journalId, StringComparison.OrdinalIgnoreCase);
        }

        public void Dispose()
        {
            if (Monitor.IsEntered(this.gate))
            {
                throw new InvalidOperationException("A remediation journal operation is active.");
            }
            lock (this.gate)
            {
                FileStream owner = this.stream;
                this.stream = null;
                this.initialJson = null;
                if (owner != null)
                {
                    owner.Dispose();
                }
            }
        }

        private void RequireOpen()
        {
            if (this.stream == null)
            {
                throw new ObjectDisposedException("JournalLease");
            }
        }

        private sealed class Operation : IDisposable
        {
            private object gate;

            public Operation(object gate)
            {
                this.gate = gate;
            }

            public void Dispose()
            {
                if (this.gate != null)
                {
                    Monitor.Exit(this.gate);
                    this.gate = null;
                }
            }
        }
    }
}
