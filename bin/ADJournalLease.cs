using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
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

    // The persistent account reservation is independent of the caller's journal.
    // A missing disposition after reservation is treated as uncertain on restart.
    public sealed class AccountEffectReservation
    {
        private const int MaxRecordBytes = 1024;
        private const string FailureContextKey = "ADAnalyzer.RemediationReservation";
        private static readonly Encoding RecordEncoding = new UTF8Encoding(false, true);
        private readonly string path;
        private readonly string record;
        private readonly Guid account;
        private readonly Guid attempt;
        private bool mayHaveDispatched;

        private AccountEffectReservation(string path, string record, Guid account, Guid attempt)
        {
            this.path = path;
            this.record = record;
            this.account = account;
            this.attempt = attempt;
        }

        public static AccountEffectReservation Acquire(string directory, Guid account, bool undo)
        {
            string path = ReservationPath(directory, account);
            Guid attempt = Guid.NewGuid();
            string record = "Status=Uncertain\n"
                + "AttemptId=" + attempt.ToString("D") + "\n"
                + "Account=" + account.ToString("D") + "\n"
                + "Operation=" + (undo ? "Undo" : "Apply") + "\n"
                + "CreatedUtc=" + DateTimeOffset.UtcNow.ToString("o", CultureInfo.InvariantCulture) + "\n"
                + "LastConfirmedStep=AccountReserved\n";

            FileStream stream;
            try
            {
                // CreateNew is the only admission decision. An unreadable or
                // incomplete existing reservation also prevents dispatch.
                stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read,
                    4096, FileOptions.WriteThrough);
            }
            catch (IOException failure)
            {
                if (File.Exists(path) || Directory.Exists(path))
                {
                    throw new InvalidOperationException(ConflictMessage(path, account), failure);
                }
                throw;
            }
            catch (UnauthorizedAccessException failure)
            {
                if (File.Exists(path) || Directory.Exists(path))
                {
                    throw new InvalidOperationException(ConflictMessage(path, account), failure);
                }
                throw;
            }

            // Keep any file that survives a failed write or flush. Its owner
            // cannot prove that a complete reservation was established.
            using (stream)
            {
                byte[] bytes = RecordEncoding.GetBytes(record);
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(true);
            }
            return new AccountEffectReservation(path, record, account, attempt);
        }

        public static Dictionary<string, object> Inspect(string directory, Guid account)
        {
            string path = ReservationPath(directory, account);
            Dictionary<string, object> observation = new Dictionary<string, object>
            {
                { "Status", "Indeterminate" },
                { "AttemptId", null },
                { "Operation", null },
                { "CreatedUtc", null },
                { "LastConfirmedStep", null }
            };
            try
            {
                if (Environment.OSVersion.Platform == PlatformID.Win32NT
                    && !IsFixedInspectionDirectory(directory))
                {
                    return observation;
                }
                File.GetAttributes(path);
            }
            catch (FileNotFoundException)
            {
                if (Directory.Exists(directory))
                {
                    observation["Status"] = "NotObserved";
                }
                return observation;
            }
            catch (IOException)
            {
                return observation;
            }
            catch (UnauthorizedAccessException)
            {
                return observation;
            }

            // A record observed here can disappear or become unreadable before
            // the bounded read. Preserve Indeterminate in that case.
            string record = ReadRecord(path);
            if (record == null)
            {
                return observation;
            }

            string[] lines = record.Split('\n');
            Guid attempt;
            DateTimeOffset created;
            if (lines.Length == 7
                && lines[0] == "Status=Uncertain"
                && lines[1].StartsWith("AttemptId=", StringComparison.Ordinal)
                && Guid.TryParseExact(lines[1].Substring("AttemptId=".Length), "D", out attempt)
                && attempt != Guid.Empty
                && lines[2] == "Account=" + account.ToString("D")
                && (lines[3] == "Operation=Apply" || lines[3] == "Operation=Undo")
                && lines[4].StartsWith("CreatedUtc=", StringComparison.Ordinal)
                && DateTimeOffset.TryParseExact(lines[4].Substring("CreatedUtc=".Length), "o",
                    CultureInfo.InvariantCulture, DateTimeStyles.None, out created)
                && created.Offset == TimeSpan.Zero
                && lines[5] == "LastConfirmedStep=AccountReserved"
                && lines[6] == String.Empty)
            {
                observation["Status"] = "Held";
                observation["AttemptId"] = attempt;
                observation["Operation"] = lines[3].Substring("Operation=".Length);
                observation["CreatedUtc"] = created;
                observation["LastConfirmedStep"] = "AccountReserved";
            }
            return observation;
        }

        private static bool IsFixedInspectionDirectory(string directory)
        {
            string root = Path.GetPathRoot(directory);
            if (root == null || root.Length != 3 || root[1] != ':' || new DriveInfo(root).DriveType != DriveType.Fixed)
            {
                return false;
            }

            // Inspect ancestors before descendants so a redirected path cannot
            // lead this low-level read into a different authority or drive.
            Stack<DirectoryInfo> components = new Stack<DirectoryInfo>();
            for (DirectoryInfo component = new DirectoryInfo(directory); component != null; component = component.Parent)
            {
                components.Push(component);
            }
            foreach (DirectoryInfo component in components)
            {
                if ((component.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    return false;
                }
            }
            return true;
        }

        private static string ReservationPath(string directory, Guid account)
        {
            if (account == Guid.Empty)
            {
                throw new ArgumentException("A canonical account GUID is required.", "account");
            }
            if (String.IsNullOrEmpty(directory) || !Path.IsPathRooted(directory))
            {
                throw new ArgumentException("The remediation authority must use a local absolute path.", "directory");
            }
            return Path.Combine(directory, account.ToString("N") + ".hold");
        }

        public void BeginDispatch()
        {
            if (mayHaveDispatched)
            {
                throw new InvalidOperationException("This account reservation already admitted a dispatch.");
            }
            // Verify ownership again immediately before entering the provider.
            RequireOwnedRecord();
            mayHaveDispatched = true;
        }

        public void ReleaseBeforeDispatch()
        {
            if (!mayHaveDispatched)
            {
                Release();
            }
        }

        public void TryAttachFailureContext(Exception failure)
        {
            if (!mayHaveDispatched || failure == null)
            {
                return;
            }

            try
            {
                // Exception implementations can supply executable or read-only
                // Data. Optional diagnostics must keep the original failure.
                var property = failure.GetType().GetProperty("Data");
                var getter = property == null ? null : property.GetGetMethod();
                if (getter == null || getter.DeclaringType != typeof(Exception))
                {
                    return;
                }

                IDictionary data = failure.Data;
                if (!data.IsReadOnly && !data.Contains(FailureContextKey))
                {
                    data.Add(FailureContextKey, new Dictionary<string, object>
                    {
                        { "ObjectGuid", account },
                        { "AttemptId", attempt },
                        { "Status", "Uncertain" },
                        { "LastConfirmedStep", "AccountReserved" }
                    });
                }
            }
            catch (Exception)
            {
                // Preserve the original exception if its metadata is unavailable.
            }
        }

        public void ReleaseAfterRecordedCompletion()
        {
            if (!mayHaveDispatched)
            {
                throw new InvalidOperationException("No account dispatch was recorded for this reservation.");
            }

            try
            {
                Release();
            }
            catch (Exception failure)
            {
                throw new InvalidOperationException(
                    "The verified result was recorded, but the account reservation could not be released.", failure);
            }
        }

        private void Release()
        {
            RequireOwnedRecord();
            File.Delete(path);
        }

        private void RequireOwnedRecord()
        {
            if (!String.Equals(ReadRecord(path), record, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("The remediation account reservation changed or is unavailable.");
            }
        }

        private static string ConflictMessage(string path, Guid account)
        {
            string message = "An earlier remediation attempt for account " + account.ToString("D")
                + " is active or Uncertain. No directory write was attempted.";
            string existing = ReadRecord(path);
            if (existing != null)
            {
                string[] lines = existing.Split('\n');
                Guid attempt;
                if (lines.Length == 7 && lines[0] == "Status=Uncertain"
                    && lines[1].StartsWith("AttemptId=", StringComparison.Ordinal)
                    && Guid.TryParseExact(lines[1].Substring("AttemptId=".Length), "D", out attempt)
                    && lines[2] == "Account=" + account.ToString("D")
                    && lines[5] == "LastConfirmedStep=AccountReserved")
                {
                    message += " Attempt " + attempt.ToString("D") + ". Last confirmed step: AccountReserved.";
                }
            }
            return message;
        }

        private static string ReadRecord(string path)
        {
            try
            {
                if ((File.GetAttributes(path) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
                {
                    return null;
                }
                using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete))
                {
                    long length = stream.Length;
                    if (length < 1 || length > MaxRecordBytes)
                    {
                        return null;
                    }
                    byte[] bytes = new byte[(int)length];
                    int offset = 0;
                    while (offset < bytes.Length)
                    {
                        int count = stream.Read(bytes, offset, bytes.Length - offset);
                        if (count == 0)
                        {
                            return null;
                        }
                        offset += count;
                    }
                    return stream.ReadByte() == -1 ? RecordEncoding.GetString(bytes) : null;
                }
            }
            catch (IOException)
            {
                return null;
            }
            catch (UnauthorizedAccessException)
            {
                return null;
            }
            catch (DecoderFallbackException)
            {
                return null;
            }
        }
    }
}
