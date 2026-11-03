using System;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Vantor.Services
{
    public class VantorIpcClient : IVantorIpcClient, IDisposable
    {
        private const string PipeName = "VantorSecurityIPC";
        private readonly Timer? _heartbeatTimer;
        private bool _isConnected;
        private bool _isDisposed;
        private readonly SemaphoreSlim _lock = new(1, 1);

        public event Action<bool>? ConnectionStateChanged;

        public bool IsConnected
        {
            get => _isConnected;
            private set
            {
                if (_isConnected != value)
                {
                    _isConnected = value;
                    ConnectionStateChanged?.Invoke(_isConnected);
                }
            }
        }

        public VantorIpcClient()
        {
            _heartbeatTimer = new Timer(async _ => await CheckHeartbeatAsync(), null, Timeout.Infinite, Timeout.Infinite);
        }

        public void StartHeartbeat()
        {
            _heartbeatTimer?.Change(TimeSpan.Zero, TimeSpan.FromSeconds(1.5));
        }

        public void StopHeartbeat()
        {
            _heartbeatTimer?.Change(Timeout.Infinite, Timeout.Infinite);
        }

        private async Task CheckHeartbeatAsync()
        {
            if (_isDisposed) return;
            bool ok = await PingAsync();
            IsConnected = ok;
        }

        public async Task<bool> PingAsync()
        {
            string? resp = await SendCommandAsync("{\"cmd\":\"ping\"}", 400);
            return resp != null && resp.Contains("pong");
        }

        public async Task<string?> SendCommandAsync(string jsonPayload, int timeoutMs = 1500)
        {
            await _lock.WaitAsync();
            try
            {
                return await Task.Run(() =>
                {
                    try
                    {
                        using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut);
                        pipe.Connect(timeoutMs);

                        byte[] payload = Encoding.UTF8.GetBytes(jsonPayload);
                        byte[] lenHeader = BitConverter.GetBytes((uint)payload.Length);

                        pipe.Write(lenHeader, 0, 4);
                        pipe.Write(payload, 0, payload.Length);
                        pipe.Flush();

                        byte[] respLenHeader = new byte[4];
                        int read = pipe.Read(respLenHeader, 0, 4);
                        if (read != 4) return null;

                        uint respLen = BitConverter.ToUInt32(respLenHeader, 0);
                        if (respLen > 10 * 1024 * 1024) return null; // 10MB safety cap

                        byte[] respBuffer = new byte[respLen];
                        int totalRead = 0;
                        while (totalRead < respLen)
                        {
                            int r = pipe.Read(respBuffer, totalRead, (int)respLen - totalRead);
                            if (r <= 0) break;
                            totalRead += r;
                        }

                        return Encoding.UTF8.GetString(respBuffer, 0, totalRead);
                    }
                    catch
                    {
                        return null;
                    }
                });
            }
            finally
            {
                _lock.Release();
            }
        }

        public async Task<bool> StartScanAsync(string mode, string path = "")
        {
            string cmd = JsonSerializer.Serialize(new { cmd = "start_scan", type = mode, path = path });
            string? resp = await SendCommandAsync(cmd, 1500);
            return resp != null;
        }

        public async Task<bool> CancelScanAsync()
        {
            string? resp = await SendCommandAsync("{\"cmd\":\"cancel_scan\"}", 800);
            return resp != null;
        }

        public async Task<string?> GetScanStatusJsonAsync()
        {
            return await SendCommandAsync("{\"cmd\":\"get_status\"}", 250);
        }

        public async Task<bool> UpdateConfigAsync(bool rtp, bool antiTamper, double heuristic, double zipRatio)
        {
            string cfgJson = JsonSerializer.Serialize(new
            {
                cmd = "update_config",
                config = new
                {
                    rtpEnabled = rtp,
                    antiTamperEnabled = antiTamper,
                    heuristicThreshold = heuristic,
                    zipBombRatioLimit = zipRatio
                }
            });
            string? resp = await SendCommandAsync(cfgJson, 1000);
            return resp != null;
        }

        public async Task<bool> RestoreQuarantineAsync(long id, string targetPath = "")
        {
            string req = JsonSerializer.Serialize(new { cmd = "restore_quarantine", id = id, destination = targetPath });
            string? resp = await SendCommandAsync(req, 2000);
            return resp != null && resp.Contains("\"success\":true");
        }

        public async Task<bool> DeleteQuarantineAsync(long id)
        {
            string req = JsonSerializer.Serialize(new { cmd = "delete_quarantine", id = id });
            string? resp = await SendCommandAsync(req, 1500);
            return resp != null;
        }

        public void Dispose()
        {
            if (_isDisposed) return;
            _isDisposed = true;
            _heartbeatTimer?.Dispose();
            _lock.Dispose();
        }
    }
}
