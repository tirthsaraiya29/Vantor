using System;
using System.Threading.Tasks;

namespace Vantor.Services
{
    public interface IVantorIpcClient
    {
        bool IsConnected { get; }
        event Action<bool>? ConnectionStateChanged;

        Task<bool> PingAsync();
        Task<string?> SendCommandAsync(string jsonPayload, int timeoutMs = 1500);
        Task<bool> StartScanAsync(string mode, string path = "");
        Task<bool> CancelScanAsync();
        Task<string?> GetScanStatusJsonAsync();
        Task<bool> UpdateConfigAsync(bool rtp, bool antiTamper, double heuristic, double zipRatio);
        Task<bool> RestoreQuarantineAsync(long id, string targetPath = "");
        Task<bool> DeleteQuarantineAsync(long id);
        void StartHeartbeat();
        void StopHeartbeat();
    }
}
