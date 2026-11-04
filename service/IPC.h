#pragma once

#include "../common/NamedPipe.h"
#include "Scanner.h"
#include <memory>
#include <string>
#include <mutex>

namespace vantor {
namespace service {

class ServiceIPC {
public:
    static ServiceIPC& Instance() {
        static ServiceIPC instance;
        return instance;
    }

    bool Start();
    void Stop();

    std::string HandleRequest(const std::string& requestJson);

private:
    ServiceIPC();
    ~ServiceIPC();

    std::unique_ptr<ipc::NamedPipeServer> server_;
    scan::ScanProgressInfo lastProgress_;
    std::mutex progressMutex_;
};

} // namespace service
} // namespace vantor
