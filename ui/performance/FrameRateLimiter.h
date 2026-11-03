#pragma once

#include <chrono>
#include <thread>

namespace vantor {
namespace ui {

class FrameRateLimiter {
public:
    explicit FrameRateLimiter(int targetFps = 60)
        : targetFps_(targetFps), frameDuration_(1000000 / targetFps) {
        lastFrameTime_ = std::chrono::steady_clock::now();
    }

    void SetTargetFps(int fps) {
        if (fps <= 0) fps = 60;
        targetFps_ = fps;
        frameDuration_ = std::chrono::microseconds(1000000 / targetFps_);
    }

    int GetTargetIntervalMs() const {
        return 1000 / targetFps_;
    }

    // Call at end of rendering cycle
    void Throttle() {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(now - lastFrameTime_);

        if (elapsed < frameDuration_) {
            std::this_thread::sleep_for(frameDuration_ - elapsed);
        }
        lastFrameTime_ = std::chrono::steady_clock::now();
    }

    bool ShouldRender() {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(now - lastFrameTime_);
        if (elapsed >= frameDuration_) {
            lastFrameTime_ = now;
            return true;
        }
        return false;
    }

private:
    int targetFps_;
    std::chrono::microseconds frameDuration_;
    std::chrono::steady_clock::time_point lastFrameTime_;
};

} // namespace ui
} // namespace vantor
