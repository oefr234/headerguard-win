#pragma once

#include "http.h"

#include <condition_variable>
#include <functional>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <vector>

namespace hg {

// A thread-safe queue for the producer-consumer pattern.
//
// pop() blocks while the queue is empty. close() tells consumers that no more
// items will arrive: they drain what is left and then get std::nullopt.
template <typename T>
class BlockingQueue {
public:
    void push(T value) {
        {
            std::lock_guard lock(mutex_);
            items_.push(std::move(value));
        }
        // Notify after unlocking so the woken thread can take the mutex
        // immediately instead of blocking on it again.
        ready_.notify_one();
    }

    void close() {
        {
            std::lock_guard lock(mutex_);
            closed_ = true;
        }
        ready_.notify_all();
    }

    std::optional<T> pop() {
        std::unique_lock lock(mutex_);
        // The predicate guards against spurious wakeups and against a
        // notification that arrived before this thread started waiting.
        ready_.wait(lock, [this] { return closed_ || !items_.empty(); });
        if (items_.empty()) {
            return std::nullopt;
        }
        T value = std::move(items_.front());
        items_.pop();
        return value;
    }

private:
    std::mutex mutex_;
    std::condition_variable ready_;
    std::queue<T> items_;
    bool closed_ = false;
};

// Scans every URL using `jobs` worker threads and returns the results in the
// same order as the input. `cancelled`, when provided, is polled before each
// URL; URLs skipped because of it get ErrorKind::Cancelled.
std::vector<ScanResult> scanAll(const HttpSession& session, const std::vector<std::wstring>& urls,
                                const ScanOptions& options, unsigned jobs,
                                const std::function<bool()>& cancelled = {});

// Reads one URL per line from a UTF-8 text file. Blank lines and lines
// starting with '#' are ignored.
bool loadUrls(const std::wstring& path, std::vector<std::wstring>& urls, std::wstring& problem);

}  // namespace hg
