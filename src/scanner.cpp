#include "scanner.h"

#include "text.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <thread>

namespace hg {

std::vector<ScanResult> scanAll(const HttpSession& session, const std::vector<std::wstring>& urls,
                                const ScanOptions& options, unsigned jobs,
                                const std::function<bool()>& cancelled) {
    std::vector<ScanResult> results(urls.size());
    if (urls.empty()) {
        return results;
    }

    // More threads than URLs would only sit idle.
    const auto workerCount =
        static_cast<unsigned>(std::clamp<std::size_t>(jobs, 1, urls.size()));

    BlockingQueue<std::size_t> queue;

    {
        // Each worker writes only to results[index] for the indexes it pops.
        // No two threads ever touch the same element, so the vector itself
        // needs no lock; the queue is the only shared mutable state.
        std::vector<std::jthread> workers;
        workers.reserve(workerCount);
        for (unsigned i = 0; i < workerCount; ++i) {
            workers.emplace_back([&] {
                while (const auto index = queue.pop()) {
                    if (cancelled && cancelled()) {
                        results[*index].url = urls[*index];
                        results[*index].error =
                            makeError(ErrorKind::Cancelled, L"scan stopped before this URL");
                        continue;
                    }
                    results[*index] = fetch(session, urls[*index], options);
                }
            });
        }

        // Producer: this thread hands out the work, then closes the queue.
        for (std::size_t i = 0; i < urls.size(); ++i) {
            queue.push(i);
        }
        queue.close();

        // Leaving this scope destroys the jthreads, which joins them. Only
        // after that is it safe to read `results` from this thread.
    }

    return results;
}

bool loadUrls(const std::wstring& path, std::vector<std::wstring>& urls, std::wstring& problem) {
    std::ifstream file{std::filesystem::path(path)};
    if (!file) {
        problem = L"cannot open " + path;
        return false;
    }

    std::string line;
    bool first = true;
    while (std::getline(file, line)) {
        if (first) {
            first = false;
            // Skip the UTF-8 byte order mark that Notepad may write.
            if (line.rfind("\xEF\xBB\xBF", 0) == 0) {
                line.erase(0, 3);
            }
        }

        const auto begin = line.find_first_not_of(" \t\r\n");
        if (begin == std::string::npos) {
            continue;
        }
        const auto end = line.find_last_not_of(" \t\r\n");
        line = line.substr(begin, end - begin + 1);

        if (line.front() == '#') {
            continue;
        }
        urls.push_back(utf8ToWide(line));
    }
    return true;
}

}  // namespace hg
