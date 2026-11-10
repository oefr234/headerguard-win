#include "scanner.h"
#include "service.h"
#include "text.h"

#include <fcntl.h>
#include <io.h>

#include <cwchar>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr int kExitOk = 0;
constexpr int kExitFailure = 1;
constexpr int kExitUsage = 2;

void printUsage() {
    std::wcerr <<
        L"Usage:\n"
        L"  headerguard-win [options] <url> [<url>...]\n"
        L"  headerguard-win [options] --file <urls.txt>\n"
        L"  headerguard-win serve <urls.txt> [--interval <seconds>]\n"
        L"  headerguard-win query\n"
        L"  headerguard-win service install <urls.txt> [--interval <seconds>]\n"
        L"  headerguard-win service uninstall\n"
        L"\n"
        L"Options:\n"
        L"  --file <path>         read URLs from a text file, one per line\n"
        L"  --jobs <n>            number of worker threads (default 4)\n"
        L"  --timeout <seconds>   per-step network timeout (default 10)\n"
        L"  --max-redirects <n>   redirects to follow (default 10)\n"
        L"  --no-headers          do not print response headers\n"
        L"  --insecure            continue past certificate errors and report them\n"
        L"\n"
        L"serve runs the periodic monitor in this console; query prints its latest\n"
        L"report. service install registers the same monitor as a Windows service.\n";
}

bool parseNumber(const wchar_t* text, unsigned long minimum, unsigned long maximum,
                 unsigned long& value) {
    wchar_t* end = nullptr;
    errno = 0;
    const unsigned long parsed = std::wcstoul(text, &end, 10);
    if (errno != 0 || end == text || *end != L'\0' || text[0] == L'-' || parsed < minimum ||
        parsed > maximum) {
        return false;
    }
    value = parsed;
    return true;
}

std::wstring absolutePath(const std::wstring& path) {
    // The service starts with System32 as its current directory, so a
    // relative path stored at install time would point somewhere else.
    const DWORD needed = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (needed == 0) {
        return path;
    }
    std::wstring full(needed, L'\0');
    const DWORD written = GetFullPathNameW(path.c_str(), needed, full.data(), nullptr);
    full.resize(written);
    return full;
}

struct Arguments {
    std::vector<std::wstring> positional;
    std::wstring file;
    hg::ScanOptions scan;
    unsigned jobs = 4;
    DWORD intervalSeconds = 300;
    bool showHeaders = true;
};

// Returns false (after printing the reason) on a malformed command line.
bool parseArguments(int argc, wchar_t* argv[], int first, Arguments& out) {
    for (int i = first; i < argc; ++i) {
        const std::wstring_view arg = argv[i];

        const auto numberOption = [&](unsigned long minimum, unsigned long maximum,
                                      unsigned long& value) {
            if (i + 1 >= argc || !parseNumber(argv[i + 1], minimum, maximum, value)) {
                std::wcerr << arg << L" needs a number between " << minimum << L" and " << maximum
                           << L"\n";
                return false;
            }
            ++i;
            return true;
        };

        unsigned long number = 0;
        if (arg == L"--file") {
            if (i + 1 >= argc) {
                std::wcerr << L"--file needs a path\n";
                return false;
            }
            out.file = argv[++i];
        } else if (arg == L"--jobs") {
            if (!numberOption(1, 64, number)) return false;
            out.jobs = static_cast<unsigned>(number);
        } else if (arg == L"--timeout") {
            if (!numberOption(1, 600, number)) return false;
            out.scan.timeoutMs = static_cast<DWORD>(number * 1000);
        } else if (arg == L"--max-redirects") {
            if (!numberOption(0, 50, number)) return false;
            out.scan.maxRedirects = static_cast<DWORD>(number);
        } else if (arg == L"--interval") {
            if (!numberOption(5, 86'400, number)) return false;
            out.intervalSeconds = static_cast<DWORD>(number);
        } else if (arg == L"--no-headers") {
            out.showHeaders = false;
        } else if (arg == L"--insecure") {
            out.scan.ignoreCertErrors = true;
        } else if (arg.starts_with(L"--")) {
            std::wcerr << L"Unknown option " << arg << L"\n";
            return false;
        } else {
            out.positional.emplace_back(arg);
        }
    }
    return true;
}

hg::MonitorConfig toMonitorConfig(const Arguments& args) {
    hg::MonitorConfig config;
    config.urlFile = absolutePath(args.positional.front());
    config.intervalSeconds = args.intervalSeconds;
    config.jobs = args.jobs;
    config.scan = args.scan;
    return config;
}

int runScan(const Arguments& args) {
    std::vector<std::wstring> urls = args.positional;
    if (!args.file.empty()) {
        std::wstring problem;
        if (!hg::loadUrls(args.file, urls, problem)) {
            std::wcerr << L"Error: " << problem << L"\n";
            return kExitFailure;
        }
    }
    if (urls.empty()) {
        printUsage();
        return kExitUsage;
    }

    hg::Error error;
    const auto session = hg::HttpSession::open(error);
    if (!session) {
        std::wcerr << L"Error: " << hg::formatError(error) << L"\n";
        return kExitFailure;
    }

    const auto results = hg::scanAll(*session, urls, args.scan, args.jobs);

    bool anyFailed = false;
    for (std::size_t i = 0; i < results.size(); ++i) {
        if (i > 0) {
            std::wcout << L"\n";
        }
        std::wcout << hg::formatResult(results[i], args.showHeaders);
        anyFailed = anyFailed || !results[i].ok;
    }
    return anyFailed ? kExitFailure : kExitOk;
}

}  // namespace

// wmain instead of main: Windows passes the command line as UTF-16, so URLs
// and paths with non-ASCII characters arrive intact.
int wmain(int argc, wchar_t* argv[]) {
    // Make wcout/wcerr emit UTF-8, both in the console and when redirected.
    // After this call only the wide streams may be used.
    _setmode(_fileno(stdout), _O_U8TEXT);
    _setmode(_fileno(stderr), _O_U8TEXT);

    if (argc < 2) {
        printUsage();
        return kExitUsage;
    }

    const std::wstring_view command = argv[1];
    Arguments args;

    if (command == L"--help" || command == L"-h" || command == L"/?") {
        printUsage();
        return kExitOk;
    }

    if (command == L"query") {
        return hg::queryMonitor();
    }

    if (command == L"serve") {
        if (!parseArguments(argc, argv, 2, args) || args.positional.size() != 1) {
            printUsage();
            return kExitUsage;
        }
        return hg::runMonitorInConsole(toMonitorConfig(args));
    }

    if (command == L"service") {
        if (argc < 3) {
            printUsage();
            return kExitUsage;
        }
        const std::wstring_view action = argv[2];
        if (action == L"uninstall") {
            return hg::uninstallService();
        }
        if (action == L"install" || action == L"run") {
            if (!parseArguments(argc, argv, 3, args) || args.positional.size() != 1) {
                printUsage();
                return kExitUsage;
            }
            const hg::MonitorConfig config = toMonitorConfig(args);
            return action == L"install" ? hg::installService(config) : hg::runAsService(config);
        }
        printUsage();
        return kExitUsage;
    }

    if (!parseArguments(argc, argv, 1, args)) {
        return kExitUsage;
    }
    return runScan(args);
}
