#include "service.h"

#include "scanner.h"
#include "text.h"

#include <sddl.h>

#include <cstdint>
#include <cstdio>
#include <iostream>
#include <mutex>
#include <thread>

#pragma comment(lib, "advapi32.lib")

namespace hg {

namespace {

constexpr wchar_t kServiceName[] = L"HeaderGuardSvc";
constexpr wchar_t kServiceDisplayName[] = L"HeaderGuard URL Monitor";
constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\headerguard-win";
constexpr DWORD kPipeIoTimeoutMs = 5'000;

// Who may open the pipe:
//   SY (LocalSystem), BA (Administrators), OW (the account that created it):
//     full access.
//   AU (Authenticated Users): read only.
// Clients are deliberately not given write access. On a pipe, generic write
// includes FILE_CREATE_PIPE_INSTANCE, which would let any user create their
// own instance of this pipe name and impersonate the server.
constexpr wchar_t kPipeSddl[] = L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;GR;;;AU)";

// The latest report, written by the scan loop and read by the pipe thread.
class ReportStore {
public:
    void set(std::string report) {
        std::lock_guard lock(mutex_);
        report_ = std::move(report);
    }

    std::string get() const {
        std::lock_guard lock(mutex_);
        return report_;
    }

private:
    mutable std::mutex mutex_;
    std::string report_ = "No scan has completed yet.\n";
};

bool isSignaled(HANDLE event) {
    return WaitForSingleObject(event, 0) == WAIT_OBJECT_0;
}

std::wstring timestamp() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    wchar_t buffer[32];
    swprintf_s(buffer, L"%04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth, st.wDay, st.wHour,
               st.wMinute, st.wSecond);
    return buffer;
}

// Waits for an overlapped operation on `pipe`, giving up when `stopEvent` is
// signaled or the timeout expires. On give-up the operation is cancelled and
// then awaited: the kernel may still be writing into the OVERLAPPED
// structure, so it must not go out of scope before the I/O has really ended.
bool waitForIo(HANDLE pipe, OVERLAPPED& overlapped, HANDLE stopEvent, DWORD timeoutMs) {
    const HANDLE handles[] = {stopEvent, overlapped.hEvent};
    const DWORD wait = WaitForMultipleObjects(2, handles, FALSE, timeoutMs);

    DWORD transferred = 0;
    if (wait == WAIT_OBJECT_0 + 1) {
        return GetOverlappedResult(pipe, &overlapped, &transferred, FALSE) != FALSE;
    }

    CancelIoEx(pipe, &overlapped);
    GetOverlappedResult(pipe, &overlapped, &transferred, TRUE);
    return false;
}

// Serves one client at a time: connect, send the latest report, disconnect.
// All I/O is overlapped so that the thread can also watch the stop event; a
// blocking ConnectNamedPipe would hang service shutdown forever.
void pipeServer(HANDLE stopEvent, const ReportStore& store) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(kPipeSddl, SDDL_REVISION_1,
                                                              &descriptor, nullptr)) {
        return;
    }
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.lpSecurityDescriptor = descriptor;

    // FIRST_PIPE_INSTANCE: fail if another process already owns this name
    // (pipe squatting). REJECT_REMOTE_CLIENTS: local machine only.
    FileHandle pipe(CreateNamedPipeW(
        kPipeName,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, 64 * 1024, 0, 0, &attributes));
    LocalFree(descriptor);
    if (!pipe) {
        return;
    }

    KernelHandle ioEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));  // manual reset
    if (!ioEvent) {
        return;
    }

    while (!isSignaled(stopEvent)) {
        OVERLAPPED overlapped{};
        overlapped.hEvent = ioEvent.get();
        ResetEvent(ioEvent.get());

        bool connected = false;
        if (ConnectNamedPipe(pipe.get(), &overlapped)) {
            connected = true;
        } else {
            const DWORD error = GetLastError();
            if (error == ERROR_PIPE_CONNECTED) {
                // A client connected between CreateNamedPipe/Disconnect and
                // this call. That is a success, not a failure.
                connected = true;
            } else if (error == ERROR_IO_PENDING) {
                connected = waitForIo(pipe.get(), overlapped, stopEvent, INFINITE);
            }
        }

        if (connected) {
            // Protocol: a 4-byte length, then that many bytes of UTF-8 text.
            // A pipe in byte mode has no message boundaries, so without the
            // prefix the client could not tell when the report is complete.
            const std::string report = store.get();
            const auto length = static_cast<std::uint32_t>(report.size());
            std::string message(reinterpret_cast<const char*>(&length), sizeof(length));
            message += report;

            ResetEvent(ioEvent.get());
            bool written = WriteFile(pipe.get(), message.data(),
                                     static_cast<DWORD>(message.size()), nullptr, &overlapped) != FALSE;
            if (!written && GetLastError() == ERROR_IO_PENDING) {
                written = waitForIo(pipe.get(), overlapped, stopEvent, kPipeIoTimeoutMs);
            }

            if (written) {
                // DisconnectNamedPipe discards data the client has not read
                // yet. Wait for the client to close its end first: this read
                // completes with ERROR_BROKEN_PIPE when that happens. The
                // timeout stops a stalled client from blocking everyone else.
                char unused = 0;
                ResetEvent(ioEvent.get());
                if (!ReadFile(pipe.get(), &unused, 1, nullptr, &overlapped) &&
                    GetLastError() == ERROR_IO_PENDING) {
                    waitForIo(pipe.get(), overlapped, stopEvent, kPipeIoTimeoutMs);
                }
            }
        }

        DisconnectNamedPipe(pipe.get());
    }
}

// The work both the service and the console mode do: scan, publish, sleep.
void monitorLoop(const MonitorConfig& config, HANDLE stopEvent) {
    ReportStore store;

    // jthread joins in its destructor; the thread exits when stopEvent is set.
    std::jthread pipeThread([&] { pipeServer(stopEvent, store); });

    Error sessionError;
    const auto session = HttpSession::open(sessionError);
    if (!session) {
        store.set(wideToUtf8(L"Cannot start scanning: " + formatError(sessionError) + L"\n"));
        WaitForSingleObject(stopEvent, INFINITE);
        return;
    }

    const auto cancelled = [stopEvent] { return isSignaled(stopEvent); };

    while (!isSignaled(stopEvent)) {
        std::vector<std::wstring> urls;
        std::wstring problem;
        std::wstring report = L"Last scan: " + timestamp() + L"\n\n";

        if (!loadUrls(config.urlFile, urls, problem)) {
            report += L"Error: " + problem + L"\n";
        } else {
            const auto results = scanAll(*session, urls, config.scan, config.jobs, cancelled);
            if (isSignaled(stopEvent)) {
                break;  // a partial scan is not worth publishing
            }
            report += formatReport(results, false);
        }
        store.set(wideToUtf8(report));

        // An interruptible sleep: returns early when the stop event is set.
        WaitForSingleObject(stopEvent, config.intervalSeconds * 1000);
    }
}

// ---------------------------------------------------------------- console

HANDLE g_consoleStopEvent = nullptr;

BOOL WINAPI consoleCtrlHandler(DWORD) {
    // Runs on a thread created by the system for this purpose.
    if (g_consoleStopEvent != nullptr) {
        SetEvent(g_consoleStopEvent);
    }
    return TRUE;
}

// ---------------------------------------------------------------- service

// The SCM callbacks receive no user pointer for ServiceMain, so the state
// they share has to be global.
struct ServiceState {
    MonitorConfig config;
    SERVICE_STATUS_HANDLE statusHandle = nullptr;
    KernelHandle stopEvent;
    DWORD checkpoint = 1;
};

ServiceState g_service;

void reportStatus(DWORD state, DWORD exitCode = NO_ERROR, DWORD waitHintMs = 0) {
    SERVICE_STATUS status{};
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state;
    status.dwWin32ExitCode = exitCode;
    status.dwWaitHint = waitHintMs;

    // While starting, stop requests are not accepted yet.
    if (state == SERVICE_RUNNING) {
        status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }
    // The checkpoint tells the SCM that a pending operation is making
    // progress; it must be zero in the stable states.
    if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) {
        status.dwCheckPoint = g_service.checkpoint++;
    }

    SetServiceStatus(g_service.statusHandle, &status);
}

DWORD WINAPI serviceControlHandler(DWORD control, DWORD, LPVOID, LPVOID) {
    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        // A request in flight can take up to the configured timeout to
        // notice the stop event, so ask the SCM for that much patience.
        reportStatus(SERVICE_STOP_PENDING, NO_ERROR, g_service.config.scan.timeoutMs + 5'000);
        SetEvent(g_service.stopEvent.get());
        return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

void WINAPI serviceMain(DWORD, LPWSTR*) {
    g_service.statusHandle =
        RegisterServiceCtrlHandlerExW(kServiceName, serviceControlHandler, nullptr);
    if (g_service.statusHandle == nullptr) {
        return;
    }

    reportStatus(SERVICE_START_PENDING, NO_ERROR, 3'000);

    g_service.stopEvent.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!g_service.stopEvent) {
        reportStatus(SERVICE_STOPPED, GetLastError());
        return;
    }

    reportStatus(SERVICE_RUNNING);
    monitorLoop(g_service.config, g_service.stopEvent.get());
    reportStatus(SERVICE_STOPPED);
}

int reportFailure(const wchar_t* function, DWORD code) {
    std::wcerr << function << L" failed, code " << code << L" (" << describeCode(code) << L")\n";
    if (code == ERROR_ACCESS_DENIED) {
        std::wcerr << L"Run this command from an elevated (Administrator) terminal.\n";
    }
    return 1;
}

}  // namespace

int runMonitorInConsole(const MonitorConfig& config) {
    KernelHandle stopEvent(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!stopEvent) {
        return reportFailure(L"CreateEventW", GetLastError());
    }
    g_consoleStopEvent = stopEvent.get();
    SetConsoleCtrlHandler(consoleCtrlHandler, TRUE);

    std::wcout << L"Monitoring " << config.urlFile << L" every " << config.intervalSeconds
               << L" s. Press Ctrl+C to stop.\n"
               << L"Run \"headerguard-win query\" in another terminal to read the report.\n"
               << std::flush;

    monitorLoop(config, stopEvent.get());

    SetConsoleCtrlHandler(consoleCtrlHandler, FALSE);
    g_consoleStopEvent = nullptr;
    std::wcout << L"Stopped.\n";
    return 0;
}

int runAsService(const MonitorConfig& config) {
    g_service.config = config;

    wchar_t name[] = L"HeaderGuardSvc";
    const SERVICE_TABLE_ENTRYW table[] = {{name, serviceMain}, {nullptr, nullptr}};

    // Connects this process to the SCM and blocks until the service stops.
    // The SCM then calls serviceMain on a new thread.
    if (!StartServiceCtrlDispatcherW(table)) {
        const DWORD code = GetLastError();
        if (code == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            std::wcerr << L"\"service run\" can only be started by the Service Control Manager.\n"
                       << L"Use \"serve\" to run the monitor in a console.\n";
            return 1;
        }
        return reportFailure(L"StartServiceCtrlDispatcherW", code);
    }
    return 0;
}

int installService(const MonitorConfig& config) {
    wchar_t exePath[MAX_PATH];
    const DWORD length = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    if (length == 0 || length == MAX_PATH) {
        return reportFailure(L"GetModuleFileNameW", GetLastError());
    }

    // Both paths are quoted. An unquoted service path containing spaces
    // (C:\Program Files\...) lets Windows try C:\Program.exe first, a
    // well-known privilege escalation.
    const std::wstring command = L"\"" + std::wstring(exePath) + L"\" service run \"" +
                                 config.urlFile + L"\" --interval " +
                                 std::to_wstring(config.intervalSeconds);

    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE));
    if (!manager) {
        return reportFailure(L"OpenSCManagerW", GetLastError());
    }

    // LocalService: a built-in low-privilege account. The service only needs
    // to make outbound requests and read one file, so it should not run as
    // LocalSystem.
    ServiceHandle service(CreateServiceW(
        manager.get(), kServiceName, kServiceDisplayName, SERVICE_CHANGE_CONFIG,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, command.c_str(),
        nullptr, nullptr, nullptr, L"NT AUTHORITY\\LocalService", nullptr));
    if (!service) {
        return reportFailure(L"CreateServiceW", GetLastError());
    }

    wchar_t descriptionText[] =
        L"Periodically checks a list of URLs and serves the latest report over a named pipe.";
    SERVICE_DESCRIPTIONW description{descriptionText};
    ChangeServiceConfig2W(service.get(), SERVICE_CONFIG_DESCRIPTION, &description);

    std::wcout << L"Service " << kServiceName << L" installed.\n"
               << L"Command line: " << command << L"\n\n"
               << L"It runs as LocalService, which cannot read files inside your user profile.\n"
               << L"If starting it fails with \"Access is denied\", copy the executable and the\n"
               << L"URL list to a folder that account can read (for example under\n"
               << L"C:\\Program Files and C:\\ProgramData) and install from there.\n\n"
               << L"Start it with: sc start " << kServiceName << L"\n";
    return 0;
}

int uninstallService() {
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager) {
        return reportFailure(L"OpenSCManagerW", GetLastError());
    }

    ServiceHandle service(
        OpenServiceW(manager.get(), kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE));
    if (!service) {
        return reportFailure(L"OpenServiceW", GetLastError());
    }

    SERVICE_STATUS status{};
    if (ControlService(service.get(), SERVICE_CONTROL_STOP, &status)) {
        // Give it a little time to stop so that the deletion is immediate
        // instead of being deferred until the process exits.
        for (int i = 0; i < 40 && status.dwCurrentState != SERVICE_STOPPED; ++i) {
            Sleep(500);
            if (!QueryServiceStatus(service.get(), &status)) {
                break;
            }
        }
    }

    if (!DeleteService(service.get())) {
        return reportFailure(L"DeleteService", GetLastError());
    }

    std::wcout << L"Service " << kServiceName << L" removed.\n";
    return 0;
}

int queryMonitor() {
    FileHandle pipe;
    for (int attempt = 0; attempt < 3 && !pipe; ++attempt) {
        // SECURITY_IDENTIFICATION caps what the server may do with our
        // identity: it can see who we are but cannot act as us. Without it a
        // rogue pipe server could impersonate a privileged client.
        pipe.reset(CreateFileW(kPipeName, GENERIC_READ, 0, nullptr, OPEN_EXISTING,
                               SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
        if (pipe) {
            break;
        }

        const DWORD code = GetLastError();
        if (code == ERROR_FILE_NOT_FOUND) {
            std::wcerr << L"The monitor is not running (pipe " << kPipeName << L" not found).\n";
            return 1;
        }
        if (code != ERROR_PIPE_BUSY) {
            return reportFailure(L"CreateFileW", code);
        }
        // The single pipe instance is serving someone else; wait our turn.
        if (!WaitNamedPipeW(kPipeName, kPipeIoTimeoutMs)) {
            return reportFailure(L"WaitNamedPipeW", GetLastError());
        }
    }
    if (!pipe) {
        std::wcerr << L"The monitor is busy, try again.\n";
        return 1;
    }

    // ReadFile may return fewer bytes than requested, so loop until done.
    const auto readExactly = [&pipe](char* destination, std::size_t count) {
        std::size_t done = 0;
        while (done < count) {
            DWORD read = 0;
            if (!ReadFile(pipe.get(), destination + done, static_cast<DWORD>(count - done), &read,
                          nullptr) ||
                read == 0) {
                return false;
            }
            done += read;
        }
        return true;
    };

    // Never trust a length that arrives from another process: cap it before
    // allocating.
    constexpr std::uint32_t kMaxReportBytes = 16 * 1024 * 1024;

    std::uint32_t length = 0;
    if (!readExactly(reinterpret_cast<char*>(&length), sizeof(length)) ||
        length > kMaxReportBytes) {
        std::wcerr << L"The monitor sent an invalid response.\n";
        return 1;
    }

    std::string report(length, '\0');
    if (!readExactly(report.data(), report.size())) {
        std::wcerr << L"The connection closed before the whole report arrived.\n";
        return 1;
    }

    std::wcout << utf8ToWide(report);
    return 0;
}

}  // namespace hg
