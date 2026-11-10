#pragma once

#include "http.h"

#include <string>

namespace hg {

struct MonitorConfig {
    std::wstring urlFile;        // absolute path, re-read before every cycle
    DWORD intervalSeconds = 300;
    unsigned jobs = 4;
    ScanOptions scan;
};

// Runs the monitor in the current console until Ctrl+C. Same code path as the
// service, without needing administrator rights: useful for debugging.
int runMonitorInConsole(const MonitorConfig& config);

// Entry point when the Service Control Manager starts the process.
int runAsService(const MonitorConfig& config);

// Registers / removes the service. Both need an elevated terminal.
int installService(const MonitorConfig& config);
int uninstallService();

// Client side: connects to the monitor's named pipe and prints its latest report.
int queryMonitor();

}  // namespace hg
