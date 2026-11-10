#pragma once

#include "http.h"

#include <string>
#include <string_view>
#include <vector>

namespace hg {

// Windows APIs use UTF-16; files and the pipe protocol use UTF-8.
std::wstring utf8ToWide(std::string_view text);
std::string wideToUtf8(std::wstring_view text);

// Multi-line, human-readable description of one result.
std::wstring formatResult(const ScanResult& result, bool showHeaders);

// All results plus a summary line.
std::wstring formatReport(const std::vector<ScanResult>& results, bool showHeaders);

}  // namespace hg
