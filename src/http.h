#pragma once

#include "errors.h"
#include "handles.h"

#include <optional>
#include <string>
#include <vector>

namespace hg {

struct CertificateInfo {
    std::wstring subject;
    std::wstring issuer;
    std::wstring notBefore;       // YYYY-MM-DD (UTC)
    std::wstring notAfter;        // YYYY-MM-DD (UTC)
    long long daysRemaining = 0;  // negative when already expired
    bool trusted = false;         // chain builds to a trusted root and matches the host
    std::wstring trustProblem;    // empty when trusted
    std::vector<std::wstring> chain;  // leaf first, root last
};

struct ScanOptions {
    DWORD timeoutMs = 10'000;  // applied to resolve, connect, send and receive
    DWORD maxRedirects = 10;
    // Continue past certificate errors so the certificate can still be
    // inspected. The result then reports the problem instead of failing.
    bool ignoreCertErrors = false;
};

struct ScanResult {
    std::wstring url;
    bool ok = false;  // a response was received (any status code)
    DWORD status = 0;
    std::wstring finalUrl;              // after redirects
    std::vector<std::wstring> headers;  // raw lines, status line first
    std::optional<CertificateInfo> certificate;  // only for https responses
    Error error;                        // meaningful when !ok
};

// Owns the WinHTTP session handle. One session can be shared by many threads;
// it holds the proxy settings and the connection pool.
class HttpSession {
public:
    static std::optional<HttpSession> open(Error& error);

    HINTERNET get() const noexcept { return handle_.get(); }

private:
    explicit HttpSession(HInternet handle) noexcept : handle_(std::move(handle)) {}

    HInternet handle_;
};

// Sends a GET request and collects status, headers, final URL and certificate.
// Never throws for network failures: they are reported in ScanResult::error.
ScanResult fetch(const HttpSession& session, const std::wstring& url, const ScanOptions& options);

}  // namespace hg
