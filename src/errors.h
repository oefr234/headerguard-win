#pragma once

#include <windows.h>

#include <string>
#include <string_view>

namespace hg {

// The failure categories the tool distinguishes. They mirror the exception
// types of the Python version (requests): MissingSchema, InvalidSchema,
// InvalidURL, ConnectionError, ReadTimeout, TooManyRedirects, SSLError.
enum class ErrorKind {
    None,
    MissingScheme,     // "example.com" - no http:// or https://
    InvalidScheme,     // "ftp://..." - a scheme WinHTTP does not speak
    InvalidUrl,        // malformed URL
    NameNotResolved,   // DNS lookup failed
    ConnectionFailed,  // TCP connect refused / reset
    Timeout,           // resolve, connect, send or receive timed out
    RedirectFailed,    // too many redirects, or a redirect WinHTTP refuses
    TlsFailure,        // handshake or certificate validation failed
    Cancelled,         // scan stopped before this URL ran
    Other,
};

struct Error {
    ErrorKind kind = ErrorKind::None;
    DWORD code = 0;          // GetLastError() value, 0 if not applicable
    std::wstring function;   // the API call that failed
    std::wstring message;    // system text for `code`
    std::wstring detail;     // extra context (e.g. which certificate check failed)
};

const wchar_t* kindName(ErrorKind kind) noexcept;

// Maps a Win32 / WinHTTP error code to a category.
ErrorKind classify(DWORD code) noexcept;

// Text for an error code. WinHTTP codes (12000-12999) are not in the system
// message table; they live in winhttp.dll's own resources.
std::wstring describeCode(DWORD code);

// Builds an Error from a failed API call. Pass the GetLastError() value that
// was captured immediately after the failure.
Error makeError(std::wstring_view function, DWORD code);

Error makeError(ErrorKind kind, std::wstring_view detail);

// One line, suitable for printing.
std::wstring formatError(const Error& error);

}  // namespace hg
