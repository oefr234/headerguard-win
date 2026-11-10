#include "errors.h"

#include <winhttp.h>

namespace hg {

const wchar_t* kindName(ErrorKind kind) noexcept {
    switch (kind) {
    case ErrorKind::None:             return L"None";
    case ErrorKind::MissingScheme:    return L"MissingScheme";
    case ErrorKind::InvalidScheme:    return L"InvalidScheme";
    case ErrorKind::InvalidUrl:       return L"InvalidUrl";
    case ErrorKind::NameNotResolved:  return L"NameNotResolved";
    case ErrorKind::ConnectionFailed: return L"ConnectionFailed";
    case ErrorKind::Timeout:          return L"Timeout";
    case ErrorKind::RedirectFailed:   return L"RedirectFailed";
    case ErrorKind::TlsFailure:       return L"TlsFailure";
    case ErrorKind::Cancelled:        return L"Cancelled";
    case ErrorKind::Other:            return L"Other";
    }
    return L"Other";
}

ErrorKind classify(DWORD code) noexcept {
    switch (code) {
    case ERROR_SUCCESS:
        return ErrorKind::None;
    case ERROR_WINHTTP_UNRECOGNIZED_SCHEME:
        return ErrorKind::InvalidScheme;
    case ERROR_WINHTTP_INVALID_URL:
        return ErrorKind::InvalidUrl;
    case ERROR_WINHTTP_NAME_NOT_RESOLVED:
        return ErrorKind::NameNotResolved;
    case ERROR_WINHTTP_CANNOT_CONNECT:
    case ERROR_WINHTTP_CONNECTION_ERROR:
        return ErrorKind::ConnectionFailed;
    case ERROR_WINHTTP_TIMEOUT:
        return ErrorKind::Timeout;
    case ERROR_WINHTTP_REDIRECT_FAILED:
        return ErrorKind::RedirectFailed;
    case ERROR_WINHTTP_SECURE_FAILURE:
    case ERROR_WINHTTP_SECURE_CHANNEL_ERROR:
    case ERROR_WINHTTP_SECURE_CERT_DATE_INVALID:
    case ERROR_WINHTTP_SECURE_CERT_CN_INVALID:
    case ERROR_WINHTTP_SECURE_INVALID_CA:
    case ERROR_WINHTTP_SECURE_INVALID_CERT:
    case ERROR_WINHTTP_SECURE_CERT_REVOKED:
    case ERROR_WINHTTP_SECURE_CERT_REV_FAILED:
    case ERROR_WINHTTP_SECURE_CERT_WRONG_USAGE:
    case ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED:
        return ErrorKind::TlsFailure;
    default:
        return ErrorKind::Other;
    }
}

std::wstring describeCode(DWORD code) {
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS |
                  FORMAT_MESSAGE_FROM_SYSTEM;
    HMODULE module = nullptr;

    if (code >= WINHTTP_ERROR_BASE && code <= WINHTTP_ERROR_LAST) {
        // GetModuleHandle does not add a reference; winhttp.dll is already
        // loaded because this program links against it.
        module = GetModuleHandleW(L"winhttp.dll");
        if (module != nullptr) {
            flags |= FORMAT_MESSAGE_FROM_HMODULE;
        }
    }

    // With ALLOCATE_BUFFER the function allocates the buffer and writes its
    // address through the lpBuffer parameter, hence the odd cast.
    LPWSTR buffer = nullptr;
    const DWORD length = FormatMessageW(flags, module, code, 0,
                                        reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    if (length == 0 || buffer == nullptr) {
        return L"(no description available)";
    }

    std::wstring text(buffer, length);
    LocalFree(buffer);

    while (!text.empty() &&
           (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' ' ||
            text.back() == L'.')) {
        text.pop_back();
    }
    return text;
}

Error makeError(std::wstring_view function, DWORD code) {
    Error error;
    error.kind = classify(code);
    error.code = code;
    error.function = function;
    error.message = describeCode(code);
    return error;
}

Error makeError(ErrorKind kind, std::wstring_view detail) {
    Error error;
    error.kind = kind;
    error.detail = detail;
    return error;
}

std::wstring formatError(const Error& error) {
    std::wstring text = kindName(error.kind);
    if (!error.function.empty()) {
        text += L": " + error.function + L" failed, code " + std::to_wstring(error.code) +
                L" (" + error.message + L")";
    }
    if (!error.detail.empty()) {
        text += L": " + error.detail;
    }
    return text;
}

}  // namespace hg
