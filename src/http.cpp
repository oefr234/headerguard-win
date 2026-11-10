#include "http.h"

#include <cstdio>
#include <cwchar>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")

namespace hg {

namespace {

constexpr wchar_t kUserAgent[] = L"headerguard-win/1.0";

struct CrackedUrl {
    std::wstring host;
    std::wstring path;  // path + query, never empty
    INTERNET_PORT port = 0;
    bool secure = false;
};

// Splits a URL with WinHttpCrackUrl. With the length members set to -1 the
// function does not copy anything: it returns pointers into the input string.
bool crackUrl(const std::wstring& url, CrackedUrl& out, Error& error) {
    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    parts.dwSchemeLength = static_cast<DWORD>(-1);
    parts.dwHostNameLength = static_cast<DWORD>(-1);
    parts.dwUrlPathLength = static_cast<DWORD>(-1);
    parts.dwExtraInfoLength = static_cast<DWORD>(-1);

    if (!WinHttpCrackUrl(url.c_str(), static_cast<DWORD>(url.size()), 0, &parts)) {
        error = makeError(L"WinHttpCrackUrl", GetLastError());
        return false;
    }
    // Newer Windows versions also parse ftp:// and other schemes here, but
    // WinHTTP can only send requests over http and https.
    if (parts.nScheme != INTERNET_SCHEME_HTTP && parts.nScheme != INTERNET_SCHEME_HTTPS) {
        std::wstring scheme;
        if (parts.lpszScheme != nullptr) {
            scheme.assign(parts.lpszScheme, parts.dwSchemeLength);
        }
        error = makeError(ErrorKind::InvalidScheme,
                          L"unsupported scheme \"" + scheme + L"\", use http or https");
        return false;
    }
    if (parts.lpszHostName == nullptr || parts.dwHostNameLength == 0) {
        error = makeError(ErrorKind::InvalidUrl, L"the URL has no host name");
        return false;
    }

    out.host.assign(parts.lpszHostName, parts.dwHostNameLength);
    out.port = parts.nPort;
    out.secure = parts.nScheme == INTERNET_SCHEME_HTTPS;

    if (parts.lpszUrlPath != nullptr) {
        out.path.assign(parts.lpszUrlPath, parts.dwUrlPathLength);
    }
    if (parts.lpszExtraInfo != nullptr) {
        out.path.append(parts.lpszExtraInfo, parts.dwExtraInfoLength);
    }
    // The fragment (#...) is for the client only and is never sent.
    if (const auto fragment = out.path.find(L'#'); fragment != std::wstring::npos) {
        out.path.erase(fragment);
    }
    if (out.path.empty()) {
        out.path = L"/";
    }
    return true;
}

// The "call twice" pattern: the first call fails with
// ERROR_INSUFFICIENT_BUFFER and reports the size needed, the second call
// fills a buffer of that size.
std::wstring queryOptionString(HINTERNET handle, DWORD option) {
    DWORD bytes = 0;
    if (WinHttpQueryOption(handle, option, nullptr, &bytes) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes == 0) {
        return {};
    }
    std::wstring buffer(bytes / sizeof(wchar_t), L'\0');
    if (!WinHttpQueryOption(handle, option, buffer.data(), &bytes)) {
        return {};
    }
    buffer.resize(wcslen(buffer.c_str()));
    return buffer;
}

bool queryRawHeaders(HINTERNET request, std::vector<std::wstring>& lines, Error& error) {
    DWORD bytes = 0;
    if (WinHttpQueryHeaders(request, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
                            WINHTTP_NO_OUTPUT_BUFFER, &bytes, WINHTTP_NO_HEADER_INDEX) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        error = makeError(L"WinHttpQueryHeaders", GetLastError());
        return false;
    }

    std::wstring raw(bytes / sizeof(wchar_t), L'\0');
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX,
                             raw.data(), &bytes, WINHTTP_NO_HEADER_INDEX)) {
        error = makeError(L"WinHttpQueryHeaders", GetLastError());
        return false;
    }
    raw.resize(bytes / sizeof(wchar_t));

    std::size_t start = 0;
    while (start < raw.size()) {
        std::size_t end = raw.find(L"\r\n", start);
        if (end == std::wstring::npos) {
            end = raw.size();
        }
        if (end > start) {
            lines.emplace_back(raw, start, end - start);
        }
        start = end + 2;
    }
    return true;
}

// WinHTTP reports *why* a TLS handshake was rejected only through a status
// callback. In synchronous mode the callback runs on the calling thread,
// inside WinHttpSendRequest, so a plain DWORD is enough as context.
void CALLBACK secureFailureCallback(HINTERNET, DWORD_PTR context, DWORD status, LPVOID info,
                                    DWORD infoLength) {
    if (status == WINHTTP_CALLBACK_STATUS_SECURE_FAILURE && context != 0 && info != nullptr &&
        infoLength >= sizeof(DWORD)) {
        *reinterpret_cast<DWORD*>(context) |= *static_cast<DWORD*>(info);
    }
}

std::wstring describeSecureFailure(DWORD flags) {
    struct Entry {
        DWORD flag;
        const wchar_t* text;
    };
    static constexpr Entry entries[] = {
        {WINHTTP_CALLBACK_STATUS_FLAG_CERT_REV_FAILED, L"revocation check could not be completed"},
        {WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CERT, L"certificate is invalid"},
        {WINHTTP_CALLBACK_STATUS_FLAG_CERT_REVOKED, L"certificate was revoked"},
        {WINHTTP_CALLBACK_STATUS_FLAG_INVALID_CA, L"issuer is not trusted"},
        {WINHTTP_CALLBACK_STATUS_FLAG_CERT_CN_INVALID, L"certificate does not match the host name"},
        {WINHTTP_CALLBACK_STATUS_FLAG_CERT_DATE_INVALID, L"certificate is expired or not yet valid"},
        {WINHTTP_CALLBACK_STATUS_FLAG_CERT_WRONG_USAGE, L"certificate is not valid for server authentication"},
        {WINHTTP_CALLBACK_STATUS_FLAG_SECURITY_CHANNEL_ERROR, L"TLS protocol error"},
    };

    std::wstring text;
    for (const auto& entry : entries) {
        if (flags & entry.flag) {
            if (!text.empty()) {
                text += L"; ";
            }
            text += entry.text;
        }
    }
    return text;
}

std::wstring certName(PCCERT_CONTEXT cert, DWORD flags) {
    const DWORD length =
        CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, nullptr, nullptr, 0);
    if (length <= 1) {
        return {};
    }
    std::wstring name(length, L'\0');
    CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, nullptr, name.data(), length);
    name.resize(length - 1);  // drop the terminating null
    return name;
}

std::wstring formatDate(const FILETIME& time) {
    SYSTEMTIME st{};
    if (!FileTimeToSystemTime(&time, &st)) {
        return L"?";
    }
    wchar_t buffer[16];
    swprintf_s(buffer, L"%04u-%02u-%02u", st.wYear, st.wMonth, st.wDay);
    return buffer;
}

long long daysUntil(const FILETIME& time) {
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);

    ULARGE_INTEGER a{}, b{};
    a.LowPart = time.dwLowDateTime;
    a.HighPart = time.dwHighDateTime;
    b.LowPart = now.dwLowDateTime;
    b.HighPart = now.dwHighDateTime;

    // FILETIME counts 100-nanosecond intervals.
    constexpr long long ticksPerDay = 10'000'000LL * 60 * 60 * 24;
    return (static_cast<long long>(a.QuadPart) - static_cast<long long>(b.QuadPart)) / ticksPerDay;
}

std::wstring describeTrustStatus(DWORD status) {
    struct Entry {
        DWORD flag;
        const wchar_t* text;
    };
    static constexpr Entry entries[] = {
        {CERT_TRUST_IS_NOT_TIME_VALID, L"a certificate in the chain is expired or not yet valid"},
        {CERT_TRUST_IS_REVOKED, L"a certificate in the chain was revoked"},
        {CERT_TRUST_IS_NOT_SIGNATURE_VALID, L"a signature in the chain is invalid"},
        {CERT_TRUST_IS_NOT_VALID_FOR_USAGE, L"not valid for server authentication"},
        {CERT_TRUST_IS_UNTRUSTED_ROOT, L"the root is not trusted"},
        {CERT_TRUST_IS_PARTIAL_CHAIN, L"the chain is incomplete"},
    };

    std::wstring text;
    for (const auto& entry : entries) {
        if (status & entry.flag) {
            if (!text.empty()) {
                text += L"; ";
            }
            text += entry.text;
        }
    }
    return text;
}

// Reads the server certificate WinHTTP received and validates it again with
// CryptoAPI: build the chain up to a root in the Windows store, then apply
// the SSL policy (which also checks the name against `host`).
std::optional<CertificateInfo> readCertificate(HINTERNET request, const std::wstring& host) {
    PCCERT_CONTEXT raw = nullptr;
    DWORD size = sizeof(raw);
    if (!WinHttpQueryOption(request, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &raw, &size) ||
        raw == nullptr) {
        return std::nullopt;
    }
    CertContext cert(raw);  // the caller owns the context and must free it

    CertificateInfo info;
    info.subject = certName(cert.get(), 0);
    info.issuer = certName(cert.get(), CERT_NAME_ISSUER_FLAG);
    info.notBefore = formatDate(cert.get()->pCertInfo->NotBefore);
    info.notAfter = formatDate(cert.get()->pCertInfo->NotAfter);
    info.daysRemaining = daysUntil(cert.get()->pCertInfo->NotAfter);

    char serverAuthOid[] = szOID_PKIX_KP_SERVER_AUTH;
    LPSTR usages[] = {serverAuthOid};

    CERT_CHAIN_PARA chainPara{};
    chainPara.cbSize = sizeof(chainPara);
    chainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
    chainPara.RequestedUsage.Usage.cUsageIdentifier = 1;
    chainPara.RequestedUsage.Usage.rgpszUsageIdentifier = usages;

    // hCertStore holds the intermediates the server sent in the handshake.
    PCCERT_CHAIN_CONTEXT rawChain = nullptr;
    if (!CertGetCertificateChain(nullptr, cert.get(), nullptr, cert.get()->hCertStore, &chainPara,
                                 0, nullptr, &rawChain)) {
        info.trustProblem = L"CertGetCertificateChain failed: " + describeCode(GetLastError());
        return info;
    }
    CertChain chain(rawChain);

    if (chain.get()->cChain > 0) {
        const CERT_SIMPLE_CHAIN* simple = chain.get()->rgpChain[0];
        for (DWORD i = 0; i < simple->cElement; ++i) {
            info.chain.push_back(certName(simple->rgpElement[i]->pCertContext, 0));
        }
    }

    std::wstring hostCopy = host;
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA sslPara{};
    sslPara.cbSize = sizeof(sslPara);
    sslPara.dwAuthType = AUTHTYPE_SERVER;
    sslPara.pwszServerName = hostCopy.data();

    CERT_CHAIN_POLICY_PARA policyPara{};
    policyPara.cbSize = sizeof(policyPara);
    policyPara.pvExtraPolicyPara = &sslPara;

    CERT_CHAIN_POLICY_STATUS policyStatus{};
    policyStatus.cbSize = sizeof(policyStatus);

    if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain.get(), &policyPara,
                                          &policyStatus)) {
        info.trustProblem = L"CertVerifyCertificateChainPolicy could not run";
        return info;
    }

    if (policyStatus.dwError == ERROR_SUCCESS) {
        info.trusted = true;
    } else {
        info.trustProblem = describeCode(policyStatus.dwError);
        const std::wstring chainText = describeTrustStatus(chain.get()->TrustStatus.dwErrorStatus);
        if (!chainText.empty()) {
            info.trustProblem += L" (" + chainText + L")";
        }
    }
    return info;
}

}  // namespace

std::optional<HttpSession> HttpSession::open(Error& error) {
    HInternet handle(WinHttpOpen(kUserAgent, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                 WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!handle) {
        error = makeError(L"WinHttpOpen", GetLastError());
        return std::nullopt;
    }
    return HttpSession(std::move(handle));
}

ScanResult fetch(const HttpSession& session, const std::wstring& url, const ScanOptions& options) {
    ScanResult result;
    result.url = url;

    // WinHttpCrackUrl reports both "no scheme" and "unknown scheme" with the
    // same code, so the first case is detected here to keep them apart.
    if (url.find(L"://") == std::wstring::npos) {
        result.error = makeError(ErrorKind::MissingScheme,
                                 L"no scheme supplied, did you mean https://" + url + L"?");
        return result;
    }

    CrackedUrl target;
    if (!crackUrl(url, target, result.error)) {
        return result;
    }

    // From here on every early return closes the handles opened so far:
    // the HInternet destructors run in reverse order of construction.
    HInternet connect(WinHttpConnect(session.get(), target.host.c_str(), target.port, 0));
    if (!connect) {
        result.error = makeError(L"WinHttpConnect", GetLastError());
        return result;
    }

    HInternet request(WinHttpOpenRequest(connect.get(), L"GET", target.path.c_str(), nullptr,
                                         WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                         target.secure ? WINHTTP_FLAG_SECURE : 0));
    if (!request) {
        result.error = makeError(L"WinHttpOpenRequest", GetLastError());
        return result;
    }

    const int timeout = static_cast<int>(options.timeoutMs);
    if (!WinHttpSetTimeouts(request.get(), timeout, timeout, timeout, timeout)) {
        result.error = makeError(L"WinHttpSetTimeouts", GetLastError());
        return result;
    }

    DWORD maxRedirects = options.maxRedirects;
    if (!WinHttpSetOption(request.get(), WINHTTP_OPTION_MAX_HTTP_AUTOMATIC_REDIRECTS,
                          &maxRedirects, sizeof(maxRedirects))) {
        result.error = makeError(L"WinHttpSetOption", GetLastError());
        return result;
    }

    if (options.ignoreCertErrors && target.secure) {
        DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                      SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        if (!WinHttpSetOption(request.get(), WINHTTP_OPTION_SECURITY_FLAGS, &flags,
                              sizeof(flags))) {
            result.error = makeError(L"WinHttpSetOption", GetLastError());
            return result;
        }
    }

    DWORD secureFailureFlags = 0;
    WinHttpSetStatusCallback(request.get(), secureFailureCallback,
                             WINHTTP_CALLBACK_FLAG_SECURE_FAILURE, 0);

    // DNS, TCP connect, TLS handshake and the request itself all happen here.
    if (!WinHttpSendRequest(request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0,
                            reinterpret_cast<DWORD_PTR>(&secureFailureFlags))) {
        result.error = makeError(L"WinHttpSendRequest", GetLastError());
        result.error.detail = describeSecureFailure(secureFailureFlags);
        return result;
    }

    // Waits for the status line and headers. Redirects are followed inside
    // this call, so redirect and TLS errors of later hops surface here.
    if (!WinHttpReceiveResponse(request.get(), nullptr)) {
        result.error = makeError(L"WinHttpReceiveResponse", GetLastError());
        result.error.detail = describeSecureFailure(secureFailureFlags);
        return result;
    }

    DWORD status = 0;
    DWORD statusSize = sizeof(status);
    if (!WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize,
                             WINHTTP_NO_HEADER_INDEX)) {
        result.error = makeError(L"WinHttpQueryHeaders", GetLastError());
        return result;
    }
    result.status = status;

    if (!queryRawHeaders(request.get(), result.headers, result.error)) {
        return result;
    }

    result.finalUrl = queryOptionString(request.get(), WINHTTP_OPTION_URL);
    if (result.finalUrl.empty()) {
        result.finalUrl = url;
    }

    // After redirects the certificate belongs to the final host, so it has
    // to be validated against that name, not the one we started with.
    CrackedUrl finalTarget;
    Error ignored;
    if (crackUrl(result.finalUrl, finalTarget, ignored) && finalTarget.secure) {
        result.certificate = readCertificate(request.get(), finalTarget.host);
    }

    result.ok = true;
    return result;
}

}  // namespace hg
