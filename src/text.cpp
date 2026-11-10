#include "text.h"

#include <algorithm>

namespace hg {

std::wstring utf8ToWide(std::string_view text) {
    if (text.empty()) {
        return {};
    }
    const int size = static_cast<int>(text.size());
    const int length = MultiByteToWideChar(CP_UTF8, 0, text.data(), size, nullptr, 0);
    if (length <= 0) {
        return {};
    }
    std::wstring wide(static_cast<std::size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), size, wide.data(), length);
    return wide;
}

std::string wideToUtf8(std::wstring_view text) {
    if (text.empty()) {
        return {};
    }
    const int size = static_cast<int>(text.size());
    const int length =
        WideCharToMultiByte(CP_UTF8, 0, text.data(), size, nullptr, 0, nullptr, nullptr);
    if (length <= 0) {
        return {};
    }
    std::string narrow(static_cast<std::size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), size, narrow.data(), length, nullptr, nullptr);
    return narrow;
}

std::wstring formatResult(const ScanResult& result, bool showHeaders) {
    std::wstring text = L"URL: " + result.url + L"\n";

    if (!result.ok) {
        text += L"Error: " + formatError(result.error) + L"\n";
        return text;
    }

    text += L"Status: " + std::to_wstring(result.status) + L"\n";
    text += L"Final URL: " + result.finalUrl + L"\n";

    if (showHeaders) {
        text += L"Headers:\n";
        for (const auto& line : result.headers) {
            text += L"  " + line + L"\n";
        }
    }

    if (result.certificate) {
        const CertificateInfo& cert = *result.certificate;
        text += L"Certificate:\n";
        text += L"  Subject: " + cert.subject + L"\n";
        text += L"  Issuer: " + cert.issuer + L"\n";
        text += L"  Valid: " + cert.notBefore + L" to " + cert.notAfter;
        if (cert.daysRemaining >= 0) {
            text += L" (" + std::to_wstring(cert.daysRemaining) + L" days remaining)\n";
        } else {
            text += L" (EXPIRED " + std::to_wstring(-cert.daysRemaining) + L" days ago)\n";
        }
        text += L"  Trust: ";
        text += cert.trusted ? L"trusted" : L"NOT TRUSTED - " + cert.trustProblem;
        text += L"\n";
        if (!cert.chain.empty()) {
            text += L"  Chain:\n";
            for (std::size_t i = 0; i < cert.chain.size(); ++i) {
                text += L"    [" + std::to_wstring(i) + L"] " + cert.chain[i] + L"\n";
            }
        }
    }
    return text;
}

std::wstring formatReport(const std::vector<ScanResult>& results, bool showHeaders) {
    std::wstring text;
    for (const auto& result : results) {
        text += formatResult(result, showHeaders);
        text += L"\n";
    }

    const auto failed = std::count_if(results.begin(), results.end(),
                                      [](const ScanResult& r) { return !r.ok; });
    text += L"Scanned " + std::to_wstring(results.size()) + L" URL(s), " +
            std::to_wstring(failed) + L" failed\n";
    return text;
}

}  // namespace hg
