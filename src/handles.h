#pragma once

// RAII owners for the Windows resources used in this project.
//
// Every Win32 "open" has a matching "close", and the close function differs
// per resource family (WinHttpCloseHandle, CloseHandle, CloseServiceHandle...).
// UniqueResource captures that pairing once, in a traits type, so the rest of
// the code can never forget a close or call the wrong one.

#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>

#include <utility>

namespace hg {

template <typename Traits>
class UniqueResource {
public:
    using Type = typename Traits::Type;

    UniqueResource() noexcept = default;
    explicit UniqueResource(Type value) noexcept : value_(value) {}

    // Owning a handle means exactly one owner: copying is disabled, moving
    // transfers ownership and leaves the source empty.
    UniqueResource(const UniqueResource&) = delete;
    UniqueResource& operator=(const UniqueResource&) = delete;

    UniqueResource(UniqueResource&& other) noexcept : value_(other.release()) {}

    UniqueResource& operator=(UniqueResource&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    ~UniqueResource() { reset(); }

    Type get() const noexcept { return value_; }

    explicit operator bool() const noexcept { return value_ != Traits::invalid(); }

    // Gives up ownership without closing.
    Type release() noexcept { return std::exchange(value_, Traits::invalid()); }

    // Closes the current resource (if any) and takes ownership of a new one.
    void reset(Type value = Traits::invalid()) noexcept {
        if (value_ != Traits::invalid()) {
            Traits::close(value_);
        }
        value_ = value;
    }

private:
    Type value_ = Traits::invalid();
};

// HINTERNET: a user-mode WinHTTP object, not a kernel handle.
struct HInternetTraits {
    using Type = HINTERNET;
    static Type invalid() noexcept { return nullptr; }
    static void close(Type h) noexcept { WinHttpCloseHandle(h); }
};

// Kernel handles whose creation function returns NULL on failure
// (CreateEvent, OpenProcess, CreateThread...).
struct KernelHandleTraits {
    using Type = HANDLE;
    static Type invalid() noexcept { return nullptr; }
    static void close(Type h) noexcept { CloseHandle(h); }
};

// Kernel handles whose creation function returns INVALID_HANDLE_VALUE on
// failure (CreateFile, CreateNamedPipe). Mixing the two conventions is a
// classic Win32 bug, hence two separate types.
struct FileHandleTraits {
    using Type = HANDLE;
    static Type invalid() noexcept { return INVALID_HANDLE_VALUE; }
    static void close(Type h) noexcept { CloseHandle(h); }
};

struct ServiceHandleTraits {
    using Type = SC_HANDLE;
    static Type invalid() noexcept { return nullptr; }
    static void close(Type h) noexcept { CloseServiceHandle(h); }
};

struct CertContextTraits {
    using Type = PCCERT_CONTEXT;
    static Type invalid() noexcept { return nullptr; }
    static void close(Type c) noexcept { CertFreeCertificateContext(c); }
};

struct CertChainTraits {
    using Type = PCCERT_CHAIN_CONTEXT;
    static Type invalid() noexcept { return nullptr; }
    static void close(Type c) noexcept { CertFreeCertificateChain(c); }
};

using HInternet = UniqueResource<HInternetTraits>;
using KernelHandle = UniqueResource<KernelHandleTraits>;
using FileHandle = UniqueResource<FileHandleTraits>;
using ServiceHandle = UniqueResource<ServiceHandleTraits>;
using CertContext = UniqueResource<CertContextTraits>;
using CertChain = UniqueResource<CertChainTraits>;

}  // namespace hg
