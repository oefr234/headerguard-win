# headerguard-win

A Windows command-line tool, written in C++20 directly against the Win32 API,
that sends a GET request to one or more URLs and reports the status code, the
final URL after redirects, the response headers and the TLS certificate.

It is a rewrite of a small Python tool (requests + typer) and exists as a
learning project for Windows systems programming.

## What it demonstrates

| Area | Where | APIs |
|---|---|---|
| HTTP client | `src/http.cpp` | WinHTTP: `WinHttpOpen`, `WinHttpConnect`, `WinHttpOpenRequest`, `WinHttpSendRequest`, `WinHttpReceiveResponse`, `WinHttpQueryHeaders` |
| Error handling | `src/errors.cpp` | `GetLastError`, `FormatMessageW` with the `winhttp.dll` message table |
| RAII | `src/handles.h` | one move-only owner template for `HINTERNET`, kernel handles, service handles, certificate contexts |
| TLS certificate | `src/http.cpp` | `WINHTTP_OPTION_SERVER_CERT_CONTEXT`, `CertGetCertificateChain`, `CertVerifyCertificateChainPolicy` |
| Concurrency | `src/scanner.h`, `src/scanner.cpp` | producer-consumer queue with `std::mutex` and `std::condition_variable`, `std::jthread` workers |
| Windows service | `src/service.cpp` | `StartServiceCtrlDispatcherW`, `RegisterServiceCtrlHandlerExW`, `SetServiceStatus`, `CreateServiceW` |
| IPC | `src/service.cpp` | named pipe with overlapped I/O, an explicit security descriptor, events |

## Build

Open `headerguard-win.slnx` in Visual Studio (workload "Desktop development
with C++") and build the x64 configuration, or from a terminal:

```
msbuild headerguard-win.vcxproj /p:Configuration=Release /p:Platform=x64
```

## Usage

```
headerguard-win [options] <url> [<url>...]
headerguard-win [options] --file urls.txt
headerguard-win serve urls.txt [--interval <seconds>]
headerguard-win query
headerguard-win service install urls.txt [--interval <seconds>]
headerguard-win service uninstall
```

| Option | Meaning |
|---|---|
| `--file <path>` | read URLs from a UTF-8 text file, one per line, `#` for comments |
| `--jobs <n>` | worker threads, default 4 |
| `--timeout <seconds>` | timeout for each of resolve, connect, send, receive; default 10 |
| `--max-redirects <n>` | default 10 |
| `--no-headers` | do not print response headers |
| `--insecure` | continue past certificate errors and report what is wrong with the certificate |

The exit code is 0 when every URL returned a response, 1 when at least one
failed, 2 for a usage error.

## Error categories

| Category | Typical cause | WinHTTP code | Python (requests) equivalent |
|---|---|---|---|
| `MissingScheme` | `example.com` | detected before any API call | `MissingSchema` |
| `InvalidScheme` | `ftp://example.com` | detected after `WinHttpCrackUrl` | `InvalidSchema` |
| `InvalidUrl` | `https://` | 12005 | `InvalidURL` |
| `NameNotResolved` | host does not exist | 12007 | `ConnectionError` |
| `ConnectionFailed` | port closed | 12029, 12030 | `ConnectionError` |
| `Timeout` | server too slow | 12002 | `ConnectTimeout`, `ReadTimeout` |
| `RedirectFailed` | redirect limit exceeded | 12156 | `TooManyRedirects` |
| `TlsFailure` | expired, wrong host, untrusted issuer | 12175 | `SSLError` |

For `TlsFailure` the tool also prints which certificate check failed. WinHTTP
only exposes that through a status callback
(`WINHTTP_CALLBACK_STATUS_SECURE_FAILURE`).

## Monitor, service and pipe

`serve` scans the URL list every `--interval` seconds and keeps the latest
report in memory. `query` connects to the named pipe
`\\.\pipe\headerguard-win` and prints that report. `serve` runs in a console
and needs no special rights, which makes it the easy way to debug the monitor.

`service install` registers the same monitor as the Windows service
`HeaderGuardSvc` (run it from an elevated terminal), started with
`sc start HeaderGuardSvc`.

Design decisions worth knowing:

- The service runs as `NT AUTHORITY\LocalService`, not LocalSystem. That
  account cannot read files inside a user profile, so the executable and the
  URL list have to live somewhere it can read.
- The service command line is quoted, to avoid the unquoted service path
  problem.
- The pipe grants Authenticated Users read access only. Write access on a pipe
  includes the right to create new instances of it.
- The pipe is created with `FILE_FLAG_FIRST_PIPE_INSTANCE` and
  `PIPE_REJECT_REMOTE_CLIENTS`; the client connects with
  `SECURITY_IDENTIFICATION` so the server cannot impersonate it.
- All pipe I/O is overlapped and waits on a stop event as well, so the service
  can stop promptly and a stalled client cannot block it for more than a few
  seconds.

## Limitations

- Only the response headers are read; the body is not downloaded.
- Certificate revocation is not checked.
- The service writes no log; use `serve` to see what the monitor does.
