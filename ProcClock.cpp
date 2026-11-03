// ProcClock - detects system clock changes from the creation timestamps of running processes.
//
// For every running process Windows keeps both the wall-clock creation time and the interrupt time
// (time since boot) at creation. The interrupt time "is not subject to adjustments by users or the
// Windows time service", so comparing the two reveals every clock change that happened while at
// least one of today's still-running processes was being created - and exactly which processes were
// started while the clock was wrong. No event log, no USN journal needed.
//
// Build (Developer Command Prompt):  cl /nologo /O2 /EHsc /std:c++17 /utf-8 /MT ProcClock.cpp
// Requires Windows 10 or later. Run as Administrator to see every process.

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <shellapi.h>

#include <cctype>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "ClockAnalysis.h"

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#endif

namespace {

constexpr const char* kRepoUrl = "https://github.com/santiagolin/ProcClock";

// ---------------------------------------------------------------------------------------------
// Native API declarations (no WDK needed)
// ---------------------------------------------------------------------------------------------

using NtStatus = LONG;
constexpr NtStatus kStatusInfoLengthMismatch = static_cast<NtStatus>(0xC0000004L);
constexpr NtStatus kStatusBufferTooSmall = static_cast<NtStatus>(0xC0000023L);
constexpr NtStatus kStatusBufferOverflow = static_cast<NtStatus>(0x80000005L);
constexpr NtStatus kStatusAccessDenied = static_cast<NtStatus>(0xC0000022L);
constexpr NtStatus kStatusInvalidInfoClass = static_cast<NtStatus>(0xC0000003L);
constexpr ULONG kProcessTelemetryIdInformation = 64;  // PROCESSINFOCLASS value, documented for NtQueryInformationProcess

// PROCESS_TELEMETRY_ID_INFORMATION (learn.microsoft.com/windows/win32/devnotes/process_telemetry_id_information_type).
// No SDK header ships it. Strings and the SID live after the header at the given offsets.
struct TelemetryIdInformation {
    ULONG HeaderSize;  // fields beyond this size are not populated
    ULONG ProcessId;
    ULONG64 ProcessStartKey;  // ProcessSequenceNumber | (BootId << 48)
    ULONG64 CreateTime;       // FILETIME, wall clock
    ULONG64 CreateInterruptTime;          // 100 ns since boot, not affected by clock changes
    ULONG64 CreateUnbiasedInterruptTime;  // same, excluding time spent in sleep/hibernation
    ULONG64 ProcessSequenceNumber;
    ULONG64 SessionCreateTime;
    ULONG SessionId;
    ULONG BootId;
    ULONG ImageChecksum;
    ULONG ImageTimeDateStamp;
    ULONG UserSidOffset;
    ULONG ImagePathOffset;
    ULONG PackageNameOffset;
    ULONG RelativeAppNameOffset;
    ULONG CommandLineOffset;
};
static_assert(offsetof(TelemetryIdInformation, CreateTime) == 16, "unexpected layout");
static_assert(offsetof(TelemetryIdInformation, ProcessSequenceNumber) == 40, "unexpected layout");
static_assert(offsetof(TelemetryIdInformation, CommandLineOffset) == 88, "unexpected layout");

#define FIELD_END(field) (offsetof(TelemetryIdInformation, field) + sizeof(TelemetryIdInformation::field))

using NtQueryInformationProcessFn = NtStatus(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using QueryInterruptTimeFn = VOID(WINAPI*)(PULONGLONG);
using GetSystemTimePreciseFn = VOID(WINAPI*)(LPFILETIME);

NtQueryInformationProcessFn g_ntQueryInformationProcess = nullptr;

// ---------------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------------

std::string ToUtf8(const wchar_t* text, size_t length) {
    if (!text || length == 0) return {};
    const int needed = WideCharToMultiByte(CP_UTF8, 0, text, static_cast<int>(length), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, static_cast<int>(length), &out[0], needed, nullptr, nullptr);
    return out;
}

std::string ToUtf8(const std::wstring& text) { return ToUtf8(text.c_str(), text.size()); }

uint64_t ToUInt64(const FILETIME& ft) {
    return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

std::string BaseName(const std::string& path) {
    const size_t slash = path.find_last_of("\\/");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

std::string DescribeStatus(NtStatus status) { return procclock::Format("NTSTATUS 0x%08lX", static_cast<unsigned long>(status)); }

std::string DescribeWin32Error(DWORD error) {
    if (error == ERROR_ACCESS_DENIED) return "access denied";
    if (error == ERROR_INVALID_PARAMETER) return "process exited";
    return procclock::Format("error %lu", static_cast<unsigned long>(error));
}

// Converts NT device paths (\Device\HarddiskVolume3\...) to drive-letter paths (C:\...) and
// \Device\Mup\server\share to UNC paths. Paths on volumes without a drive letter (for example
// a shadow copy) are kept as they are, which is what an investigator wants to see.
class DosPathMapper {
public:
    DosPathMapper() {
        wchar_t drives[256] = {};
        const DWORD length = GetLogicalDriveStringsW(255, drives);
        if (length == 0 || length >= 255) return;
        for (const wchar_t* drive = drives; *drive; drive += wcslen(drive) + 1) {
            const wchar_t name[3] = {drive[0], L':', L'\0'};
            wchar_t target[1024] = {};
            if (QueryDosDeviceW(name, target, 1024)) mappings_.emplace_back(ToUtf8(target, wcslen(target)), ToUtf8(name, 2));
        }
        mappings_.emplace_back("\\Device\\Mup", "\\");
    }

    std::string ToDosPath(const std::string& path) const {
        for (const auto& mapping : mappings_) {
            const std::string& device = mapping.first;
            if (path.size() > device.size() && path[device.size()] == '\\' && StartsWithIgnoreCase(path, device)) {
                const std::string rest = path.substr(device.size());
                return mapping.second == "\\" ? "\\" + rest : mapping.second + rest;  // UNC: \\server\share
            }
        }
        return path;
    }

private:
    static bool StartsWithIgnoreCase(const std::string& text, const std::string& prefix) {
        for (size_t i = 0; i < prefix.size(); ++i) {
            if (std::tolower(static_cast<unsigned char>(text[i])) != std::tolower(static_cast<unsigned char>(prefix[i])))
                return false;
        }
        return true;
    }
    std::vector<std::pair<std::string, std::string>> mappings_;
};

// Reads a NUL-terminated UTF-16 string stored at `offset` inside the returned buffer.
std::string ReadString(const std::vector<unsigned char>& buffer, ULONG valid, ULONG offset) {
    if (offset == 0 || offset >= valid) return {};
    std::wstring text;
    for (ULONG pos = offset; pos + sizeof(wchar_t) <= valid; pos += sizeof(wchar_t)) {
        wchar_t ch;
        std::memcpy(&ch, buffer.data() + pos, sizeof(ch));
        if (ch == L'\0') break;
        text.push_back(ch);
    }
    return ToUtf8(text);
}

// Resolves the SID stored at `offset` to DOMAIN\user (or the SID string). Results are cached.
std::string ReadUser(const std::vector<unsigned char>& buffer, ULONG valid, ULONG offset,
                     std::map<std::string, std::string>& cache) {
    if (offset == 0 || static_cast<size_t>(offset) + 8 > valid) return {};
    const unsigned subAuthorities = buffer[offset + 1];
    if (static_cast<size_t>(offset) + 8 + 4 * static_cast<size_t>(subAuthorities) > valid) return {};
    PSID sid = const_cast<unsigned char*>(buffer.data() + offset);
    if (!IsValidSid(sid)) return {};

    std::string sidText;
    LPWSTR sidString = nullptr;
    if (ConvertSidToStringSidW(sid, &sidString)) {
        sidText = ToUtf8(sidString, wcslen(sidString));
        LocalFree(sidString);
    }
    auto cached = cache.find(sidText);
    if (cached != cache.end()) return cached->second;

    std::string result = sidText;
    wchar_t name[256], domain[256];
    DWORD nameLength = 256, domainLength = 256;
    SID_NAME_USE use;
    if (LookupAccountSidW(nullptr, sid, name, &nameLength, domain, &domainLength, &use)) {
        result = (domainLength ? ToUtf8(domain, wcslen(domain)) + "\\" : std::string()) + ToUtf8(name, wcslen(name));
    }
    cache[sidText] = result;
    return result;
}

// ---------------------------------------------------------------------------------------------
// Privileges and clocks
// ---------------------------------------------------------------------------------------------

bool IsElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD length = 0;
    const BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &length);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated;
}

bool EnableDebugPrivilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return false;
    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bool ok = LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &privileges.Privileges[0].Luid) &&
              AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr) &&
              GetLastError() == ERROR_SUCCESS;  // ERROR_NOT_ALL_ASSIGNED when the privilege is not held
    CloseHandle(token);
    return ok;
}

// KUSER_SHARED_DATA.InterruptTime, read with the documented High1/Low/High2 protocol.
uint64_t ReadSharedInterruptTime() {
    struct KSystemTime {
        ULONG LowPart;
        LONG High1Time;
        LONG High2Time;
    };
    const volatile KSystemTime* interruptTime = reinterpret_cast<const volatile KSystemTime*>(0x7FFE0008);
    for (;;) {
        const LONG high1 = interruptTime->High1Time;
        MemoryBarrier();
        const ULONG low = interruptTime->LowPart;
        MemoryBarrier();
        const LONG high2 = interruptTime->High2Time;
        if (high1 == high2) return (static_cast<uint64_t>(static_cast<ULONG>(high1)) << 32) | low;
        YieldProcessor();
    }
}

uint64_t InterruptTimeNow() {
    static QueryInterruptTimeFn query = [] {
        for (const wchar_t* dll : {L"kernelbase.dll", L"kernel32.dll"}) {
            if (HMODULE module = GetModuleHandleW(dll)) {
                if (FARPROC proc = GetProcAddress(module, "QueryInterruptTimePrecise")) {
                    return reinterpret_cast<QueryInterruptTimeFn>(reinterpret_cast<void*>(proc));
                }
            }
        }
        return static_cast<QueryInterruptTimeFn>(nullptr);
    }();
    if (query) {
        ULONGLONG value = 0;
        query(&value);
        return value;
    }
    return ReadSharedInterruptTime();
}

uint64_t SystemTimeNow() {
    static GetSystemTimePreciseFn precise = [] {
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        FARPROC proc = kernel32 ? GetProcAddress(kernel32, "GetSystemTimePreciseAsFileTime") : nullptr;
        return reinterpret_cast<GetSystemTimePreciseFn>(reinterpret_cast<void*>(proc));
    }();
    FILETIME now{};
    if (precise) precise(&now);
    else GetSystemTimeAsFileTime(&now);
    return ToUInt64(now);
}

// Both clocks "now", sampled as close together as possible.
void ReadClocks(uint64_t& systemTime, uint64_t& interruptTime) {
    const uint64_t before = InterruptTimeNow();
    systemTime = SystemTimeNow();
    const uint64_t after = InterruptTimeNow();
    interruptTime = before + (after - before) / 2;
}

// ---------------------------------------------------------------------------------------------
// Process collection
// ---------------------------------------------------------------------------------------------

struct SnapshotEntry {
    DWORD pid;
    DWORD parentPid;
    std::string name;
};

std::vector<SnapshotEntry> EnumerateProcesses() {
    std::vector<SnapshotEntry> entries;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return entries;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            entries.push_back({entry.th32ProcessID, entry.th32ParentProcessID, ToUtf8(entry.szExeFile, wcslen(entry.szExeFile))});
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return entries;
}

NtStatus QueryTelemetry(HANDLE process, std::vector<unsigned char>& buffer, ULONG& returned) {
    buffer.assign(4096, 0);
    for (int attempt = 0; attempt < 5; ++attempt) {
        returned = 0;
        const NtStatus status = g_ntQueryInformationProcess(process, kProcessTelemetryIdInformation, buffer.data(),
                                                            static_cast<ULONG>(buffer.size()), &returned);
        if (status == kStatusInfoLengthMismatch || status == kStatusBufferTooSmall || status == kStatusBufferOverflow) {
            const size_t needed = returned > buffer.size() ? returned : buffer.size() * 2;
            buffer.assign(needed + 256, 0);
            continue;
        }
        if (status >= 0 && (returned == 0 || returned > buffer.size())) returned = static_cast<ULONG>(buffer.size());
        return status;
    }
    return kStatusBufferTooSmall;
}

struct ReadResult {
    bool ok = false;
    std::string error;
    NtStatus status = 0;
    procclock::ProcessRecord record;
    uint32_t bootId = 0;
    bool creationTimeMismatch = false;  // self-check against GetProcessTimes
};

ReadResult ReadProcess(const SnapshotEntry& entry, std::map<std::string, std::string>& userCache,
                       const DosPathMapper& paths) {
    ReadResult result;
    result.record.pid = entry.pid;
    result.record.parentPid = entry.parentPid;
    result.record.name = entry.name;

    // Limited access works even for protected processes; fall back to full query access if needed.
    for (DWORD access : {static_cast<DWORD>(PROCESS_QUERY_LIMITED_INFORMATION), static_cast<DWORD>(PROCESS_QUERY_INFORMATION)}) {
        HANDLE process = OpenProcess(access, FALSE, entry.pid);
        if (!process) {
            result.error = DescribeWin32Error(GetLastError());
            continue;
        }
        std::vector<unsigned char> buffer;
        ULONG valid = 0;
        const NtStatus status = QueryTelemetry(process, buffer, valid);
        if (status < 0) {
            CloseHandle(process);
            result.status = status;
            result.error = status == kStatusAccessDenied ? "access denied" : DescribeStatus(status);
            if (status == kStatusAccessDenied) continue;
            return result;
        }

        TelemetryIdInformation info{};
        std::memcpy(&info, buffer.data(), std::min<size_t>(valid, sizeof(info)));
        const ULONG header = std::min<ULONG>(info.HeaderSize, valid);
        if (header < FIELD_END(CreateInterruptTime)) {
            CloseHandle(process);
            result.error = "telemetry header too small";
            return result;
        }
        procclock::ProcessRecord& r = result.record;
        r.createTime = info.CreateTime;
        r.createInterruptTime = info.CreateInterruptTime;
        if (header >= FIELD_END(ProcessSequenceNumber)) r.sequence = info.ProcessSequenceNumber;
        if (header >= FIELD_END(SessionId)) r.sessionId = info.SessionId;
        if (header >= FIELD_END(BootId)) result.bootId = info.BootId;
        if (header >= FIELD_END(UserSidOffset)) r.user = ReadUser(buffer, valid, info.UserSidOffset, userCache);
        if (header >= FIELD_END(ImagePathOffset)) r.imagePath = paths.ToDosPath(ReadString(buffer, valid, info.ImagePathOffset));
        if (header >= FIELD_END(CommandLineOffset)) r.commandLine = ReadString(buffer, valid, info.CommandLineOffset);
        if (!r.imagePath.empty()) r.name = BaseName(r.imagePath);  // authoritative even if the PID was reused

        // Self-check: the telemetry creation time must match the classic API.
        FILETIME creation{}, exitTime{}, kernelTime{}, userTime{};
        if (GetProcessTimes(process, &creation, &exitTime, &kernelTime, &userTime)) {
            const int64_t diff = static_cast<int64_t>(ToUInt64(creation)) - static_cast<int64_t>(r.createTime);
            result.creationTimeMismatch = procclock::AbsTicks(diff) > procclock::kTicksPerSecond;
        }
        CloseHandle(process);
        if (r.createTime == 0) {
            result.error = "no creation time";
            return result;
        }
        result.ok = true;
        result.error.clear();
        return result;
    }
    return result;
}

// ---------------------------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------------------------

struct Arguments {
    procclock::Options options;
    procclock::ReportOptions report;
    std::wstring csvPath;
    bool help = false;
};

const char* kUsage =
    "Usage: ProcClock.exe [--threshold <seconds>] [--reference now|boot] [--all] [--csv <file>]\n"
    "\n"
    "  --threshold <s>   Ignore clock jumps up to this many seconds (default 60)\n"
    "  --reference now   Compute real creation times with the current clock (default)\n"
    "  --reference boot  Use the clock as it was at boot instead (if the current clock is wrong)\n"
    "  --all             List every process and print full command lines\n"
    "  --csv <file>      Export every analyzed process to CSV\n"
    "\n"
    "Exit code: 0 = no clock change, 2 = clock change detected, 1 = error.\n";

bool ParseArguments(Arguments& args, std::string& error) {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return true;
    bool ok = true;
    for (int i = 1; i < argc && ok; ++i) {
        const std::wstring arg = argv[i];
        const bool hasValue = i + 1 < argc;
        if (arg == L"--help" || arg == L"-h" || arg == L"/?") {
            args.help = true;
        } else if (arg == L"--all") {
            args.report.listAll = true;
        } else if (arg == L"--threshold" && hasValue) {
            wchar_t* end = nullptr;
            const double seconds = wcstod(argv[++i], &end);
            if (!end || *end != L'\0' || seconds < 1) {
                error = "--threshold needs a number of seconds >= 1";
                ok = false;
            } else {
                args.options.thresholdTicks = static_cast<int64_t>(seconds * procclock::kTicksPerSecond);
            }
        } else if (arg == L"--reference" && hasValue) {
            const std::wstring value = argv[++i];
            if (value == L"now") args.options.reference = procclock::Reference::Now;
            else if (value == L"boot") args.options.reference = procclock::Reference::Boot;
            else {
                error = "--reference must be 'now' or 'boot'";
                ok = false;
            }
        } else if (arg == L"--csv" && hasValue) {
            args.csvPath = argv[++i];
        } else {
            error = "Unknown or incomplete argument: " + ToUtf8(arg);
            ok = false;
        }
    }
    LocalFree(argv);
    return ok;
}

bool LaunchedInOwnConsole() {
    DWORD processes[2];
    return GetConsoleProcessList(processes, 2) == 1;  // double-clicked from Explorer
}

int Run(const Arguments& args) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    g_ntQueryInformationProcess = ntdll ? reinterpret_cast<NtQueryInformationProcessFn>(
                                              reinterpret_cast<void*>(GetProcAddress(ntdll, "NtQueryInformationProcess")))
                                        : nullptr;
    if (!g_ntQueryInformationProcess) {
        std::cerr << "NtQueryInformationProcess is not available.\n";
        return 1;
    }

    procclock::CollectionInfo info;
    const bool elevated = IsElevated();
    if (elevated) EnableDebugPrivilege();
    else info.warnings.push_back("not running as Administrator - many system processes cannot be read.");

    const std::vector<SnapshotEntry> entries = EnumerateProcesses();
    std::vector<procclock::ProcessRecord> records;
    std::map<std::string, std::string> userCache;
    const DosPathMapper paths;
    std::map<uint32_t, size_t> bootIds;
    size_t mismatches = 0, unsupported = 0;

    const DWORD self = GetCurrentProcessId();
    for (const SnapshotEntry& entry : entries) {
        if (entry.pid == 0 || entry.pid == self) continue;  // idle process; ProcClock itself is not evidence
        ++info.enumerated;
        ReadResult result = ReadProcess(entry, userCache, paths);
        if (result.status == kStatusInvalidInfoClass) ++unsupported;
        if (!result.ok) {
            info.unreadable.push_back(procclock::Format("%s (PID %lu): %s", entry.name.c_str(),
                                                        static_cast<unsigned long>(entry.pid), result.error.c_str()));
            continue;
        }
        if (result.creationTimeMismatch) ++mismatches;
        if (result.bootId) ++bootIds[result.bootId];
        records.push_back(std::move(result.record));
    }

    uint64_t nowSystemTime = 0, nowInterruptTime = 0;
    ReadClocks(nowSystemTime, nowInterruptTime);  // after collection, so "now" is later than every creation

    if (records.empty()) {
        if (unsupported) std::cerr << "This Windows version does not provide process telemetry information (Windows 10+ required).\n";
        else std::cerr << "No process could be read. Try running as Administrator.\n";
        return 1;
    }
    if (mismatches) {
        info.warnings.push_back(procclock::Format(
            "%zu processes report a telemetry creation time that differs from GetProcessTimes - results may be unreliable.",
            mismatches));
    }
    if (!bootIds.empty()) {
        info.bootId = bootIds.rbegin()->first;
        if (bootIds.size() > 1) info.warnings.push_back("processes report different boot IDs.");
    }

    const procclock::Analysis analysis = procclock::Analyze(std::move(records), nowSystemTime, nowInterruptTime, args.options);
    procclock::PrintReport(std::cout, analysis, info, args.report);

    if (!args.csvPath.empty()) {
        std::ostringstream csv;
        procclock::WriteCsv(csv, analysis);
        const std::string data = csv.str();
        FILE* file = _wfopen(args.csvPath.c_str(), L"wb");
        if (file && fwrite(data.data(), 1, data.size(), file) == data.size()) {
            std::cout << "\nCSV written to " << ToUtf8(args.csvPath) << "\n";
        } else {
            std::cerr << "\nCould not write CSV to " << ToUtf8(args.csvPath) << "\n";
        }
        if (file) fclose(file);
    }
    return analysis.steps.empty() ? 0 : 2;
}

}  // namespace

int main() {
    SetConsoleOutputCP(CP_UTF8);
    std::cout << "ProcClock " << procclock::kVersion << " - detects system clock changes from process creation times\n"
              << kRepoUrl << "\n\n";

    Arguments args;
    std::string error;
    int exitCode = 0;
    if (!ParseArguments(args, error)) {
        std::cerr << error << "\n\n" << kUsage;
        exitCode = 1;
    } else if (args.help) {
        std::cout << kUsage;
    } else {
        exitCode = Run(args);
    }

    if (LaunchedInOwnConsole()) {
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
    }
    return exitCode;
}
