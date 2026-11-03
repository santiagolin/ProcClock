// ClockAnalysis.h - portable core of ProcClock.
//
// Every Windows process records two clocks when it is created:
//   * CreateTime          - the system (wall) clock, which anyone with the right privilege can change
//   * CreateInterruptTime - time since boot, which is NOT affected by clock changes
// Their difference is the boot time "as seen by the clock" at that moment. While nobody touches the
// clock it is identical for every process; when the clock is changed it jumps. Sorting processes by
// creation order therefore shows when the clock was changed, by how much, and which processes were
// started while it was wrong.
//
// This header has no Windows dependencies so the logic can be unit-tested on any platform.
#pragma once

#include <algorithm>
#include <utility>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <map>
#include <ostream>
#include <string>
#include <vector>

namespace procclock {

constexpr int64_t kTicksPerSecond = 10000000LL;  // FILETIME and interrupt time both use 100 ns units
constexpr int64_t kTicksPerMinute = 60 * kTicksPerSecond;
constexpr int64_t kTicksPerHour = 60 * kTicksPerMinute;
constexpr int64_t kTicksPerDay = 24 * kTicksPerHour;
// Jumps this soon after boot are often the time service correcting the hardware clock.
constexpr int64_t kEarlyBootWindow = 10 * kTicksPerMinute;
// Processes created at the same moment on different CPUs can get their sequence numbers in the
// opposite order of their creation times. Disagreements closer together than this are normal.
constexpr int64_t kSequenceTolerance = kTicksPerSecond;
// The System process gets sequence number 1 at the start of boot, but Windows records its creation
// time seconds later, after other early processes such as Registry (seen: 4.2 s on Windows). It is
// left out of the sequence check; its timestamps still take part in the clock analysis.
constexpr uint32_t kSystemPid = 4;
constexpr const char* kVersion = "0.1.3";

struct ProcessRecord {
    uint32_t pid = 0;
    uint32_t parentPid = 0;
    uint32_t sessionId = 0;
    uint64_t sequence = 0;            // ProcessSequenceNumber: creation order within this boot (0 = unknown)
    uint64_t createTime = 0;          // wall clock at creation (FILETIME: 100 ns since 1601-01-01 UTC)
    uint64_t createInterruptTime = 0; // 100 ns since boot at creation; immune to clock changes
    std::string name;                 // all strings are UTF-8
    std::string user;
    std::string imagePath;
    std::string commandLine;
};

// Wall clock minus monotonic clock at creation = boot time according to the clock at that moment.
inline int64_t ApparentBootTime(const ProcessRecord& p) {
    return static_cast<int64_t>(p.createTime) - static_cast<int64_t>(p.createInterruptTime);
}

inline int64_t AbsTicks(int64_t v) { return v < 0 ? -v : v; }

enum class Reference { Now, Boot };
enum class Severity { Info, Check, Suspicious };

struct Options {
    int64_t thresholdTicks = 60 * kTicksPerSecond;  // smaller jumps are treated as normal time-sync noise
    Reference reference = Reference::Now;
};

// A run of consecutively created processes that saw the same clock offset.
struct Segment {
    size_t first = 0;    // index into Analysis::processes (inclusive)
    size_t last = 0;     // inclusive
    int64_t offset = 0;  // median apparent boot time of the run
    size_t Count() const { return last - first + 1; }
};

// A jump of the wall clock relative to the monotonic clock.
struct ClockStep {
    size_t before = 0;       // index of the newest process created before the jump
    size_t after = 0;        // index of the oldest process created after it; == processes.size() means "now"
    int64_t delta = 0;       // size of the jump; negative = clock set back
    uint64_t notBefore = 0;  // the jump happened after this interrupt time...
    uint64_t notAfter = 0;   // ...and before this one
    int pairedWith = -1;     // index of the step that undid this one (or that this one undid)
    Severity severity = Severity::Info;
};

// Two processes, adjacent in creation order, whose sequence numbers run backwards.
struct SequenceInversion {
    size_t first;   // created first, yet has the higher sequence number
    size_t second;  // created next, with the lower sequence number
    int64_t gap;    // interrupt time between the two creations
};

struct Analysis {
    Options options;
    std::vector<ProcessRecord> processes;  // sorted in creation order
    std::vector<int64_t> offsets;          // apparent boot time, per process
    std::vector<int64_t> shifts;           // offset minus reference offset, per process
    std::vector<size_t> segmentOf;         // segment index, per process
    std::vector<Segment> segments;
    std::vector<ClockStep> steps;
    uint64_t nowSystemTime = 0;
    uint64_t nowInterruptTime = 0;
    int64_t nowOffset = 0;        // apparent boot time according to the clock right now
    int64_t bootOffset = 0;       // apparent boot time according to the oldest processes
    int64_t referenceOffset = 0;  // used to compute "real" creation times
    std::vector<SequenceInversion> inversions;  // sequence numbers that disagree with creation order

    // Lowest and highest known sequence number in a segment ({0, 0} when unknown).
    std::pair<uint64_t, uint64_t> SequenceRange(size_t s) const {
        uint64_t low = 0, high = 0;
        for (size_t i = segments[s].first; i <= segments[s].last; ++i) {
            const uint64_t seq = processes[i].sequence;
            if (seq == 0) continue;
            if (low == 0 || seq < low) low = seq;
            if (seq > high) high = seq;
        }
        return {low, high};
    }

    // Disagreements too far apart to be explained by processes created at the same moment.
    size_t SignificantInversions() const {
        size_t count = 0;
        for (const SequenceInversion& inv : inversions) count += inv.gap > kSequenceTolerance ? 1 : 0;
        return count;
    }

    bool IsShifted(size_t i) const { return AbsTicks(shifts[i]) > options.thresholdTicks; }
    bool SegmentShifted(size_t s) const {
        return AbsTicks(segments[s].offset - referenceOffset) > options.thresholdTicks;
    }
    // Creation time according to the reference clock instead of the (possibly altered) wall clock.
    int64_t RealCreateTime(size_t i) const {
        return static_cast<int64_t>(processes[i].createInterruptTime) + referenceOffset;
    }
    size_t ShiftedProcessCount() const { return ShiftedCountRelativeTo(referenceOffset); }
    // Processes whose clock differed from the clock given by `offset` (an apparent boot time).
    size_t ShiftedCountRelativeTo(int64_t offset) const {
        size_t n = 0;
        for (size_t i = 0; i < processes.size(); ++i) n += AbsTicks(offsets[i] - offset) > options.thresholdTicks ? 1 : 0;
        return n;
    }
    size_t CountSteps(bool backward) const {
        size_t n = 0;
        for (const auto& s : steps) n += ((s.delta < 0) == backward) ? 1 : 0;
        return n;
    }
};

inline int64_t MedianOf(std::vector<int64_t> v) {
    if (v.empty()) return 0;
    std::nth_element(v.begin(), v.begin() + v.size() / 2, v.end());
    return v[v.size() / 2];
}

inline Analysis Analyze(std::vector<ProcessRecord> procs, uint64_t nowSystemTime, uint64_t nowInterruptTime,
                        const Options& options) {
    Analysis a;
    a.options = options;
    a.nowSystemTime = nowSystemTime;
    a.nowInterruptTime = nowInterruptTime;
    a.nowOffset = static_cast<int64_t>(nowSystemTime) - static_cast<int64_t>(nowInterruptTime);

    // Records without a wall-clock time cannot be placed on the timeline.
    procs.erase(std::remove_if(procs.begin(), procs.end(),
                               [](const ProcessRecord& p) { return p.createTime == 0; }),
                procs.end());

    // Interrupt time gives the true creation order; the sequence number breaks ties.
    std::stable_sort(procs.begin(), procs.end(), [](const ProcessRecord& x, const ProcessRecord& y) {
        if (x.createInterruptTime != y.createInterruptTime) return x.createInterruptTime < y.createInterruptTime;
        return x.sequence < y.sequence;
    });
    a.processes = std::move(procs);
    const size_t n = a.processes.size();

    size_t previous = n;  // last process that took part in the sequence check
    for (size_t i = 0; i < n; ++i) {
        const ProcessRecord& p = a.processes[i];
        a.offsets.push_back(ApparentBootTime(p));
        if (p.sequence == 0 || p.pid == kSystemPid) continue;
        if (previous < n && p.sequence < a.processes[previous].sequence) {
            a.inversions.push_back(
                {previous, i, static_cast<int64_t>(p.createInterruptTime - a.processes[previous].createInterruptTime)});
        }
        previous = i;
    }

    // 1. Split the creation-ordered list wherever the offset jumps by more than the threshold.
    if (n > 0) {
        Segment current;
        for (size_t i = 1; i < n; ++i) {
            if (AbsTicks(a.offsets[i] - a.offsets[i - 1]) > options.thresholdTicks) {
                current.last = i - 1;
                a.segments.push_back(current);
                current = Segment{};
                current.first = i;
            }
        }
        current.last = n - 1;
        a.segments.push_back(current);
        for (auto& s : a.segments) {
            s.offset = MedianOf(std::vector<int64_t>(a.offsets.begin() + static_cast<std::ptrdiff_t>(s.first),
                                                     a.offsets.begin() + static_cast<std::ptrdiff_t>(s.last) + 1));
        }
    }
    a.segmentOf.assign(n, 0);
    for (size_t s = 0; s < a.segments.size(); ++s) {
        for (size_t i = a.segments[s].first; i <= a.segments[s].last; ++i) a.segmentOf[i] = s;
    }

    // 2. Every boundary between segments is a clock jump.
    for (size_t s = 1; s < a.segments.size(); ++s) {
        ClockStep st;
        st.before = a.segments[s - 1].last;
        st.after = a.segments[s].first;
        st.delta = a.offsets[st.after] - a.offsets[st.before];
        st.notBefore = a.processes[st.before].createInterruptTime;
        st.notAfter = a.processes[st.after].createInterruptTime;
        a.steps.push_back(st);
    }
    // A jump after the newest process only shows up when comparing with the clock right now.
    if (n > 0 && AbsTicks(a.nowOffset - a.offsets[n - 1]) > options.thresholdTicks) {
        ClockStep st;
        st.before = n - 1;
        st.after = n;
        st.delta = a.nowOffset - a.offsets[n - 1];
        st.notBefore = a.processes[n - 1].createInterruptTime;
        st.notAfter = nowInterruptTime;
        a.steps.push_back(st);
    }

    // 3. Pair each jump with a later opposite jump of about the same size (set back, then restored).
    for (size_t i = 0; i < a.steps.size(); ++i) {
        if (a.steps[i].pairedWith >= 0) continue;
        const int64_t tolerance = std::max<int64_t>(options.thresholdTicks, AbsTicks(a.steps[i].delta) / 20);
        for (size_t j = i + 1; j < a.steps.size(); ++j) {
            if (a.steps[j].pairedWith >= 0) continue;
            if ((a.steps[i].delta < 0) == (a.steps[j].delta < 0)) continue;
            if (AbsTicks(a.steps[i].delta + a.steps[j].delta) <= tolerance) {
                a.steps[i].pairedWith = static_cast<int>(j);
                a.steps[j].pairedWith = static_cast<int>(i);
                break;
            }
        }
    }

    // 4. Severity. A clock that goes back and is later restored is the classic manipulation pattern.
    for (auto& st : a.steps) {
        const bool early = st.notAfter <= static_cast<uint64_t>(kEarlyBootWindow);
        if (st.pairedWith >= 0) st.severity = Severity::Suspicious;
        else if (st.delta < 0) st.severity = early ? Severity::Check : Severity::Suspicious;
        else st.severity = Severity::Info;
    }

    // 5. Reference clock for "real" creation times.
    a.bootOffset = a.segments.empty() ? a.nowOffset : a.segments.front().offset;
    a.referenceOffset = (options.reference == Reference::Boot) ? a.bootOffset : a.nowOffset;
    for (size_t i = 0; i < n; ++i) a.shifts.push_back(a.offsets[i] - a.referenceOffset);
    return a;
}

// ---------------------------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------------------------

inline std::string Format(const char* fmt, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    return buffer;
}

constexpr int64_t kSecondsFrom1601To1970 = 11644473600LL;

inline int64_t FloorDiv(int64_t a, int64_t b) { return (a >= 0) ? a / b : -((-a + b - 1) / b); }

// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
inline int64_t DaysFromCivil(int64_t y, unsigned m, unsigned d) {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

// FILETIME for a UTC date and time (used by the tests).
inline uint64_t FileTimeFromUtc(int y, unsigned mo, unsigned d, unsigned h, unsigned mi, unsigned s) {
    const int64_t unixSeconds = DaysFromCivil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s;
    return static_cast<uint64_t>((unixSeconds + kSecondsFrom1601To1970) * kTicksPerSecond);
}

// FILETIME -> "YYYY-MM-DD HH:MM:SS" (UTC).
inline std::string FormatFileTime(int64_t fileTime) {
    if (fileTime < 0) return "(invalid time)";
    const int64_t unixSeconds = fileTime / kTicksPerSecond - kSecondsFrom1601To1970;
    const int64_t days = FloorDiv(unixSeconds, 86400);
    const int64_t secondsOfDay = unixSeconds - days * 86400;
    const int64_t z = days + 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    const unsigned day = doy - (153 * mp + 2) / 5 + 1;
    const unsigned month = mp < 10 ? mp + 3 : mp - 9;
    const int64_t year = static_cast<int64_t>(yoe) + era * 400 + (month <= 2 ? 1 : 0);
    return Format("%04lld-%02u-%02u %02lld:%02lld:%02lld", static_cast<long long>(year), month, day,
                  static_cast<long long>(secondsOfDay / 3600), static_cast<long long>(secondsOfDay % 3600 / 60),
                  static_cast<long long>(secondsOfDay % 60));
}

// 100 ns ticks -> "1d 02h 03m 04s", "2h 00m 00s", "5m 03s", "42s". Optional +/- sign.
inline std::string FormatDuration(int64_t ticks, bool withSign = false) {
    const bool negative = ticks < 0;
    unsigned long long s = static_cast<unsigned long long>((AbsTicks(ticks) + kTicksPerSecond / 2) / kTicksPerSecond);
    const unsigned long long d = s / 86400; s %= 86400;
    const unsigned long long h = s / 3600; s %= 3600;
    const unsigned long long m = s / 60; s %= 60;
    std::string text;
    if (d) text = Format("%llud %02lluh %02llum %02llus", d, h, m, s);
    else if (h) text = Format("%lluh %02llum %02llus", h, m, s);
    else if (m) text = Format("%llum %02llus", m, s);
    else text = Format("%llus", s);
    if (text == "0s") return text;
    return withSign ? (negative ? "-" : "+") + text : text;
}

// Seconds with millisecond precision, e.g. "0.004s" or "12.345s".
inline std::string FormatSeconds(int64_t ticks) {
    const unsigned long long ms = static_cast<unsigned long long>((AbsTicks(ticks) + 5000) / 10000);
    return Format("%s%llu.%03llus", ticks < 0 ? "-" : "", ms / 1000, ms % 1000);
}

// Exact seconds (100 ns resolution) for CSV, e.g. "1234.5678901".
inline std::string FormatExactSeconds(uint64_t ticks) {
    const unsigned long long t = static_cast<unsigned long long>(ticks);
    const unsigned long long perSecond = static_cast<unsigned long long>(kTicksPerSecond);
    return Format("%llu.%07llu", t / perSecond, t % perSecond);
}

inline std::string Truncate(const std::string& s, size_t maxLength) {
    if (maxLength == 0 || s.size() <= maxLength) return s;
    return s.substr(0, maxLength) + "...";
}

// ---------------------------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------------------------

struct CollectionInfo {
    size_t enumerated = 0;                // processes in the snapshot
    std::vector<std::string> unreadable;  // "name (PID n): reason"
    uint32_t bootId = 0;
    std::vector<std::string> warnings;
};

struct ReportOptions {
    bool listAll = false;                 // print every process, untruncated
    size_t maxProcessesPerSegment = 40;
    size_t maxCommandLine = 160;
};

inline const char* SeverityLabel(Severity s) {
    switch (s) {
        case Severity::Suspicious: return "SUSPICIOUS";
        case Severity::Check: return "CHECK";
        default: return "INFO";
    }
}

inline std::string DescribeProcess(const Analysis& a, size_t i) {
    const ProcessRecord& p = a.processes[i];
    std::string text = Format("%s (PID %u", p.name.empty() ? "?" : p.name.c_str(), p.pid);
    if (p.sequence) text += Format(", seq %llu", static_cast<unsigned long long>(p.sequence));
    return text + ")";
}

// Parent name, but only if that PID still belongs to the process that existed before the child.
inline std::string DescribeParent(const Analysis& a, size_t i, const std::map<uint32_t, size_t>& byPid) {
    const ProcessRecord& p = a.processes[i];
    if (p.parentPid == 0) return "none";  // System and the idle process have no parent
    auto it = byPid.find(p.parentPid);
    // A "parent" created after its child is a different process that reused the PID. System is the
    // exception: it never exits, but Windows records its creation time late (see kSystemPid).
    if (it != byPid.end() &&
        (p.parentPid == kSystemPid || a.processes[it->second].createInterruptTime <= p.createInterruptTime)) {
        return Format("%s (PID %u)", a.processes[it->second].name.c_str(), p.parentPid);
    }
    return Format("PID %u (exited)", p.parentPid);
}

inline void PrintReport(std::ostream& out, const Analysis& a, const CollectionInfo& info, const ReportOptions& ro) {
    const bool refIsNow = a.options.reference == Reference::Now;
    const char* refName = refIsNow ? "the current system clock" : "the clock at boot";
    std::map<uint32_t, size_t> byPid;
    for (size_t i = 0; i < a.processes.size(); ++i) byPid[a.processes[i].pid] = i;

    for (const auto& w : info.warnings) out << "WARNING: " << w << "\n";
    bool printedNotice = !info.warnings.empty();
    for (const SequenceInversion& inv : a.inversions) {
        const bool significant = inv.gap > kSequenceTolerance;
        if (!significant && !ro.listAll) continue;
        out << (significant ? "WARNING: " : "Note: ") << DescribeProcess(a, inv.second) << " was created "
            << FormatSeconds(inv.gap) << " after " << DescribeProcess(a, inv.first)
            << " but has a lower sequence number"
            << (significant ? ".\n" : " (normal when processes start at the same moment).\n");
        printedNotice = true;
    }
    if (printedNotice) out << "\n";

    out << "Current system time : " << FormatFileTime(static_cast<int64_t>(a.nowSystemTime))
        << " UTC   <- compare with a trusted clock\n";
    out << "Boot time           : " << FormatFileTime(a.referenceOffset) << " UTC   (uptime "
        << FormatDuration(static_cast<int64_t>(a.nowInterruptTime));
    if (info.bootId) out << ", boot ID " << info.bootId;
    out << ")\n";
    out << "Processes analyzed  : " << a.processes.size();
    if (info.enumerated) out << " of " << info.enumerated << " running";
    if (!info.unreadable.empty()) out << " (" << info.unreadable.size() << " could not be read)";
    out << "\n";
    out << "Threshold           : " << FormatDuration(a.options.thresholdTicks) << "\n";
    out << "Reference clock     : " << refName << "\n";
    if (AbsTicks(a.nowOffset - a.bootOffset) > a.options.thresholdTicks) {
        out << "Note                : the clock now differs from the clock at boot by "
            << FormatDuration(a.nowOffset - a.bootOffset, true) << ".\n"
            << "                      If the current clock is the wrong one, re-run with --reference "
            << (refIsNow ? "boot" : "now") << ".\n";
    }
    out << "\n";

    if (a.processes.empty()) {
        out << "No process could be analyzed.\n";
        return;
    }

    // Timeline
    out << "== Clock timeline (creation order; times per reference clock) ==\n";
    out << Format("  %-4s %-18s %6s  %-17s %-19s  %s\n", "Seg", "Clock vs ref", "Procs", "Sequence",
                  "First created (UTC)", "Last created (UTC)");
    for (size_t s = 0; s < a.segments.size(); ++s) {
        const Segment& seg = a.segments[s];
        const auto range = a.SequenceRange(s);
        std::string seq = range.first ? Format("%llu-%llu", static_cast<unsigned long long>(range.first),
                                               static_cast<unsigned long long>(range.second))
                                      : std::string("-");
        out << Format("  %-4zu %-18s %6zu  %-17s %-19s  %-19s%s\n", s + 1,
                      FormatDuration(seg.offset - a.referenceOffset, true).c_str(), seg.Count(), seq.c_str(),
                      FormatFileTime(a.RealCreateTime(seg.first)).c_str(),
                      FormatFileTime(a.RealCreateTime(seg.last)).c_str(), a.SegmentShifted(s) ? "  <== shifted" : "");
    }
    out << "\n";

    // Clock changes
    out << "== Clock changes ==\n";
    if (a.steps.empty()) out << "  None. Every process was created with the same clock offset.\n";
    for (size_t k = 0; k < a.steps.size(); ++k) {
        const ClockStep& st = a.steps[k];
        const bool backward = st.delta < 0;
        out << Format("  [%zu] %-10s Clock set %s by %s\n", k + 1, SeverityLabel(st.severity),
                      backward ? "BACK" : "FORWARD", FormatDuration(st.delta).c_str());
        out << "      When   : between " << FormatFileTime(static_cast<int64_t>(st.notBefore) + a.referenceOffset)
            << " and " << FormatFileTime(static_cast<int64_t>(st.notAfter) + a.referenceOffset) << " UTC (uptime "
            << FormatDuration(static_cast<int64_t>(st.notBefore)) << " to "
            << FormatDuration(static_cast<int64_t>(st.notAfter)) << ")\n";
        out << "      Before : " << DescribeProcess(a, st.before) << "\n";
        out << "      After  : "
            << (st.after < a.processes.size() ? DescribeProcess(a, st.after)
                                              : std::string("(now - no running process was created after this change)"))
            << "\n";
        if (st.pairedWith >= 0) {
            const size_t other = static_cast<size_t>(st.pairedWith);
            if (other > k) {
                const ClockStep& end = a.steps[other];
                const int64_t minDuration = static_cast<int64_t>(end.notBefore) - static_cast<int64_t>(st.notAfter);
                const int64_t maxDuration = static_cast<int64_t>(end.notAfter) - static_cast<int64_t>(st.notBefore);
                out << "      Undone : by change [" << other + 1 << "]; the clock stayed "
                    << (backward ? "behind" : "ahead") << " for "
                    << (minDuration > 0 ? FormatDuration(minDuration) + " to " : std::string("up to "))
                    << FormatDuration(maxDuration) << "\n";
            } else {
                out << "      Undoes : change [" << other + 1 << "]\n";
            }
        } else if (st.severity == Severity::Check) {
            out << "      Hint   : shortly after boot; may be the time service correcting a fast hardware clock\n";
        } else if (!backward) {
            out << "      Hint   : may be time sync, a VM resumed from a saved state or snapshot, or a manual change\n";
        }
    }
    out << "\n";

    // Processes created while the clock was shifted
    out << "== Processes created while the clock differed from the reference ==\n";
    bool anyShifted = false;
    for (size_t s = 0; s < a.segments.size(); ++s) {
        if (!a.SegmentShifted(s)) continue;
        anyShifted = true;
        const Segment& seg = a.segments[s];
        const int64_t shift = seg.offset - a.referenceOffset;
        out << "  Segment " << s + 1 << ": the clock was " << FormatDuration(shift) << (shift < 0 ? " BEHIND" : " AHEAD")
            << " - " << seg.Count() << " running process" << (seg.Count() == 1 ? "" : "es") << "\n";
        const auto range = a.SequenceRange(s);
        if (range.first) {
            const unsigned long long started = range.second - range.first + 1;
            if (started > seg.Count()) {
                out << "  ~" << started << " processes were started between the first and last of these (seq "
                    << range.first << "-" << range.second << "); " << started - seg.Count()
                    << " have already exited.\n";
            }
        }
        out << Format("  %-8s %-7s %-19s  %-19s  %-18s %s\n", "Seq", "PID", "Recorded creation", "Real creation",
                      "Shift", "Process");
        size_t printed = 0;
        for (size_t i = seg.first; i <= seg.last; ++i) {
            if (!ro.listAll && printed == ro.maxProcessesPerSegment) {
                out << "  ... " << seg.Count() - printed << " more (use --all or --csv)\n";
                break;
            }
            ++printed;
            const ProcessRecord& p = a.processes[i];
            out << Format("  %-8llu %-7u %-19s  %-19s  %-18s %s\n", static_cast<unsigned long long>(p.sequence), p.pid,
                          FormatFileTime(static_cast<int64_t>(p.createTime)).c_str(),
                          FormatFileTime(a.RealCreateTime(i)).c_str(), FormatDuration(a.shifts[i], true).c_str(),
                          p.name.c_str());
            out << "          parent: " << DescribeParent(a, i, byPid);
            if (!p.user.empty()) out << "   user: " << p.user;
            out << "\n";
            if (!p.imagePath.empty()) out << "          path  : " << p.imagePath << "\n";
            if (!p.commandLine.empty()) {
                out << "          cmd   : " << Truncate(p.commandLine, ro.listAll ? 0 : ro.maxCommandLine) << "\n";
            }
        }
        out << "\n";
    }
    if (!anyShifted) out << "  None.\n\n";

    if (ro.listAll) {
        out << "== All analyzed processes (creation order) ==\n";
        out << Format("  %-8s %-7s %-4s %-19s  %-18s %s\n", "Seq", "PID", "Seg", "Recorded creation", "Shift", "Process");
        for (size_t i = 0; i < a.processes.size(); ++i) {
            const ProcessRecord& p = a.processes[i];
            out << Format("  %-8llu %-7u %-4zu %-19s  %-18s %s\n", static_cast<unsigned long long>(p.sequence), p.pid,
                          a.segmentOf[i] + 1, FormatFileTime(static_cast<int64_t>(p.createTime)).c_str(),
                          FormatDuration(a.shifts[i], true).c_str(), p.name.c_str());
        }
        if (!info.unreadable.empty()) {
            out << "\n  Could not be read:\n";
            for (const auto& u : info.unreadable) out << "    " << u << "\n";
        }
        out << "\n";
    }

    // Result
    out << "== Result ==\n";
    if (a.steps.empty()) {
        out << "No clock changes detected during this boot (" << a.processes.size() << " running processes checked).\n";
        return;
    }
    out << "CLOCK CHANGES DETECTED: " << a.CountSteps(true) << " backward, " << a.CountSteps(false) << " forward.";
    const int64_t drift = a.nowOffset - a.bootOffset;  // current clock minus the clock at boot
    if (AbsTicks(drift) <= a.options.thresholdTicks) {
        out << " " << a.ShiftedProcessCount() << " running process" << (a.ShiftedProcessCount() == 1 ? " was" : "es were")
            << " created while the clock differed from " << refName << ".\n";
    } else {
        // The clock is still off: which processes ran on a wrong clock depends on which clock is right.
        auto count = [](size_t n) {
            if (n == 0) return std::string("no running process was created on a wrong clock");
            return Format("%zu running process%s created on a wrong clock", n, n == 1 ? " was" : "es were");
        };
        out << "\nThe current clock is " << FormatDuration(drift) << (drift < 0 ? " behind" : " ahead of")
            << " the clock at boot, so one of them is wrong. Compare with a trusted clock:\n"
            << "  If the current clock is right : " << count(a.ShiftedCountRelativeTo(a.nowOffset))
            << (refIsNow ? " (this report)" : " (see --reference now)") << "\n"
            << "  If the clock at boot was right: " << count(a.ShiftedCountRelativeTo(a.bootOffset))
            << (refIsNow ? " (see --reference boot)" : " (this report)") << "\n";
    }
    for (size_t k = 0; k < a.steps.size(); ++k) {
        const ClockStep& st = a.steps[k];
        if (st.pairedWith > static_cast<int>(k)) {
            out << "Pattern: clock set " << (st.delta < 0 ? "back" : "forward") << " by " << FormatDuration(st.delta)
                << " and later restored (changes [" << k + 1 << "] and [" << st.pairedWith + 1 << "]).\n";
        }
    }
}

inline std::string CsvField(const std::string& s) {
    if (s.find_first_of(",\"\r\n") == std::string::npos) return s;
    std::string quoted = "\"";
    for (char c : s) quoted += (c == '"') ? std::string("\"\"") : std::string(1, c);
    return quoted + "\"";
}

inline void WriteCsv(std::ostream& out, const Analysis& a) {
    out << "sequence,pid,parent_pid,session_id,segment,uptime_at_creation_s,recorded_creation_utc,real_creation_utc,"
           "apparent_boot_utc,shift_seconds,shifted,name,user,image_path,command_line\n";
    for (size_t i = 0; i < a.processes.size(); ++i) {
        const ProcessRecord& p = a.processes[i];
        out << p.sequence << ',' << p.pid << ',' << p.parentPid << ',' << p.sessionId << ',' << a.segmentOf[i] + 1
            << ',' << FormatExactSeconds(p.createInterruptTime) << ',' << FormatFileTime(static_cast<int64_t>(p.createTime)) << ',' << FormatFileTime(a.RealCreateTime(i))
            << ',' << FormatFileTime(a.offsets[i]) << ',' << Format("%.3f", static_cast<double>(a.shifts[i]) / kTicksPerSecond)
            << ',' << (a.IsShifted(i) ? "yes" : "no") << ',' << CsvField(p.name) << ',' << CsvField(p.user) << ','
            << CsvField(p.imagePath) << ',' << CsvField(p.commandLine) << '\n';
    }
}

}  // namespace procclock
