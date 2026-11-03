// Unit tests for ClockAnalysis.h. They run on any OS:
//   g++ -std=c++17 -O2 -Wall -Wextra tests/ClockAnalysisTests.cpp -o tests/run && tests/run
// `tests/run --sample` prints an example report from a simulated machine.
#include "../ClockAnalysis.h"

#include <cstring>
#include <iostream>
#include <random>
#include <sstream>

using namespace procclock;

static int g_checks = 0, g_failures = 0;
#define CHECK(cond)                                                                         \
    do {                                                                                    \
        ++g_checks;                                                                         \
        if (!(cond)) {                                                                      \
            ++g_failures;                                                                   \
            std::cerr << __FILE__ << ":" << __LINE__ << ": CHECK failed: " #cond "\n";      \
        }                                                                                   \
    } while (0)

// A simulated Windows machine: a true clock, an interrupt clock (time since boot) and a system
// clock that someone can change.
struct Machine {
    uint64_t bootTrueTime = FileTimeFromUtc(2025, 3, 14, 8, 0, 0);
    int64_t clockError = 0;  // system clock minus true time
    uint64_t uptime = 0;     // interrupt time
    uint64_t nextSequence = 4;
    uint32_t nextPid = 4;
    std::vector<ProcessRecord> running;
    std::vector<int64_t> trueCreation;  // ground truth per running process
    std::vector<int64_t> errorAtCreation;

    void Advance(int64_t ticks) { uptime += static_cast<uint64_t>(ticks); }
    void ChangeClock(int64_t delta) { clockError += delta; }
    uint64_t SystemNow() const { return static_cast<uint64_t>(static_cast<int64_t>(bootTrueTime + uptime) + clockError); }

    uint32_t Start(const std::string& name, uint32_t parent = 0, const std::string& user = "NT AUTHORITY\\SYSTEM",
                   const std::string& commandLine = "", int64_t jitter = 0) {
        ProcessRecord p;
        p.pid = nextPid;
        nextPid += 4;
        p.parentPid = parent;
        p.sequence = nextSequence++;
        p.createInterruptTime = uptime;
        p.createTime = static_cast<uint64_t>(static_cast<int64_t>(SystemNow()) + jitter);
        const bool fullPath = name.find('\\') != std::string::npos;
        p.imagePath = fullPath ? name : "C:\\Windows\\System32\\" + name;
        p.name = fullPath ? name.substr(name.find_last_of('\\') + 1) : name;
        p.user = user;
        p.commandLine = commandLine.empty() ? "\"" + p.imagePath + "\"" : commandLine;
        running.push_back(p);
        trueCreation.push_back(static_cast<int64_t>(bootTrueTime + uptime));
        errorAtCreation.push_back(clockError);
        return p.pid;
    }
    void StartShortLived(int count) {  // processes that already exited only consume sequence numbers
        nextSequence += static_cast<uint64_t>(count);
        nextPid += 4 * static_cast<uint32_t>(count);
    }
    Analysis Run(Options options = Options{}) const { return Analyze(running, SystemNow(), uptime, options); }
};

static size_t IndexOf(const Analysis& a, const std::string& name) {
    for (size_t i = 0; i < a.processes.size(); ++i)
        if (a.processes[i].name == name) return i;
    return a.processes.size();
}

static void Boot(Machine& m, int services = 20) {
    m.Start("System");
    m.Advance(2 * kTicksPerSecond);
    for (const char* name : {"smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe"}) {
        m.Start(name, 4);
        m.Advance(kTicksPerSecond / 2);
    }
    for (int i = 0; i < services; ++i) {
        m.Start("svchost.exe", 16);
        m.Advance(kTicksPerSecond / 4);
    }
}

static void TestFormatting() {
    CHECK(FormatFileTime(0) == "1601-01-01 00:00:00");
    CHECK(FormatFileTime(static_cast<int64_t>(FileTimeFromUtc(2025, 3, 14, 8, 0, 0))) == "2025-03-14 08:00:00");
    CHECK(FormatFileTime(static_cast<int64_t>(FileTimeFromUtc(2024, 2, 29, 23, 59, 59))) == "2024-02-29 23:59:59");
    CHECK(FormatFileTime(static_cast<int64_t>(FileTimeFromUtc(1969, 12, 31, 12, 0, 0))) == "1969-12-31 12:00:00");
    CHECK(FileTimeFromUtc(1970, 1, 1, 0, 0, 0) == 116444736000000000ULL);  // well-known FILETIME of the Unix epoch
    CHECK(FormatDuration(-kTicksPerHour, true) == "-1h 00m 00s");
    CHECK(FormatDuration(90 * kTicksPerSecond) == "1m 30s");
    CHECK(FormatDuration(0, true) == "0s");
    CHECK(FormatDuration(42 * kTicksPerSecond, true) == "+42s");
    CHECK(FormatDuration(kTicksPerDay + 2 * kTicksPerHour + 3 * kTicksPerMinute + 4 * kTicksPerSecond) == "1d 02h 03m 04s");
    CHECK(CsvField("a,b") == "\"a,b\"");
    CHECK(CsvField("say \"hi\"") == "\"say \"\"hi\"\"\"");
    CHECK(CsvField("plain") == "plain");
    CHECK(FormatSeconds(5 * kTicksPerSecond) == "5.000s");
    CHECK(FormatSeconds(33333) == "0.003s");
    CHECK(FormatSeconds(-kTicksPerSecond / 2) == "-0.500s");
    CHECK(FormatExactSeconds(0) == "0.0000000");
    CHECK(FormatExactSeconds(12 * kTicksPerSecond + 345) == "12.0000345");
}

static void TestNoChange() {
    Machine m;
    Boot(m);
    std::mt19937 rng(1);
    std::uniform_int_distribution<int64_t> jitter(-kTicksPerSecond / 2, kTicksPerSecond / 2);  // time-sync noise
    for (int i = 0; i < 200; ++i) {
        m.Advance(3 * kTicksPerMinute);
        m.Start("RuntimeBroker.exe", 900, "DESKTOP\\bob", "", jitter(rng));
    }
    const Analysis a = m.Run();
    CHECK(a.segments.size() == 1);
    CHECK(a.steps.empty());
    CHECK(a.ShiftedProcessCount() == 0);
    CHECK(a.inversions.empty());
}

static void TestSmallTimeSyncCorrectionIgnored() {
    Machine m;
    Boot(m);
    m.Advance(kTicksPerHour);
    m.ChangeClock(15 * kTicksPerSecond);  // w32time stepping the clock by 15 s
    m.Start("taskhostw.exe");
    const Analysis a = m.Run();
    CHECK(a.steps.empty());
    CHECK(a.ShiftedProcessCount() == 0);
}

static void TestRollbackAndRestore() {
    Machine m;
    Boot(m);
    const uint32_t explorer = m.Start("explorer.exe", 600, "DESKTOP\\bob");
    m.Advance(5 * kTicksPerHour);
    m.Start("svchost.exe", 16);

    m.ChangeClock(-kTicksPerHour);  // Set-Date -Adjust -1:00
    m.Advance(10 * kTicksPerSecond);
    const uint32_t cmd = m.Start("cmd.exe", explorer, "DESKTOP\\bob");
    m.Start("conhost.exe", cmd, "DESKTOP\\bob");
    m.StartShortLived(40);
    m.Advance(20 * kTicksPerMinute);
    m.Start("C:\\Users\\bob\\Downloads\\tool.exe", cmd, "DESKTOP\\bob");
    m.Advance(25 * kTicksPerMinute);

    m.ChangeClock(kTicksPerHour);  // restored
    m.Advance(30 * kTicksPerSecond);
    m.Start("svchost.exe", 16);
    m.Advance(kTicksPerHour);
    m.Start("WmiPrvSE.exe", 16);

    const Analysis a = m.Run();
    CHECK(a.segments.size() == 3);
    CHECK(a.steps.size() == 2);
    if (a.steps.size() == 2) {
        CHECK(a.steps[0].delta == -kTicksPerHour);
        CHECK(a.steps[1].delta == kTicksPerHour);
        CHECK(a.steps[0].pairedWith == 1 && a.steps[1].pairedWith == 0);
        CHECK(a.steps[0].severity == Severity::Suspicious);
        CHECK(a.steps[1].severity == Severity::Suspicious);
        // The window lasted ~45 minutes; the reported bounds must contain it.
        const int64_t minDuration = static_cast<int64_t>(a.steps[1].notBefore) - static_cast<int64_t>(a.steps[0].notAfter);
        const int64_t maxDuration = static_cast<int64_t>(a.steps[1].notAfter) - static_cast<int64_t>(a.steps[0].notBefore);
        CHECK(minDuration <= 45 * kTicksPerMinute && 45 * kTicksPerMinute <= maxDuration);
    }
    CHECK(a.ShiftedProcessCount() == 3);
    for (const char* name : {"cmd.exe", "conhost.exe", "tool.exe"}) {
        const size_t i = IndexOf(a, name);
        CHECK(i < a.processes.size());
        if (i < a.processes.size()) {
            CHECK(a.IsShifted(i));
            CHECK(a.shifts[i] == -kTicksPerHour);
        }
    }
    // With the clock restored, "real" creation times recover the true times for every process.
    for (size_t i = 0; i < a.processes.size(); ++i) {
        for (size_t k = 0; k < m.running.size(); ++k) {
            if (m.running[k].sequence == a.processes[i].sequence) CHECK(a.RealCreateTime(i) == m.trueCreation[k]);
        }
    }
    std::ostringstream report;
    PrintReport(report, a, CollectionInfo{}, ReportOptions{});
    const std::string text = report.str();
    CHECK(text.find("CLOCK CHANGES DETECTED: 1 backward, 1 forward") != std::string::npos);
    CHECK(text.find("~43 processes were started") != std::string::npos);  // cmd, conhost, 40 short-lived, tool
    CHECK(text.find("and later restored") != std::string::npos);
    CHECK(text.find("one of them is wrong") == std::string::npos);  // restored: both clocks agree
}

static void TestRollbackNotRestored() {
    Machine m;
    Boot(m);
    m.Advance(3 * kTicksPerHour);
    m.ChangeClock(-2 * kTicksPerHour);
    m.Advance(kTicksPerMinute);
    m.Start("cmd.exe");
    m.Advance(kTicksPerMinute);
    m.Start("notepad.exe");

    const Analysis a = m.Run();
    CHECK(a.steps.size() == 1);
    if (!a.steps.empty()) {
        CHECK(a.steps[0].delta == -2 * kTicksPerHour);
        CHECK(a.steps[0].pairedWith == -1);
        CHECK(a.steps[0].severity == Severity::Suspicious);
    }
    // Relative to the (still wrong) current clock, the boot processes look shifted...
    CHECK(a.ShiftedProcessCount() == a.processes.size() - 2);
    // ...relative to the clock at boot, the two processes started after the change are the shifted ones.
    Options boot;
    boot.reference = Reference::Boot;
    const Analysis b = m.Run(boot);
    CHECK(b.ShiftedProcessCount() == 2);
    CHECK(b.IsShifted(IndexOf(b, "cmd.exe")) && b.IsShifted(IndexOf(b, "notepad.exe")));

    // The result spells out both possibilities, since the current clock is still off.
    std::ostringstream now, atBoot;
    PrintReport(now, a, CollectionInfo{}, ReportOptions{});
    PrintReport(atBoot, b, CollectionInfo{}, ReportOptions{});
    const std::string olderCount = Format("%zu running processes were created", a.processes.size() - 2);
    CHECK(now.str().find("The current clock is 2h 00m 00s behind the clock at boot, so one of them is wrong") !=
          std::string::npos);
    CHECK(now.str().find("If the current clock is right : " + olderCount + " on a wrong clock (this report)") !=
          std::string::npos);
    CHECK(now.str().find("If the clock at boot was right: 2 running processes were created on a wrong clock (see "
                         "--reference boot)") != std::string::npos);
    CHECK(atBoot.str().find("If the current clock is right : " + olderCount + " on a wrong clock (see --reference now)") !=
          std::string::npos);
    CHECK(atBoot.str().find("If the clock at boot was right: 2 running processes were created on a wrong clock (this "
                            "report)") != std::string::npos);
}

static void TestChangeAfterNewestProcess() {
    Machine m;
    Boot(m);
    m.Advance(kTicksPerHour);
    m.ChangeClock(-30 * kTicksPerMinute);  // nothing started afterwards
    const Analysis a = m.Run();
    CHECK(a.steps.size() == 1);
    if (!a.steps.empty()) {
        CHECK(a.steps[0].after == a.processes.size());
        CHECK(a.steps[0].delta == -30 * kTicksPerMinute);
    }
}

static void TestForwardJumpIsInfo() {
    Machine m;
    Boot(m);
    m.Advance(2 * kTicksPerHour);
    m.ChangeClock(3 * kTicksPerHour);  // e.g. VM restored from a saved state: interrupt time did not advance
    m.Start("svchost.exe");
    const Analysis a = m.Run();
    CHECK(a.steps.size() == 1);
    if (!a.steps.empty()) {
        CHECK(a.steps[0].delta == 3 * kTicksPerHour);
        CHECK(a.steps[0].severity == Severity::Info);
    }
}

static void TestEarlyBootCorrections() {
    {   // hardware clock 5 minutes fast, corrected 30 s after boot
        Machine m;
        m.clockError = 5 * kTicksPerMinute;
        Boot(m, 4);
        m.Advance(30 * kTicksPerSecond);
        m.ChangeClock(-5 * kTicksPerMinute);
        m.Start("svchost.exe");
        const Analysis a = m.Run();
        CHECK(a.steps.size() == 1);
        if (!a.steps.empty()) CHECK(a.steps[0].severity == Severity::Check);
    }
    {   // dual boot: hardware clock 3 hours behind, corrected 40 s after boot
        Machine m;
        m.clockError = -3 * kTicksPerHour;
        Boot(m, 4);
        m.Advance(40 * kTicksPerSecond);
        m.ChangeClock(3 * kTicksPerHour);
        m.Start("svchost.exe");
        const Analysis a = m.Run();
        CHECK(a.steps.size() == 1);
        if (!a.steps.empty()) CHECK(a.steps[0].severity == Severity::Info);
    }
}

static void TestTwoWindows() {
    Machine m;
    Boot(m);
    for (int round = 0; round < 2; ++round) {
        m.Advance(kTicksPerHour);
        m.Start("svchost.exe");
        m.ChangeClock(-(round + 1) * kTicksPerDay);
        m.Advance(kTicksPerMinute);
        m.Start("cmd.exe");
        m.Advance(kTicksPerMinute);
        m.ChangeClock((round + 1) * kTicksPerDay);
        m.Advance(kTicksPerMinute);
        m.Start("svchost.exe");
    }
    const Analysis a = m.Run();
    CHECK(a.steps.size() == 4);
    if (a.steps.size() == 4) {
        CHECK(a.steps[0].pairedWith == 1 && a.steps[2].pairedWith == 3);
    }
    CHECK(a.ShiftedProcessCount() == 2);
}

static void TestEmptyAndInvalid() {
    const Analysis a = Analyze({}, FileTimeFromUtc(2025, 1, 1, 0, 0, 0), 1000, Options{});
    CHECK(a.processes.empty() && a.steps.empty() && a.segments.empty());
    std::ostringstream report;
    PrintReport(report, a, CollectionInfo{}, ReportOptions{});
    CHECK(report.str().find("No process could be analyzed") != std::string::npos);

    ProcessRecord noTime;
    noTime.pid = 8;
    const Analysis b = Analyze({noTime}, FileTimeFromUtc(2025, 1, 1, 0, 0, 0), 1000, Options{});
    CHECK(b.processes.empty());
}

static void TestCsv() {
    Machine m;
    Boot(m, 2);
    m.Start("cmd.exe", 4, "DESKTOP\\bob", "cmd.exe /c echo a,b \"c\"");
    const Analysis a = m.Run();
    std::ostringstream csv;
    WriteCsv(csv, a);
    const std::string text = csv.str();
    size_t lines = 0;
    for (char c : text) lines += (c == '\n') ? 1 : 0;
    CHECK(lines == a.processes.size() + 1);
    CHECK(text.find("\"cmd.exe /c echo a,b \"\"c\"\"\"") != std::string::npos);
    CHECK(text.find(",segment,uptime_at_creation_s,recorded_creation_utc,") != std::string::npos);
    CHECK(text.find(",1,0.0000000,2025-03-14 08:00:00,") != std::string::npos);  // System, created at uptime 0
}

// Sequence numbers normally follow creation order. Swaps between processes created at the same
// moment are normal and only listed with --all; larger disagreements are reported as warnings.
static void TestSequenceInversions() {
    Machine m;
    Boot(m);
    auto swapLastTwo = [&m] { std::swap(m.running[m.running.size() - 1].sequence, m.running[m.running.size() - 2].sequence); };
    m.Advance(kTicksPerMinute);
    m.Start("a.exe");
    m.Advance(33333);  // 3.3 ms later
    m.Start("b.exe");
    swapLastTwo();
    m.Advance(kTicksPerMinute);
    m.Start("c.exe");
    m.Advance(5 * kTicksPerSecond);
    m.Start("d.exe");
    swapLastTwo();
    const Analysis a = m.Run();
    CHECK(a.steps.empty());  // the clock analysis does not depend on sequence numbers
    CHECK(a.inversions.size() == 2);
    CHECK(a.SignificantInversions() == 1);
    if (a.inversions.size() == 2) {
        CHECK(a.processes[a.inversions[0].first].name == "a.exe");
        CHECK(a.processes[a.inversions[0].second].name == "b.exe");
        CHECK(a.processes[a.inversions[1].second].name == "d.exe");
        CHECK(a.inversions[1].gap == 5 * kTicksPerSecond);
    }
    std::ostringstream report;
    PrintReport(report, a, CollectionInfo{}, ReportOptions{});
    const std::string text = report.str();
    CHECK(text.find("WARNING: d.exe (PID") != std::string::npos);
    CHECK(text.find("was created 5.000s after c.exe (PID") != std::string::npos);
    CHECK(text.find("b.exe") == std::string::npos);  // the simultaneous swap stays quiet by default
    ReportOptions all;
    all.listAll = true;
    std::ostringstream full;
    PrintReport(full, a, CollectionInfo{}, all);
    CHECK(full.str().find("Note: b.exe (PID") != std::string::npos);
    CHECK(full.str().find("was created 0.003s after a.exe") != std::string::npos);
}

// On real machines the System process (PID 4) has the first sequence number, but Windows records its
// creation time seconds after that of the Registry process. That is not an anomaly.
static void TestSystemProcessStampedLate() {
    Machine m;
    m.Start("System");
    m.Advance(kTicksPerSecond / 2);
    m.Start("Registry", 4);
    m.Advance(kTicksPerSecond);
    m.Start("smss.exe", 4);
    m.Advance(4 * kTicksPerSecond);
    m.Start("csrss.exe", 4);
    m.running[0].createInterruptTime = m.running[1].createInterruptTime + 42050000;  // 4.205 s after Registry
    m.running[0].createTime = m.bootTrueTime + m.running[0].createInterruptTime;
    for (int i = 0; i < 5; ++i) {
        m.Advance(kTicksPerMinute);
        m.Start("svchost.exe", 600);
    }
    const Analysis a = m.Run();
    CHECK(a.inversions.empty());
    CHECK(a.steps.empty());
    CHECK(a.segments.size() == 1);
    CHECK(IndexOf(a, "System") == 2);           // sorted after Registry and smss.exe
    CHECK(a.SequenceRange(0).first == 4);       // System's sequence number still counts for the range
    std::ostringstream report;
    PrintReport(report, a, CollectionInfo{}, ReportOptions{});
    CHECK(report.str().find("WARNING") == std::string::npos);

    // Registry and smss.exe list System as their parent, although System's creation time is recorded
    // after theirs. Leave the clock wrong so the boot processes are listed (reference: now).
    m.Advance(kTicksPerHour);
    m.ChangeClock(-kTicksPerHour);
    m.Start("cmd.exe", 600);
    const Analysis c = m.Run();
    std::ostringstream listing;
    PrintReport(listing, c, CollectionInfo{}, ReportOptions{});
    CHECK(listing.str().find("parent: System (PID 4)") != std::string::npos);
    CHECK(listing.str().find("PID 4 (exited)") == std::string::npos);
    CHECK(listing.str().find("parent: none") != std::string::npos);  // System itself

    // A real disagreement on either side of System is still reported.
    Machine m2;
    m2.Start("System");
    m2.Advance(kTicksPerSecond);
    m2.Start("smss.exe", 4);
    m2.Advance(4 * kTicksPerSecond);
    m2.Start("csrss.exe", 4);
    std::swap(m2.running[1].sequence, m2.running[2].sequence);  // smss.exe now has the higher number
    m2.running[0].createInterruptTime = 3 * kTicksPerSecond;      // System recorded between the two
    m2.running[0].createTime = m2.bootTrueTime + m2.running[0].createInterruptTime;
    const Analysis b = m2.Run();
    CHECK(b.inversions.size() == 1);
    if (b.inversions.size() == 1) {
        CHECK(b.processes[b.inversions[0].first].name == "smss.exe");
        CHECK(b.processes[b.inversions[0].second].name == "csrss.exe");
        CHECK(b.inversions[0].gap == 4 * kTicksPerSecond);
    }
}

// Random tampering: with the clock correct at the end, every process gets its true creation time
// back, and exactly the processes created on a wrong clock are flagged.
static void TestRandomized() {
    std::mt19937_64 rng(12345);
    for (int run = 0; run < 300; ++run) {
        Machine m;
        Boot(m, 3);
        std::uniform_int_distribution<int> action(0, 9);
        std::uniform_int_distribution<int64_t> gap(1, 30 * kTicksPerMinute);
        std::uniform_int_distribution<int64_t> bigChange(2 * kTicksPerMinute, 30 * kTicksPerDay);
        for (int e = 0; e < 60; ++e) {
            const int act = action(rng);
            m.Advance(gap(rng));
            if (act < 6) m.Start("p.exe");
            else if (act < 8) m.StartShortLived(3);
            else if (m.clockError != 0 && act == 8) m.ChangeClock(-m.clockError);  // restore
            else m.ChangeClock(((rng() & 1) ? 1 : -1) * bigChange(rng));
        }
        m.ChangeClock(-m.clockError);  // the investigator verified that the current clock is right
        m.Advance(kTicksPerSecond);
        const Analysis a = m.Run();
        bool allRecovered = true, flagsCorrect = true;
        for (size_t i = 0; i < a.processes.size(); ++i) {
            for (size_t j = 0; j < m.running.size(); ++j) {
                if (m.running[j].sequence != a.processes[i].sequence) continue;
                allRecovered &= a.RealCreateTime(i) == m.trueCreation[j];
                flagsCorrect &= a.IsShifted(i) == (AbsTicks(m.errorAtCreation[j]) > a.options.thresholdTicks);
            }
        }
        CHECK(allRecovered);
        CHECK(flagsCorrect);
        // The jumps must add up to the total change between the oldest process and now.
        int64_t sum = 0;
        for (const auto& s : a.steps) sum += s.delta;
        CHECK(sum == a.nowOffset - a.offsets.front());
    }
}

static void PrintSample() {
    Machine m;
    Boot(m, 60);
    const uint32_t winlogon = m.Start("winlogon.exe", 520);
    m.Advance(40 * kTicksPerSecond);
    const uint32_t explorer = m.Start("explorer.exe", winlogon, "DESKTOP-7Q2K\\bob", "C:\\Windows\\Explorer.EXE");
    for (int i = 0; i < 30; ++i) {
        m.Advance(9 * kTicksPerMinute);
        const bool service = i % 3 != 0;
        m.Start(service ? "svchost.exe" : "RuntimeBroker.exe", service ? 680 : 812,
                service ? "NT AUTHORITY\\SYSTEM" : "DESKTOP-7Q2K\\bob");
    }
    m.Advance(kTicksPerHour / 2);
    m.Start("svchost.exe", 680);

    m.Advance(7 * kTicksPerMinute);
    m.ChangeClock(-(3 * kTicksPerDay + 2 * kTicksPerHour));  // set back so the work looks older
    m.Advance(12 * kTicksPerSecond);
    const uint32_t ps = m.Start("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", explorer,
                                "DESKTOP-7Q2K\\bob");
    m.Start("conhost.exe", ps, "DESKTOP-7Q2K\\bob", "\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1");
    m.StartShortLived(23);
    m.Advance(6 * kTicksPerMinute);
    m.Start("C:\\Users\\bob\\Desktop\\report_tool.exe", ps, "DESKTOP-7Q2K\\bob",
            "\"C:\\Users\\bob\\Desktop\\report_tool.exe\" --sign Q3_report.xlsx");
    m.StartShortLived(9);
    m.Advance(14 * kTicksPerMinute);
    m.ChangeClock(3 * kTicksPerDay + 2 * kTicksPerHour);  // restored
    m.Advance(25 * kTicksPerSecond);
    for (int i = 0; i < 8; ++i) {
        m.Advance(11 * kTicksPerMinute);
        m.Start(i % 2 ? "svchost.exe" : "backgroundTaskHost.exe", i % 2 ? 680 : 812);
    }
    const Analysis a = m.Run();
    CollectionInfo info;
    info.enumerated = a.processes.size() + 4;
    info.unreadable = {"Secure System (PID 140): access denied", "Registry (PID 184): access denied",
                       "Memory Compression (PID 2412): access denied", "MsMpEng.exe (PID 3900): access denied"};
    info.bootId = 57;
    std::cout << "ProcClock " << kVersion << " - detects system clock changes from process creation times\n"
                 "https://github.com/santiagolin/ProcClock\n\n";
    PrintReport(std::cout, a, info, ReportOptions{});
}

int main(int argc, char** argv) {
    if (argc > 1 && std::strcmp(argv[1], "--sample") == 0) {
        PrintSample();
        return 0;
    }
    TestFormatting();
    TestNoChange();
    TestSmallTimeSyncCorrectionIgnored();
    TestRollbackAndRestore();
    TestRollbackNotRestored();
    TestChangeAfterNewestProcess();
    TestForwardJumpIsInfo();
    TestEarlyBootCorrections();
    TestTwoWindows();
    TestEmptyAndInvalid();
    TestCsv();
    TestSequenceInversions();
    TestSystemProcessStampedLate();
    TestRandomized();
    std::cout << g_checks - g_failures << "/" << g_checks << " checks passed\n";
    return g_failures ? 1 : 0;
}
