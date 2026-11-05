# ProcClock

ProcClock detects changes to the Windows system clock by checking the creation timestamps of running processes. It also shows **which processes were started while the clock was wrong**. For each one, it lists the name, PID, parent, user, image path, command line, the recorded (shifted) creation time, and the real one.

## How it works

When a process is created, Windows records two timestamps for it. `NtQueryInformationProcess` returns both in [`PROCESS_TELEMETRY_ID_INFORMATION`](https://learn.microsoft.com/en-us/windows/win32/devnotes/process_telemetry_id_information_type) (info class `ProcessTelemetryIdInformation` = 64):

| Field | Clock | Changed by setting the clock? |
|---|---|---|
| `CreateTime` | Wall clock (FILETIME, UTC) | Yes |
| `CreateInterruptTime` | 100 ns ticks since boot | No: the interrupt-time count "is not subject to adjustments by users or the Windows time service" |

For each process, `CreateTime - CreateInterruptTime` gives the boot time *according to the clock when that process started*. If nobody changes the clock, this value is the same for every process. A clock change shifts it for every process created after the change:

```text
creation order (uptime) ───────────────────────────────────────────────────────────────►
process          System … svchost │ powershell  conhost  report_tool │ backgroundTaskHost … ProcClock
apparent boot    08:00:00         │ 3 days 2 hours earlier          │ 08:00:00
                                  ▲ clock set back                  ▲ clock restored
```

ProcClock works in five steps:

1. Reads both timestamps for every running process, along with `ProcessSequenceNumber`, the user SID, the image path, and the command line.
2. Sorts the processes by `CreateInterruptTime`. This gives the true creation order, whatever the wall clock said.
3. Splits the timeline wherever the apparent boot time jumps by more than the threshold. The default is 60 s, which skips normal time-sync corrections. Each jump is a clock change, placed between the last process created before it and the first one created after it.
4. Compares each segment with a reference clock (the current clock by default, or the clock at boot). It then lists the processes in shifted segments with their **real** creation time: reference boot time + `CreateInterruptTime`.
5. Uses gaps in `ProcessSequenceNumber` to estimate how many processes started during a window and have already exited.

It also checks the current clock: if the clock is wrong right now, the gap between "now" and the boot-time processes reveals it, even if no process from that window is still running.

## Example output 

```text
ProcClock 0.1.3 - detects system clock changes from process creation times
https://github.com/santiagolin/ProcClock

Current system time : 2026-11-05 21:00:10 UTC   <- compare with a trusted clock
Boot time           : 2026-11-05 16:00:30 UTC   (uptime 4h 59m 40s, boot ID 926)
Processes analyzed  : 181 of 181 running
Threshold           : 1m 00s
Reference clock     : the current system clock

== Clock timeline (creation order; times per reference clock) ==
  Seg  Clock vs ref        Procs  Sequence          First created (UTC)  Last created (UTC)
  1    0s                    174  1-2236            2026-11-05 16:00:30  2026-11-05 20:59:30
  2    -1h 00m 00s             3  2237-2240         2026-11-05 20:59:43  2026-11-05 20:59:47  <== shifted
  3    0s                      4  2246-2249         2026-11-05 21:00:06  2026-11-05 21:00:06

== Clock changes ==
  [1] SUSPICIOUS Clock set BACK by 1h 00m 00s
      When   : between 2026-11-05 20:59:30 and 2026-11-05 20:59:43 UTC (uptime 4h 59m 00s to 4h 59m 13s)
      Before : chrome.exe (PID 13080, seq 2236)
      After  : SearchProtocolHost.exe (PID 13252, seq 2237)
      Undone : by change [2]; the clock stayed behind for 4s to 37s
  [2] SUSPICIOUS Clock set FORWARD by 1h 00m 00s
      When   : between 2026-11-05 20:59:47 and 2026-11-05 21:00:06 UTC (uptime 4h 59m 17s to 4h 59m 36s)
      Before : notepad.exe (PID 4020, seq 2240)
      After  : updater.exe (PID 12588, seq 2246)
      Undoes : change [1]

== Processes created while the clock differed from the reference ==
  Segment 2: the clock was 1h 00m 00s BEHIND - 3 running processes
  ~4 processes were started between the first and last of these (seq 2237-2240); 1 have already exited.
  Seq      PID     Recorded creation    Real creation        Shift              Process
  2237     13252   2026-11-05 19:59:43  2026-11-05 20:59:43  -1h 00m 00s        SearchProtocolHost.exe
          parent: SearchIndexer.exe (PID 5940)   user: DESKTOP-RNGJ9O0\User
          path  : C:\Windows\System32\SearchProtocolHost.exe
          cmd   : "C:\Windows\system32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe_S-1-5-21-949084117-1655274599-2283201091-100132_ Global\UsGthrCtrlFltPipeMssGthrPip...
  2238     13280   2026-11-05 19:59:43  2026-11-05 20:59:43  -1h 00m 00s        SearchFilterHost.exe
          parent: SearchIndexer.exe (PID 5940)   user: NT AUTHORITY\SYSTEM
          path  : C:\Windows\System32\SearchFilterHost.exe
          cmd   : "C:\Windows\system32\SearchFilterHost.exe" 0 868 872 880 8192 876 852
  2240     4020    2026-11-05 19:59:47  2026-11-05 20:59:47  -1h 00m 00s        notepad.exe
          parent: powershell.exe (PID 10448)   user: DESKTOP-RNGJ9O0\User
          path  : C:\Windows\System32\notepad.exe
          cmd   : "C:\Windows\system32\notepad.exe"

== Result ==
CLOCK CHANGES DETECTED: 1 backward, 1 forward. 3 running processes were created while the clock differed from the current system clock.
Pattern: clock set back by 1h 00m 00s and later restored (changes [1] and [2]).
```

## Build

**Visual Studio** (Developer Command Prompt):

```bat
cl /nologo /O2 /EHsc /std:c++17 /utf-8 /W4 /MT ProcClock.cpp
```

**CMake:**

```sh
cmake -B build
cmake --build build --config Release
cd build && ctest -C Release
```

**MinGW-w64 or Zig** (cross-compiling from Linux or macOS works too):

```sh
x86_64-w64-mingw32-g++ -std=c++17 -O2 -static ProcClock.cpp -o ProcClock.exe -ladvapi32 -lshell32
zig c++ -target x86_64-windows-gnu -std=c++17 -O2 ProcClock.cpp -o ProcClock.exe -ladvapi32 -lshell32
```

**Tests** (any OS, no Windows needed):

```sh
g++ -std=c++17 -O2 tests/ClockAnalysisTests.cpp -o tests/run
./tests/run            # unit tests plus randomized tampering simulations
./tests/run --sample   # prints the example report above
```

## Usage

Run it from an elevated prompt. You can also double-click it; the window pauses before closing.

```text
ProcClock.exe [--threshold <seconds>] [--reference now|boot] [--all] [--csv <file>]
```

| Option | Meaning |
|---|---|
| `--threshold <s>` | Ignore clock jumps up to this many seconds (default `60`) |
| `--reference now` | Calculate real creation times from the current clock (default) |
| `--reference boot` | Use the clock as it was at boot instead, if the current clock is the wrong one |
| `--all` | List every process and print full command lines |
| `--csv <file>` | Export every analyzed process to CSV (`sequence, pid, parent_pid, session_id, segment, uptime_at_creation_s, recorded_creation_utc, real_creation_utc, apparent_boot_utc, shift_seconds, shifted, name, user, image_path, command_line`). `uptime_at_creation_s` is the exact interrupt time, at 100 ns resolution. |

Exit codes: `0` means no clock change was found, `2` means a clock change was detected, and `1` means an error occurred.

### Reading the results

| Label | Meaning |
|---|---|
| `SUSPICIOUS` | The clock was set back, or it was changed and later restored (two opposite jumps of similar size). |
| `CHECK` | The clock was set back within 10 minutes of boot, with no matching restore. This is often the time service correcting the hardware clock after boot, which is common on dual-boot machines. |
| `INFO` | The clock jumped forward with no matching backward jump. This is usually harmless, for example time sync after a slow hardware clock or a VM resumed from a saved state or snapshot. It can also be a manual change. |

**Sequence warnings.** Sequence numbers normally increase in creation order. Processes started at the same moment on different CPUs can swap places, so ProcClock ignores swaps less than 1 s apart; `--all` lists them as notes. A larger disagreement is reported as a `WARNING` that names both processes. It doesn't affect clock-change detection. The System process (PID 4) is exempt. Windows gives it sequence number 1 at the start of boot but records its creation time 4.2 s after the Registry process (sequence number 2).

Every report starts with the current system time. Compare it with a trusted clock. If the current clock disagrees with the clock at boot, ProcClock prints a note. The result then gives both possibilities: how many processes ran on a wrong clock if the current clock is right, and how many if the clock at boot was right. Choose the matching view with `--reference`. ProcClock leaves its own process out of the analysis.

## Validating on Windows

Run this checklist on a test machine or VM. Use an elevated PowerShell prompt.

1. **Baseline.** Run `.\ProcClock.exe` on a machine where nobody has changed the clock. Expect `No clock changes detected` (exit code 0). Anything found at an uptime of a few seconds is an early-boot artifact worth investigating.
2. **Roll back, then restore:**

   ```powershell
   Set-Date -Adjust (New-TimeSpan -Hours -1)   # set the clock back 1 hour
   Start-Process notepad                       # created while the clock is wrong; leave it open
   Set-Date -Adjust (New-TimeSpan -Hours 1)    # restore (or: w32tm /resync)
   .\ProcClock.exe
   ```

   Expect two `SUSPICIOUS` changes (back 1 h, forward 1 h). Notepad should be listed with a shift of `-1h 00m 00s` and its real start time. `Set-Date` runs inside PowerShell, so it doesn't start a process of its own. *Confirmed on a real machine with v0.1. Each change was placed between the two processes created around it, and both windows contained the actual `Set-Date` times.*
3. **Roll back without restoring.** Set the clock back and run ProcClock right away. Expect a `SUSPICIOUS` backward change and a note that the current clock differs from the boot clock. The result should give both possibilities. By default, nearly every process looks shifted, because ProcClock is measuring against the current (wrong) clock; `--reference boot` lists only the processes started after the change. Restore the clock afterward. *Confirmed on a real machine with v0.1.2.*
4. **Sleep or hibernate.** Resume the machine and run ProcClock. Expect no changes. The interrupt time should keep counting through sleep (the *unbiased* interrupt time is the one that stops).
5. **Not elevated.** Run ProcClock as a standard user. Expect a warning and partial results.

## Limitations

- **Only the current boot and only running processes.** A process's record disappears when it exits. A change that was later undone is detected only if some process created during that window is still running. If someone changes the clock, does something, restores the clock, and closes everything they started, ProcClock finds nothing. TimeChangeDetect may still catch it.
- **Imprecise timing.** A change is placed between surviving processes. On a quiet machine, the "When" window can be wide.
- **Threshold.** Jumps up to 60 s are ignored by default. Lowering `--threshold` may surface normal time-sync corrections.
- **Visibility.** It needs Administrator rights to read every process, and a few protected processes may still be unreadable (they're listed with `--all`).
- **Requirements.** Windows 10 or later is required for `ProcessTelemetryIdInformation`.

## ProcClock and TimeChangeDetect

The two tools use independent evidence, so they work best together:

| | [TimeChangeDetect](https://github.com/santiagolin/TimeChangeDetect) | ProcClock |
|---|---|---|
| Evidence | NTFS USN journal records | Creation timestamps of running processes |
| Covers | File activity since the journal started, which can span many boots | The current boot, while the processes run |
| Lost when | The journal wraps or is deleted (`fsutil usn deletejournal`) | The processes exit, or the machine reboots |
| Shows | That the clock jumped, and roughly when | When, plus **which processes ran on the wrong clock** (user, command line, real start time) |

## Files

| File | Purpose |
|---|---|
| `ProcClock.cpp` | Windows collector: lists processes, reads their telemetry and clocks, and prints the report |
| `ClockAnalysis.h` | Platform-independent, header-only analysis, report, and CSV export |
| `tests/ClockAnalysisTests.cpp` | Tests on simulated machines, plus the `--sample` report |
| `CMakeLists.txt` | Windows exe and cross-platform tests |
