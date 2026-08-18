<#
.SYNOPSIS
    Real-time Windows process-creation feed for SigmaForge.

.DESCRIPTION
    Emits one compact JSON object per newly created process to stdout
    (NDJSON), shaped into the Sysmon Event ID 1 field names SigmaForge rules
    and the Tier 1 evaluator already expect: Image, CommandLine, ParentImage,
    ParentCommandLine, ProcessId, ParentProcessId.

    Detection method: snapshot diffing. Every poll the script reads the whole
    Win32_Process table in ONE projected WMI query and emits any PID not seen
    in the previous poll. Command line and parent are resolved from that same
    snapshot, so a poll costs exactly one WMI round-trip no matter how many
    processes started -- which matters because WMI latency is the bottleneck.
    (An earlier design that did per-new-process WMI lookups compounded that
    latency and missed bursts; a single whole-table query is more robust.)

    This is live kernel-sourced telemetry, not a log replay. It needs no
    Sysmon install and no administrator rights. Command line and image path
    are populated for processes the current user can open; system or
    other-user processes may report partial data, exactly as a real SIEM
    would see them.

    Honest limitation: a polling feed cannot observe a process that starts
    AND exits within one interval (a ~50ms `whoami` between two polls can
    slip through). Production deployments feed SigmaForge from Sysmon's ETW
    stream, which is push-based and has no such gap. The evaluator and rules
    are identical either way; only the event source changes.

    The Python collector (sigmaforge/collect.py) spawns this script and reads
    its stdout. Run it directly to watch the raw feed.

.PARAMETER IntervalMs
    Poll interval in milliseconds. Default 250. Lower catches shorter-lived
    processes at the cost of more CPU.

.PARAMETER OutFile
    If set, NDJSON is written to this file (UTF-8, no BOM, auto-flushed,
    append) instead of stdout. The Python collector uses this and tails the
    file, which is more reliable than reading the PowerShell stdout pipe.
#>

param(
    [int]$IntervalMs = 250,
    [string]$OutFile = ''
)

# Continue, not Stop: a transient hiccup or a suspend/resume must not tear
# down the loop. The poll body is wrapped in try/catch and expresses every
# skip as a positive `if` -- `continue`/`break` inside a try do not behave
# like normal loop control in PowerShell and can abort a poll early.
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Write through an explicit auto-flushing StreamWriter. UTF-8 without a BOM
# so no stray bytes prefix the first line. When -OutFile is given we append
# to that file (the collector tails it); otherwise we write to the raw
# stdout stream. AutoFlush pushes each line out the instant it is written,
# which a live reader needs -- the default stdout writer buffers on a pipe.
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
if ($OutFile) {
    $Stdout = New-Object System.IO.StreamWriter($OutFile, $true, $Utf8NoBom)
} else {
    $Stdout = New-Object System.IO.StreamWriter(
        [Console]::OpenStandardOutput(), $Utf8NoBom)
}
$Stdout.AutoFlush = $true

# Pull only the fields the rules need, in one query for the whole table.
$wql = 'SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine ' +
       'FROM Win32_Process'

function Get-Snapshot {
    return @(Get-CimInstance -Query $wql -ErrorAction SilentlyContinue)
}

# Prime the baseline so processes already running are not reported as new.
$seen = @{}
foreach ($p in Get-Snapshot) { $seen[[int]$p.ProcessId] = $true }
[Console]::Error.WriteLine(
    "[feed] baseline $($seen.Count) processes; polling every ${IntervalMs}ms")

$polls = 0
while ($true) {
  try {
    Start-Sleep -Milliseconds $IntervalMs

    $current = Get-Snapshot
    if ($current.Count -gt 0) {
        $polls++

        # Index this snapshot by PID for free parent resolution.
        $byPid = @{}
        foreach ($p in $current) { $byPid[[int]$p.ProcessId] = $p }

        foreach ($p in $current) {
            $procId = [int]$p.ProcessId
            if (-not $seen.ContainsKey($procId)) {
                $parent = $byPid[[int]$p.ParentProcessId]

                $record = [ordered]@{
                    UtcTime           = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss.fff')
                    EventID           = 1
                    Image             = $p.ExecutablePath
                    OriginalFileName  = $p.Name
                    CommandLine       = $p.CommandLine
                    ProcessId         = $procId
                    ParentProcessId   = [int]$p.ParentProcessId
                    ParentImage       = if ($parent) { $parent.ExecutablePath } else { $null }
                    ParentCommandLine = if ($parent) { $parent.CommandLine } else { $null }
                }

                $json = ($record | ConvertTo-Json -Compress -Depth 3)
                $Stdout.WriteLine($json)
            }
        }

        # A PID that has exited drops out of $seen, so later reuse of that
        # PID is correctly treated as new.
        $next = @{}
        foreach ($p in $current) { $next[[int]$p.ProcessId] = $true }
        $seen = $next

        if (($polls % 40) -eq 0) {
            [Console]::Error.WriteLine("[feed] alive, $($current.Count) processes")
        }
    }
  } catch {
    [Console]::Error.WriteLine("[feed] poll error (continuing): $($_.Exception.Message)")
  }
}
