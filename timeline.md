# Lab 71 Timeline – Suspicious Compression Investigation

| Time | Evidence Source | Activity | Assessment |
|---|---|---|---|
| 10-09-2026 06:40 | PowerShell / Filesystem | `C:\SuspiciousCompressionLab` created | Confirmed |
| 10-09-2026 06:40 | PowerShell / Filesystem | Lab directory verified | Confirmed |
| 10-09-2026 06:45 | PowerShell / Filesystem | `Source` directory created | Confirmed |
| 10-09-2026 06:49:47 | Filesystem | `employee-list.txt` created | Confirmed |
| 10-09-2026 06:49:47 | Filesystem | `project-notes.txt` created | Confirmed |
| 10-09-2026 06:49:47 | Filesystem | `sample-data.txt` created | Confirmed |
| 10-09-2026 06:49:47 | File metadata | Source file sizes recorded as 26, 26, and 24 bytes | Confirmed |
| 10-09-2026 | File hashing | SHA256 hashes collected for all three source files | Confirmed |
| 10-09-2026 07:10:30 | Filesystem | `staged-data.zip` created | Confirmed |
| 10-09-2026 07:10:30 | File metadata | Archive size recorded as 430 bytes | Confirmed |
| 10-09-2026 07:10:30 | File hashing | SHA256 collected for `staged-data.zip` | Confirmed |
| 10-09-2026 | Archive validation | ZIP archive extracted with `Expand-Archive` | Confirmed |
| 10-09-2026 | Archive validation | Three expected files recovered from archive | Confirmed |
| 10-09-2026 | Sysmon Event ID 1 | General process-creation telemetry reviewed | Confirmed telemetry availability |
| 10-09-2026 | Sysmon Event ID 1 | Targeted search for `Compress-Archive`, `powershell.exe`, and `staged-data.zip` returned multiple results | Supporting but limited |
| 10-09-2026 | Sysmon Event ID 11 | General file-creation telemetry reviewed | Confirmed telemetry availability |
| 10-09-2026 | Sysmon Event ID 11 | Targeted search for archive/lab indicators returned no displayed result | Not established |
| 10-09-2026 | PowerShell Event ID 4104 | Targeted search for compression/archive indicators returned no displayed result | Not established |
| 10-09-2026 | Security Event ID 4688 | Targeted search for `powershell.exe` and `Compress-Archive` returned no displayed result | Not established |
| 10-09-2026 06:43:42–07:26:22 | Sysmon Event ID 3 | Numerous network connections observed | General telemetry; no archive transfer established |
| 10-09-2026 | Investigation | No external transfer performed | Confirmed lab condition |
| 10-09-2026 | Cleanup | Lab directory removed | Confirmed |
| 10-09-2026 | Cleanup verification | `Test-Path "C:\SuspiciousCompressionLab"` returned `False` | Confirmed |

## Timeline Analysis

The investigation began with creation of a controlled lab environment and three harmless source files.

At approximately `07:10:30`, the three files were compressed into `staged-data.zip`. The archive was subsequently hashed and extracted successfully, confirming that the expected source files were packaged.

Windows telemetry was then reviewed. Sysmon Event ID 1 was available and a targeted search returned multiple matching process-creation records, but the screenshot output was truncated and did not expose enough detail to associate every returned event directly with the Lab 71 compression command.

Targeted searches for Sysmon Event ID 11, PowerShell Event ID 4104, and Security Event ID 4688 did not display matching results. Sysmon Event ID 3 showed numerous network connections, but no displayed evidence established transfer of the archive.

## Final Timeline Assessment

The timeline confirms:

**Source files created → source files hashed → archive created → archive validated → telemetry reviewed → lab cleaned up**

The evidence confirms local compression and archive creation.

The timeline does not establish:

- malicious intent
- unauthorized collection
- external archive transfer
- data exfiltration

The appropriate final assessment is:

**Confirmed local compression of controlled test data; suspicious staging and exfiltration not established from the available evidence.**
