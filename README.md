# Windows DFIR Lab 71 – Suspicious Compression Investigation

## Overview

This lab investigates suspicious file compression from a Windows DFIR and SOC perspective.

Compression is a legitimate administrative activity, but it can also appear during attacker data collection and staging. An attacker may gather multiple files into a single archive before attempting to move or exfiltrate the collected data.

In this controlled lab, three harmless test files were created inside a dedicated directory and compressed into `staged-data.zip` using PowerShell `Compress-Archive`. The resulting archive was then extracted and validated to confirm its contents.

The investigation also examined available Windows telemetry, including Sysmon process creation, Sysmon file creation, PowerShell Script Block Logging, Security Event ID 4688, and Sysmon network connection telemetry.

The goal was to understand how an analyst would investigate compression activity and determine whether the evidence supports simple local archiving, suspicious staging, or subsequent transfer activity.

## Environment

- Operating System: Windows
- Host shell: Windows PowerShell
- Lab directory: `C:\SuspiciousCompressionLab`
- Source directory: `C:\SuspiciousCompressionLab\Source`
- Archive: `C:\SuspiciousCompressionLab\staged-data.zip`

## Investigation Objectives

The investigation focused on:

- Identifying the files selected for compression.
- Recording source-file metadata and SHA256 hashes.
- Creating and validating a ZIP archive.
- Examining the archive's metadata and hash.
- Investigating available process-creation telemetry.
- Investigating PowerShell Script Block Logging.
- Reviewing Sysmon file-creation telemetry.
- Checking Security Event ID 4688.
- Reviewing network telemetry for possible follow-on activity.
- Building an evidence-based conclusion without assuming that compression equals exfiltration.

## Lab Directory Setup

The investigation directory was created at:

`C:\SuspiciousCompressionLab`

A source directory was then created:

`C:\SuspiciousCompressionLab\Source`

The environment was successfully created and verified before generating the test data.

## Controlled Test Data

Three harmless files were created:

| File | Size | Creation Time | Last Write Time |
|---|---:|---|---|
| `employee-list.txt` | 26 bytes | 10-09-2026 06:49:47 | 10-09-2026 06:49:47 |
| `project-notes.txt` | 26 bytes | 10-09-2026 06:49:47 | 10-09-2026 06:49:47 |
| `sample-data.txt` | 24 bytes | 10-09-2026 06:49:47 | 10-09-2026 06:49:47 |

The files contained only harmless Lab 71 test strings.

## Source File Hashes

SHA256 hashes were collected before compression.

The three observed hashes were:

- `employee-list.txt` — `95F78EE667B0C43CC8C161A6B880C49D1642890D327017B24D2E652560B9424D`
- `project-notes.txt` — `FF94E8013A52B156FE7A049FB731A5729C49EBB276A2C92B21FF8741D3266E04`
- `sample-data.txt` — `8585ACDD89E494B04AEAD3731D75DAF55AA9C072EA99067A057A51AC22CE6966`

These hashes provide a baseline for the controlled source artifacts.

## Archive Creation

The three source files were compressed using PowerShell `Compress-Archive`.

The resulting archive was:

`C:\SuspiciousCompressionLab\staged-data.zip`

Observed archive metadata:

- Length: 430 bytes
- CreationTime: `10-09-2026 07:10:30`
- LastWriteTime: `10-09-2026 07:10:30`

SHA256:

`EBF10BAAF9CD20C8941D41C675C3B71170D131C861B57FF1D6C04DE7C3125263`

## Archive Validation

The archive was extracted with `Expand-Archive` into:

`C:\SuspiciousCompressionLab\Extracted`

The extracted directory contained:

- `employee-list.txt`
- `project-notes.txt`
- `sample-data.txt`

Their observed sizes matched the original source files:

- 26 bytes
- 26 bytes
- 24 bytes

This confirmed that the archive contained the three controlled source files.

## Sysmon Investigation

Sysmon Event ID 1 process-creation telemetry was available.

An unfiltered query returned multiple process-creation events between approximately 06:50 and 07:16 on 10-09-2026.

A targeted search for:

- `Compress-Archive`
- `powershell.exe`
- `staged-data.zip`

returned multiple matching process-creation events.

However, the screenshot output showed only the event summary and did not expose the complete message details for each returned event.

Therefore, the screenshots establish the presence of matching Sysmon Event ID 1 results but do not provide enough detail to attribute every returned event specifically to the archive creation.

## Sysmon Event ID 11

Sysmon Event ID 11 file-creation telemetry was available and returned many file-creation events.

A targeted search for:

- `staged-data.zip`
- `SuspiciousCompressionLab`

returned no displayed result.

Therefore, the provided evidence does not establish a direct Sysmon Event ID 11 record for `staged-data.zip`.

The archive's existence is instead confirmed directly through filesystem inspection.

## PowerShell Event ID 4104

PowerShell Operational Event ID 4104 was queried for:

- `Compress-Archive`
- `staged-data.zip`
- `SuspiciousCompressionLab`

The targeted query returned no displayed result.

Therefore, the screenshots do not establish a matching PowerShell Script Block event for the exact compression command.

This should be recorded as a telemetry limitation rather than interpreted as proof that the command was not executed through PowerShell.

## Security Event ID 4688

Security Event ID 4688 was queried for:

- `powershell.exe`
- `Compress-Archive`

The targeted query returned no displayed result.

As a result, Security Event ID 4688 does not provide confirmed supporting evidence for the compression activity in the provided screenshots.

## Sysmon Event ID 3

Sysmon Event ID 3 network telemetry was available.

The unfiltered output showed numerous network connection events between approximately 06:43 and 07:26 on 10-09-2026.

However, the screenshots did not provide sufficient process-level details to establish that any displayed network connection belonged to the compression operation or that `staged-data.zip` was transferred externally.

No external transfer was performed as part of this lab.

## Evidence Assessment

### Confirmed

- The Lab 71 directory was created.
- A controlled source directory was created.
- Three harmless test files were created.
- Source-file metadata was collected.
- Source-file SHA256 hashes were collected.
- A 430-byte `staged-data.zip` archive was created.
- The archive SHA256 was collected.
- The archive was successfully extracted.
- The extracted files corresponded to the three controlled source files.
- Sysmon Event ID 1 telemetry was available and the targeted query returned matching process-creation events.

### Not Established

- A directly displayed Sysmon Event ID 11 event for `staged-data.zip`.
- A directly displayed PowerShell Event ID 4104 event containing the compression command.
- A directly displayed Security Event ID 4688 event supporting the compression command.
- External transfer of the archive.
- Data exfiltration.
- Malicious intent behind the compression activity.

## Investigative Conclusion

The evidence demonstrates controlled local compression of three harmless files into `staged-data.zip`, followed by successful extraction and validation.

The activity is useful as a DFIR simulation of possible data staging, but the provided telemetry does not establish malicious intent or exfiltration. The available Sysmon process-creation results provide supporting execution visibility, while the targeted PowerShell, Security 4688, and Sysmon 11 searches did not return displayed matches.

The correct investigative conclusion is therefore that **local compression and archive creation were confirmed, while malicious staging or exfiltration was not established from the available evidence**.

## Cleanup

The lab directory was removed after the investigation:

`C:\SuspiciousCompressionLab`

Cleanup verification returned:

`False`

for:

`Test-Path "C:\SuspiciousCompressionLab"`

## DFIR Lessons

- Compression is not inherently malicious.
- Archive contents are as important as the archive itself.
- Process command lines provide valuable context when investigating compression.
- File creation telemetry can help correlate archive creation with process activity.
- A network connection does not automatically indicate archive transfer.
- Missing telemetry should be documented as a limitation rather than converted into a negative assertion.
- Compression should be investigated as part of a broader collection and staging chain.
