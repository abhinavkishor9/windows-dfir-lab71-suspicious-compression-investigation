# windows-dfir-lab71-suspicious-compression-investigation
## Overview
Compression is a normal activity used to reduce file size and package multiple files into a single archive. Windows systems commonly use tools such as PowerShell, Compress-Archive, tar.exe, and third-party archiving utilities.

From a DFIR perspective, compression becomes interesting when an attacker uses it to collect and package files before moving or exfiltrating them.

A typical suspicious sequence can look like:

Discover files → Collect files → Compress files → Transfer/archive

The compression itself is not necessarily malicious. The analyst needs to understand what was compressed, where the archive was created, which process created it, who initiated it, and what happened afterward.

Why is Compression Important in SOC/DFIR?

Attackers may compress:

Documents
Credentials or configuration files
Browser artifacts
Logs
Source code
Multiple files from different directories

Packaging these files into a single archive can make collection and subsequent transfer easier.

For example, an analyst may see:

powershell.exe
        ↓
Compress-Archive
        ↓
C:\Users\...\Documents.zip

That is not automatically malicious.

But something like:

powershell.exe
        ↓
Collect files from multiple user directories
        ↓
Create archive in a temporary/staging directory
        ↓
Archive accessed by another process

would deserve closer investigation.

The key investigative question is:

Was the compression activity normal file management, or does the context suggest staged data collection?

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

- Create and document a controlled set of files for a compression investigation.
- Collect file metadata and SHA256 hashes before compression.
- Use PowerShell Compress-Archive to create a test ZIP archive.
- Validate the archive contents using Expand-Archive.
- Investigate Sysmon Event ID 1 for related process execution.
- Examine Sysmon Event ID 11 for archive/file creation activity.
- Search PowerShell Event ID 4104 and Security Event ID 4688 for supporting evidence.
- Review Sysmon Event ID 3 for possible follow-on network activity.
- Correlate timestamps, processes, files, and archive activity into an investigation timeline.
- Distinguish confirmed compression from suspected staging or exfiltration.
- Document telemetry gaps and reach an evidence-based conclusion.

  ## Investigation Scenario

  A Windows workstation is being investigated after the analyst notices the creation of a ZIP archive containing several files from a local staging directory. While compression is a normal administrative operation, attackers may also use it to package collected data before attempting to move or exfiltrate it.

During the investigation, the analyst will examine:

- Three controlled files placed in a source directory.
- Creation of staged-data.zip using PowerShell Compress-Archive.
- File metadata and SHA256 hashes before and after compression.
- Sysmon process and file-creation telemetry.
- PowerShell and Security process-creation logging.
- Network activity around the archive creation time.

The objective is to determine what happened, how the archive was created, and whether there is evidence of suspicious staging or follow-on activity.

The lab uses only harmless test data and no external transfer is performed. The investigation should therefore focus on evidence correlation and accurate classification, distinguishing confirmed compression from activity that remains unestablished.
  
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

