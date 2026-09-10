# Investigation Notes 

## 1. Investigation Objective

The objective was to investigate local compression activity from a Windows DFIR perspective and determine whether the creation of an archive could be associated with suspicious data staging.

The exercise used only harmless files created specifically for the lab.

## 2. Lab Environment

Lab path:

`C:\SuspiciousCompressionLab`

Source path:

`C:\SuspiciousCompressionLab\Source`

Archive:

`C:\SuspiciousCompressionLab\staged-data.zip`

The directory was successfully created and verified at 10-09-2026 06:40.

The source directory was created at 10-09-2026 06:45.

## 3. Source Data Creation

Three controlled files were created at approximately 10-09-2026 06:49:47.

### employee-list.txt

- Length: 26 bytes
- CreationTime: `10-09-2026 06:49:47`
- LastWriteTime: `10-09-2026 06:49:47`
- SHA256:
  `95F78EE667B0C43CC8C161A6B880C49D1642890D327017B24D2E652560B9424D`

### project-notes.txt

- Length: 26 bytes
- CreationTime: `10-09-2026 06:49:47`
- LastWriteTime: `10-09-2026 06:49:47`
- SHA256:
  `FF94E8013A52B156FE7A049FB731A5729C49EBB276A2C92B21FF8741D3266E04`

### sample-data.txt

- Length: 24 bytes
- CreationTime: `10-09-2026 06:49:47`
- LastWriteTime: `10-09-2026 06:49:47`
- SHA256:
  `8585ACDD89E494B04AEAD3731D75DAF55AA9C072EA99067A057A51AC22CE6966`

The files contained harmless Lab 71 test content.

## 4. Compression Activity

PowerShell `Compress-Archive` was used to package the source files.

The resulting archive:

`C:\SuspiciousCompressionLab\staged-data.zip`

Metadata:

- Length: 430 bytes
- CreationTime: `10-09-2026 07:10:30`
- LastWriteTime: `10-09-2026 07:10:30`

Archive SHA256:

`EBF10BAAF9CD20C8941D41C675C3B71170D131C861B57FF1D6C04DE7C3125263`

The archive therefore represents a confirmed local compression artifact.

## 5. Archive Validation

The archive was extracted using `Expand-Archive`.

Destination:

`C:\SuspiciousCompressionLab\Extracted`

The extraction produced:

- `employee-list.txt`
- `project-notes.txt`
- `sample-data.txt`

Observed extracted sizes:

- employee-list.txt — 26 bytes
- project-notes.txt — 26 bytes
- sample-data.txt — 24 bytes

The result confirmed that the expected three files were packaged into the archive.

## 6. Sysmon Event ID 1

The general Sysmon Event ID 1 query returned many process-creation events during the relevant period.

A targeted search using:

`Compress-Archive|powershell.exe|staged-data.zip`

returned multiple matching events.

Observed matching timestamps included:

- 10-09-2026 06:39:35
- 10-09-2026 06:35:42
- 10-09-2026 06:35:35
- 09-09-2026 08:00:30
- 09-09-2026 07:58:25
- 09-09-2026 07:53:45
- 09-09-2026 07:53:40
- 09-09-2026 07:53:21
- 09-09-2026 07:35:29
- 09-09-2026 07:33:52
- 09-09-2026 07:14:01
- 09-09-2026 07:05:54
- 09-09-2026 06:54:53
- 09-09-2026 06:54:46
- 02-09-2026 07:46:56
- 02-09-2026 07:31:15
- 02-09-2026 07:30:55
- 02-09-2026 07:18:20
- 02-09-2026 07:18:04
- 02-09-2026 07:17:10
- 02-09-2026 07:16:46
- 02-09-2026 06:33:27
- 02-09-2026 06:33:22
- 02-09-2026 06:32:18

Important limitation:

The screenshot displays only the event summary:

`Process Create:...`

rather than the full event messages.

Therefore, the targeted search establishes that matching Sysmon process-creation events were returned, but it does not establish that every returned record corresponds to the Lab 71 compression command.

## 7. Sysmon Event ID 11

An unfiltered Event ID 11 query returned numerous file-creation events.

A targeted search for:

- `staged-data.zip`
- `SuspiciousCompressionLab`

returned no displayed results.

The filesystem itself clearly confirmed the archive's creation, but a matching Sysmon Event ID 11 event was not established from the screenshot evidence.

## 8. PowerShell Event ID 4104

PowerShell Operational Event ID 4104 was queried using:

- `Compress-Archive`
- `staged-data.zip`
- `SuspiciousCompressionLab`

No displayed matching event was returned.

This means:

> No matching Event ID 4104 result was identified in the provided query output.

It does not prove that PowerShell Script Block Logging was disabled or that the compression command did not execute through PowerShell.

## 9. Security Event ID 4688

Security Event ID 4688 was queried using:

- `powershell.exe`
- `Compress-Archive`

No displayed result was returned.

Therefore, the provided evidence does not establish Security 4688 support for the compression command.

## 10. Sysmon Event ID 3

Sysmon Event ID 3 returned a large number of network connection events.

Visible timestamps ranged from approximately:

`10-09-2026 06:43:42`

through:

`10-09-2026 07:26:22`

The screenshot did not expose sufficient process or destination details to correlate any specific connection with `staged-data.zip`.

No external transfer was performed.

