# Sysmon EDR Tree Visualizer

A professional-grade PowerShell security tool designed to reconstruct Sysmon Event Logs into a hierarchical, EDR-style process tree. This tool helps security analysts visualize the relationship between process executions, network connections, file creations, and DNS queries.

## 🚀 Features

- **EDR-Style Visualization**: Reconstructs activity into a nested tree format (e.g., `explorer.exe` -> `chrome.exe` -> `google.com`).
- **Live & Static Analysis**: Automatically prompts to load live `Microsoft-Windows-Sysmon/Operational` logs on launch, with a fallback to `.evtx` or `.xml` files.
- **Advanced Filtering**:
    - **Event ID**: Filter by specific IDs (e.g., 1, 3, 11, 22).
    - **Date/Time**: Narrow down incidents with precise start and end dates.
    - **User**: Isolate activity by specific user accounts.
    - **Tree Search**: Perform string searches directly against the rendered process tree.
- **Instant Reporting**:
    - **Open HTML**: Generates a temporary report and launches it in your default browser.
    - **Save HTML**: Saves a standalone HTML report for documentation and handovers.

## 📋 Requirements

- **OS**: Windows 10/11 or Windows Server 2016+.
- **PowerShell**: Version PowerShell 7+.
- **Permissions**: **Administrative Privileges** are required to read live local Sysmon logs.
- **Software**: [Sysinternals Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) must be installed and configured on the system being analyzed.

## 🛠️ Installation & Usage

1. **Download**: Save `Sysmon_Visualizer.ps1` to your machine.
2. **Run**: Open PowerShell as **Administrator** and execute:
   ```powershell
   .\Sysmon_EDR_Visualizer.ps1
