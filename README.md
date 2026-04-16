# Multi-Source EDR Visualizer (Sysmon, Defender, & Security)

A high-fidelity security analysis tool that reconstructs Windows event logs into a hierarchical, EDR-style process tree. This version supports cumulative loading, allowing analysts to merge live logs and forensic files into a single unified timeline.

## 🚀 Key Features

- **Multi-Source Ingestion**: Combines data from:
    - **Sysmon**: Detailed process behavior, network connections, and DNS queries.
    - **Windows Defender**: Malware detections and automated remediation actions.
    - **Windows Security**: User logons (ID 4624), failures (4625), and process auditing (4688).
- **Selection Hub**: A pre-launch dashboard to toggle specific live log sources for a 24-hour lookback.
- **Cumulative Loading**: Merge multiple `.evtx` or `.xml` files without wiping existing data—perfect for tracking lateral movement across different machines.
- **EDR-Style Visualization**: Maps parent-child relationships with specialized icons (⚠️ for threats, 🔑 for logons).
- **Advanced Filtering**: Real-time "Search-as-you-type" filtering across the entire merged activity tree.

## 📋 Requirements

- **OS**: Windows 10/11 or Windows Server 2016+.
- **PowerShell**: **Version 7.x** (Optimized for speed and modern XAML handling).
- **Permissions**: Must be run as **Administrator** to access the Windows Security and Sysmon log streams.
- **Dependencies**: [Sysinternals Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) should be installed for process/network visibility.

## 🛠️ How It Works

### 1. Source Selection
Upon launch, a Selection Hub appears. 
- **Live Load**: Check the logs you wish to pull from the local machine (Last 24 hours).
- **Manual Import**: Skip live logs to go directly to the dashboard for file analysis.

### 2. The Dashboard
- **Add Log File**: Import external logs. These will be added to your current view rather than replacing it.
- **Clear All**: Resets the memory to start a fresh investigation.
- **Filter**: Instantly narrows down the tree by User, IP, Image name, or Threat name.

### 3. Reporting
- **Open HTML**: Generates a temporary, interactive report in your default browser.
- **Save HTML**: Exports a standalone report for evidence or peer review.

## 📥 Installation

1. Clone the repository or download `Security_logs_analyzer.ps1`.
2. Open PowerShell 7 as **Administrator**.
3. Execute the script:
   ```powershell
   .\Security_logs_analyzer.ps1
