Multi-Source EDR Visualizer (Sysmon, Defender, & Security)

A professional-grade security analysis tool that reconstructs disparate Windows event logs into a hierarchical, EDR-style process tree. This version features an advanced Lineage Engine, dedicated Threat Intel lookups, and a high-performance parsing architecture for deep forensic investigations.
🚀 Key Features

    Process Tree Lineage (New): Automatically correlates Parent and Child processes using unique GUIDs and PIDs. The view is sorted Ascending (Oldest to Newest), allowing analysts to follow the flow of execution down the screen with visual indentation (┗━━).

    VirusTotal Integration (New): Right-click any log entry to instantly search for its SHA256 hash on VirusTotal via your default browser.

    Network & DNS Visibility (New): Dedicated columns and specialized filters for Destination IPs and DNS Queries, providing instant visibility into C2 communication or data exfiltration.

    Universal Property Mapping: Uses advanced XML-based parsing to correctly extract "Named" properties (like TargetUserName, IpAddress, and CommandLine) from Security and Sysmon logs that typically appear blank in standard viewers.

    SHA256 Hash Visibility: Automatically isolates the SHA256 hash from Sysmon events. Long hashes are truncated for cleanliness but are viewable via Tooltip hover.

    GUI Cell Copying: High-flexibility selection allows you to click any cell and press Ctrl+C to copy the data directly to your clipboard.

    Performance-Optimized HTML Export: Utilizes StringBuilder logic to generate massive investigation reports instantly without application hanging.

    Multi-Source Ingestion:

        Sysmon: Process behavior (ID 1), network telemetry (ID 3), and DNS queries (ID 22).

        Windows Defender: Malware detection and remediation history with high-fidelity path parsing.

        Windows Security: Decoded Logons (4624), Process Auditing (4688), Group Enumeration (4798), and Credential Reads (5379).

    Persistent & Cumulative Loading: Append multiple .evtx or .xml files to a single session to track lateral movement across different machines.

📋 Requirements

    OS: Windows 10/11 or Windows Server 2016+.

    PowerShell: Version 7.x (Recommended) or 5.1.

    Permissions: Administrator privileges are required to access live local log streams.

🛠️ How It Works
1. Source Selection

Upon launch, choose to pull Live Logs (last 24 hours) from the local machine or proceed to the dashboard for Manual Import of forensic files.
2. The Dashboard

    Add Log: Merge new forensic files into your current investigation timeline.

    Process Lineage: Processes are visually grouped under their parents. Reading from top to bottom shows the chronological "birth" of a process tree.

    Enhanced Filtering: Search by User, Event ID, Hash, Destination IP, DNS Query, or Date Range.

    Clear Filter: A dedicated button to instantly reset all search fields and restore the full dataset.

    Exit: A dedicated button to safely close the session and clear temporary memory.

3. Reporting & Investigation

    Right-Click Menu: Select an event and right-click to perform external lookups (VirusTotal).

    Open HTML: Generates a temporary, CSS-styled report and launches it in your default browser.

    Save HTML: Exports a standalone, portable report for evidence or peer review.

📥 Installation

    Download Sysmon_Visualizer.ps1.

    Open PowerShell as Administrator.

    Run the script:
    PowerShell

    .\Sysmon_Visualizer.ps1
