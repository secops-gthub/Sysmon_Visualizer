Multi-Source EDR Visualizer (Sysmon, Defender, & Security)

A professional-grade security analysis tool that reconstructs disparate Windows event logs into a hierarchical, EDR-style process tree. This version features an advanced Lineage Engine, multi-vector Threat Intel lookups, and a high-performance parsing architecture for deep forensic investigations.
🚀 Key Features

    Process Tree Lineage: Automatically correlates Parent and Child processes using unique GUIDs and PIDs. The view is sorted Ascending (Oldest to Newest), allowing analysts to follow the flow of execution down the screen with visual indentation (┗━━).

    Expanded VirusTotal Integration (New): Beyond file hashes, the right-click context menu now supports instant intelligence lookups for Destination IPs and DNS Queries, launching the specific VirusTotal report page for that indicator.

    Dedicated Network Telemetry (New): Individual columns for Dest IP and DNS Query with dedicated real-time filters to isolate Command & Control (C2) traffic or data exfiltration attempts.

    Universal Property Mapping: Uses advanced XML-based parsing to correctly extract "Named" properties (like TargetUserName, IpAddress, and CommandLine) from Security and Sysmon logs that typically appear blank in standard viewers.

    SHA256 Hash Visibility: Automatically isolates SHA256 hashes from Sysmon events. Long hashes are truncated for cleanliness but are viewable via Tooltip hover.

    GUI Cell Copying: High-flexibility selection (Cell-level) allows you to click any data point and press Ctrl+C to copy it directly for external lookups.

    Performance-Optimized HTML Export: Utilizes StringBuilder logic to generate massive investigation reports instantly without application hanging.

    Multi-Source Ingestion:

        Sysmon: Process behavior (ID 1), network telemetry (ID 3), and DNS queries (ID 22).

        Windows Defender: Malware detection and remediation history with high-fidelity path parsing.

        Windows Security: Decoded Logons (4624), Process Auditing (4688), Group Enumeration (4798), and Credential Reads (5379).

    Persistent & Cumulative Loading: Append multiple .evtx or .xml files to a single session to track lateral movement across different machines and timeframes.

📋 Requirements

    OS: Windows 10/11 or Windows Server 2016+.

    PowerShell: Version 7.x

    Permissions: Administrator privileges are required to access live local log streams.

🛠️ How It Works
1. Source Selection

Upon launch, choose to pull Live Logs (last 24 hours) from the local machine or proceed to the dashboard for Manual Import of forensic files.
2. The Dashboard

    Add Log: Merge new forensic files into your current investigation timeline.

    Process Lineage: Processes are visually grouped under their parents. Reading from top to bottom shows the chronological "birth" and expansion of a process tree.

    Enhanced Filtering: Specialized search boxes for User, Event ID, Hash, Destination IP, DNS Query, or Date Range.

    Clear Filter: A dedicated button to instantly reset all search fields and restore the full dataset.

    Exit: A dedicated button to safely close the session and clear temporary memory.

3. Reporting & Investigation

    Smart Context Menu: Right-click an event to perform targeted VirusTotal lookups based on available data (Hash, IP, or Domain).

    Open HTML: Generates a temporary, CSS-styled report and launches it in your default browser.

    Save HTML: Exports a standalone, portable report for evidence or peer review.

📥 Installation

    Download Sysmon_Visualizer.ps1.

    Open PowerShell as Administrator.

    Run the script:
    PowerShell

    .\Sysmon_Visualizer.ps1
