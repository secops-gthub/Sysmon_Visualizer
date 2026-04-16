<#
    Sysmon, Defender & Security EDR Visualizer - Multi-Load Edition
    Copyright (c) 2026 [Your Name]
    License: MIT

    - FIXED: XAML Namespaces for both Selection and Main Windows
    - FIXED: Cumulative loading (Add logs without wiping)
    - Sources: Sysmon, Windows Defender, Security
#>

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

# ------------------------------
# CORE: UNIVERSAL PARSING ENGINE
# ------------------------------
function Get-CombinedEDREvents {
    param(
        [string]$Path = $null,
        [string[]]$LiveLogs = @()
    )

    $lookbackTime = (Get-Date).AddDays(-1) 
    $events = @()

    try {
        if ($Path) {
            $events = if ($Path.EndsWith(".xml")) {
                ([xml](Get-Content $Path)).SelectNodes("//Event")
            } else {
                Get-WinEvent -Path $Path -Oldest
            }
        } elseif ($LiveLogs.Count -gt 0) {
            foreach ($log in $LiveLogs) {
                $events += Get-WinEvent -FilterHashtable @{LogName=$log; StartTime=$lookbackTime} -ErrorAction SilentlyContinue
            }
        }
    } catch { return @() }

    $parsedData = foreach ($e in $events) {
        $xml = if ($e.ToXml) { [xml]$e.ToXml() } else { $e }
        $id = $xml.Event.System.EventID ?? $e.Id
        $provider = $xml.Event.System.Provider.Name ?? $e.ProviderName
        
        $data = @{}
        $eventDataNodes = $xml.Event.EventData.Data ?? $e.EventData.Data
        foreach ($d in $eventDataNodes) { $data[$d.Name] = $d.'#text' }
        
        $details = if ($provider -like "*Sysmon*") {
            switch($id) {
                1  { "PROCESS: $($data.CommandLine)" }
                3  { "NETWORK: $($data.SourceIp) -> $($data.DestinationIp):$($data.DestinationPort)" }
                22 { "DNS: $($data.QueryName)" }
                default { "Sysmon ID $id" }
            }
        } elseif ($provider -like "*Windows Defender*") {
            switch($id) {
                1116 { "⚠️ DEFENDER: Threat Detected - $($data.'Threat Name')" }
                1117 { "🛡️ DEFENDER: Action Taken - $($data.'Threat Name')" }
                default { "Defender ID $id" }
            }
        } elseif ($provider -like "*Microsoft-Windows-Security-Auditing*") {
            switch($id) {
                4624 { "🔑 LOGON: Type $($data.LogonType) - User: $($data.TargetUserName)" }
                4625 { "🚫 LOGON FAIL: User: $($data.TargetUserName)" }
                4688 { "🚀 PROCESS: $($data.NewProcessName)" }
                default { "Security ID $id" }
            }
        }

        [PSCustomObject]@{
            TimeCreated     = [datetime]($xml.Event.System.TimeCreated.SystemTime ?? $e.TimeCreated)
            EventID         = [int]$id
            Provider        = $provider
            Image           = $data.Image ?? $data.'Process Name' ?? $data.NewProcessName ?? "System/EDR"
            User            = $data.User ?? $data.TargetUserName ?? "N/A"
            Details         = $details
        }
    }
    return $parsedData
}

function Get-EDRTreeView {
    param([object[]]$Events)
    if ($null -eq $Events) { return @() }
    
    # Force sort newest first whenever the view is generated
    foreach ($item in ($Events | Sort-Object TimeCreated -Descending)) {
        [PSCustomObject]@{
            Time         = $item.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss.fff")
            User         = $item.User
            EventID      = $item.EventID
            ActivityTree = "$($item.TimeCreated.ToString('HH:mm:ss.fff')) | ID:$($item.EventID) | $($item.Image)`n ┗━━ $($item.Details)"
        }
    }
}

# ------------------------------
# UI: INITIAL LOG SELECTOR (Fixed Namespace)
# ------------------------------
$selectorXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Source Selection" Height="260" Width="360" WindowStartupLocation="CenterScreen" Topmost="True">
    <StackPanel Margin="20">
        <TextBlock Text="Select Live Logs to Load (Last 24h):" FontWeight="Bold" Margin="0,0,0,10"/>
        <CheckBox x:Name="ChkSecurity" Content="Windows Security Logs" Margin="0,5"/>
        <CheckBox x:Name="ChkDefender" Content="Windows Defender Logs" Margin="0,5"/>
        <CheckBox x:Name="ChkSysmon" Content="Sysmon Logs" IsChecked="True" Margin="0,5"/>
        <UniformGrid Columns="2" Margin="0,15,0,0">
            <Button x:Name="BtnLive" Content="⚡ Load Selected" Height="30" Margin="0,0,5,0"/>
            <Button x:Name="BtnManual" Content="📂 Manual Import" Height="30"/>
        </UniformGrid>
    </StackPanel>
</Window>
"@

$reader = [System.Xml.XmlNodeReader]::new(([xml]$selectorXaml))
$selector = [Windows.Markup.XamlReader]::Load($reader)

$script:selectedLogs = @()
$btnLive = $selector.FindName('BtnLive')
$btnManual = $selector.FindName('BtnManual')

$btnLive.Add_Click({
    if ($selector.FindName('ChkSecurity').IsChecked) { $script:selectedLogs += "Security" }
    if ($selector.FindName('ChkDefender').IsChecked) { $script:selectedLogs += "Microsoft-Windows-Windows Defender/Operational" }
    if ($selector.FindName('ChkSysmon').IsChecked)   { $script:selectedLogs += "Microsoft-Windows-Sysmon/Operational" }
    $selector.Close()
})
$btnManual.Add_Click({ $selector.Close() })
$selector.ShowDialog() | Out-Null

# ------------------------------
# UI: MAIN EDR DASHBOARD (Fixed Namespace)
# ------------------------------
$mainXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="EDR Cumulative Visualizer" Height="800" Width="1350">
    <Grid Margin="10">
        <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
        <StackPanel Orientation="Horizontal" Margin="0,0,0,10">
            <Button x:Name="BtnLoad" Content="📂 Add Log File" Width="110" Height="35" Margin="0,0,10,0"/>
            <Button x:Name="BtnClear" Content="🗑️ Clear All" Width="100" Height="35" Margin="0,0,20,0" Background="#FFC5C5"/>
            <TextBox x:Name="TbSearch" Width="200" VerticalContentAlignment="Center" Margin="0,0,10,0"/>
            <Button x:Name="BtnApply" Content="⚡ Filter" Width="80" Height="35" Margin="0,0,10,0"/>
            <Button x:Name="BtnHtmlOpen" Content="🌐 Open HTML" Width="110" Background="#28A745" Foreground="White" Margin="0,0,5,0"/>
            <Button x:Name="BtnHtmlSave" Content="💾 Save HTML" Width="110" Background="#6c757d" Foreground="White"/>
        </StackPanel>
        <DataGrid x:Name="GridEvents" Grid.Row="1" AutoGenerateColumns="False" IsReadOnly="True" FontFamily="Consolas">
            <DataGrid.Columns>
                <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="180"/>
                <DataGridTextColumn Header="User" Binding="{Binding User}" Width="150"/>
                <DataGridTextColumn Header="ID" Binding="{Binding EventID}" Width="50"/>
                <DataGridTextColumn Header="Activity Tree" Binding="{Binding ActivityTree}" Width="*"/>
            </DataGrid.Columns>
        </DataGrid>
        <StatusBar Grid.Row="2"><StatusBarItem><TextBlock x:Name="TxtStatus" Text="Ready"/></StatusBarItem></StatusBar>
    </Grid>
</Window>
"@

$reader = [System.Xml.XmlNodeReader]::new(([xml]$mainXaml))
$window = [Windows.Markup.XamlReader]::Load($reader)

$grid = $window.FindName('GridEvents')
$txtStatus = $window.FindName('TxtStatus')
$script:RawData = @()

# Initial load if checkboxes were used
if ($script:selectedLogs.Count -gt 0) {
    $txtStatus.Text = "Loading live logs..."
    $script:RawData = Get-CombinedEDREvents -LiveLogs $script:selectedLogs
    $grid.ItemsSource = Get-EDRTreeView -Events $script:RawData
    $txtStatus.Text = "Loaded $($script:RawData.Count) live events."
}

$window.FindName('BtnLoad').Add_Click({
    $dlg = [Microsoft.Win32.OpenFileDialog]::new()
    if ($dlg.ShowDialog()) {
        $newData = Get-CombinedEDREvents -Path $dlg.FileName
        $script:RawData += $newData
        $grid.ItemsSource = Get-EDRTreeView -Events $script:RawData
        $txtStatus.Text = "Added $($newData.Count) events. Total: $($script:RawData.Count)"
    }
})

$window.FindName('BtnClear').Add_Click({
    $script:RawData = @()
    $grid.ItemsSource = @()
    $txtStatus.Text = "Logs cleared."
})

$window.FindName('BtnApply').Add_Click({
    $searchText = $window.FindName('TbSearch').Text
    $filt = $script:RawData | Where-Object { $_.Details -like "*$searchText*" -or $_.Image -like "*$searchText*" }
    $grid.ItemsSource = Get-EDRTreeView -Events $filt
})

# Reporting logic
function Build-HtmlReport {
    param([object[]]$Data)
    $HtmlHeader = "<html><head><style>body{font-family:'Segoe UI';padding:20px}table{width:100%;border-collapse:collapse}th{background:#0078D4;color:white;padding:10px}td{padding:8px;border-bottom:1px solid #ddd;font-size:13px;vertical-align:top}.tree-cell{font-family:Consolas;white-space:pre-wrap;background:#f8f9fa;padding:5px;border-left:4px solid #0078D4;display:block}</style></head><body><h2>EDR Cumulative Report</h2><table><tbody>"
    $Rows = foreach ($row in $Data) { "<tr><td>$($row.Time)</td><td>$($row.User)</td><td><span class='tree-cell'>$($row.ActivityTree)</span></td></tr>" }
    return $HtmlHeader + ($Rows -join "") + "</tbody></table></body></html>"
}

$window.FindName('BtnHtmlOpen').Add_Click({
    if ($grid.ItemsSource) {
        $path = [System.IO.Path]::GetTempFileName() + ".html"
        Build-HtmlReport -Data $grid.ItemsSource | Out-File $path -Encoding utf8
        Start-Process $path
    }
})

$window.FindName('BtnHtmlSave').Add_Click({
    if ($grid.ItemsSource) {
        $dlg = [Microsoft.Win32.SaveFileDialog]::new()
        $dlg.Filter = "HTML Files (*.html)|*.html"
        if ($dlg.ShowDialog()) {
            Build-HtmlReport -Data $grid.ItemsSource | Out-File $dlg.FileName -Encoding utf8
        }
    }
})

$window.ShowDialog() | Out-Null
