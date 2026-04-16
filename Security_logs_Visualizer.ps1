<#
    Advanced EDR Multi-Source Visualizer - CUMULATIVE & DATE FILTERED
    - FIXED: Date Range filtering for older/manual logs.
    - FIXED: Performance optimized HTML Export (no more freezing).
    - FIXED: Universal XML property mapping for all Security Event IDs.
#>

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

# ------------------------------
# CORE: UNIVERSAL PARSING ENGINE
# ------------------------------
function Get-CombinedEDREvents {
    param([string]$Path = $null, [string[]]$LiveLogs = @())
    $events = @()
    # Only use lookback for Live Logs; Manual imports should take everything
    $lookbackTime = (Get-Date).AddDays(-1) 

    try {
        if ($Path) {
            $events = if ($Path.EndsWith(".xml")) { 
                ([xml](Get-Content $Path)).SelectNodes("//*[local-name()='Event']") 
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
        $xml = if ($e.ToXml) { [xml]$e.ToXml() } else { [xml]$e }
        $id = [int]($xml.Event.System.EventID.'#text' ?? $xml.Event.System.EventID ?? $e.Id)
        $provider = $xml.Event.System.Provider.Name ?? $e.ProviderName
        $timeCreated = [datetime]($xml.Event.System.TimeCreated.SystemTime ?? $e.TimeCreated)

        $data = @{}
        foreach ($node in $xml.Event.EventData.Data) {
            if ($node.Name) { $data[$node.Name] = $node.'#text' }
            else { $data["Param_$($data.Count)"] = $node.'#text' }
        }
        
        $detectedUser = $data.TargetUserName ?? $data.SubjectUserName ?? $data.User ?? "N/A"
        $imagePath = $data.NewProcessName ?? $data.Image ?? $data.ProcessName ?? "System/EDR"

        $details = if ($provider -like "*Security-Auditing*") {
            switch($id) {
                4624 { "🔑 LOGON: Type $($data.LogonType) - Target: $($data.TargetUserName) - IP: $($data.IpAddress ?? 'Local')" }
                4688 { "🚀 PROCESS: $($data.NewProcessName)" }
                4798 { "🔍 GROUP: Enumerate groups for $($data.TargetUserName)" }
                5379 { "📂 CRED: Read by $($data.SubjectUserName) for $($data.TargetUserName)" }
                default { "Security ID $id" }
            }
        } elseif ($provider -like "*Sysmon*") {
            switch($id) {
                1  { "PROCESS: $($data.CommandLine)" }
                3  { "NETWORK: $($data.SourceIp) -> $($data.DestinationIp):$($data.DestinationPort)" }
                22 { "DNS: $($data.QueryName)" }
                default { "Sysmon ID $id" }
            }
        }

        if ([string]::IsNullOrWhiteSpace($details) -or $details -match "ID \d+") {
            $details = ($data.GetEnumerator() | Select-Object -First 3 | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join " | "
        }

        [PSCustomObject]@{
            TimeCreated     = $timeCreated
            EventID         = [string]$id
            Provider        = $provider
            Image           = $imagePath
            User            = $detectedUser
            Details         = $details
        }
    }
    return $parsedData
}

function Get-EDRTreeView {
    param([object[]]$Events)
    if ($null -eq $Events) { return @() }
    foreach ($item in ($Events | Sort-Object TimeCreated -Descending)) {
        [PSCustomObject]@{
            Time         = $item.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss.fff")
            User         = $item.User
            EventID      = $item.EventID
            ActivityTree = "ID:$($item.EventID) | $($item.Image)`n ┗━━ $($item.Details)"
            RawDate      = $item.TimeCreated
        }
    }
}

# ------------------------------
# OPTIMIZED HTML ENGINE
# ------------------------------
function ConvertTo-HtmlReport {
    param($DataItems)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<html><head><style>
    body { font-family: 'Segoe UI', sans-serif; margin: 30px; background-color: #f8f9fa; }
    h2 { color: #0078D4; border-bottom: 2px solid #0078D4; padding-bottom: 10px; }
    table { width: 100%; border-collapse: collapse; background: white; margin-top: 20px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
    th { background-color: #0078D4; color: white; padding: 12px; text-align: left; }
    td { padding: 10px; border-bottom: 1px solid #dee2e6; font-family: 'Consolas', monospace; font-size: 12px; vertical-align: top; }
    tr:nth-child(even) { background-color: #f2f2f2; }
    .tree { white-space: pre-wrap; color: #333; }
</style></head>
<body>
    <h2>EDR Investigation Activity Report</h2>
    <table><tr><th>Time</th><th>User</th><th>ID</th><th>Activity / Details</th></tr>
"@)
    foreach ($row in $DataItems) {
        $cleanTree = [System.Net.WebUtility]::HtmlEncode($row.ActivityTree)
        [void]$sb.Append("<tr><td>$($row.Time)</td><td>$($row.User)</td><td>$($row.EventID)</td><td class='tree'>$cleanTree</td></tr>")
    }
    [void]$sb.Append("</table></body></html>")
    return $sb.ToString()
}

# ------------------------------
# UI: SOURCE SELECTOR
# ------------------------------
$selectorXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Source Selection" Height="260" Width="360" WindowStartupLocation="CenterScreen" Topmost="True">
    <StackPanel Margin="20">
        <TextBlock Text="Select Live Logs (Last 24h):" FontWeight="Bold" FontSize="14" Margin="0,0,0,10"/>
        <CheckBox x:Name="ChkSecurity" Content="Windows Security Logs" IsChecked="False" Margin="0,5"/>
        <CheckBox x:Name="ChkDefender" Content="Windows Defender Logs" IsChecked="False" Margin="0,5"/>
        <CheckBox x:Name="ChkSysmon" Content="Sysmon Logs" IsChecked="False" Margin="0,5"/>
        <UniformGrid Columns="2" Margin="0,15,0,0">
            <Button x:Name="BtnLive" Content="⚡ Load Selected" Height="35" Margin="0,0,5,0" Background="#0078D4" Foreground="White"/>
            <Button x:Name="BtnManual" Content="📂 Manual Import" Height="35"/>
        </UniformGrid>
    </StackPanel>
</Window>
"@

$reader = [System.Xml.XmlNodeReader]::new(([xml]$selectorXaml))
$selector = [Windows.Markup.XamlReader]::Load($reader)
$script:selectedLogs = @()

$selector.FindName('BtnLive').Add_Click({
    if ($selector.FindName('ChkSecurity').IsChecked) { $script:selectedLogs += "Security" }
    if ($selector.FindName('ChkDefender').IsChecked) { $script:selectedLogs += "Microsoft-Windows-Windows Defender/Operational" }
    if ($selector.FindName('ChkSysmon').IsChecked)   { $script:selectedLogs += "Microsoft-Windows-Sysmon/Operational" }
    $selector.Close()
})
$selector.FindName('BtnManual').Add_Click({ $selector.Close() })
$selector.ShowDialog() | Out-Null

# ------------------------------
# UI: MAIN EDR DASHBOARD
# ------------------------------
$mainXaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="EDR Visualizer" Height="900" Width="1400">
    <Grid Margin="10">
        <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
        
        <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,10">
            <Button x:Name="BtnLoad" Content="📂 Add Log" Width="90" Height="30" Margin="0,0,10,0"/>
            <Button x:Name="BtnClear" Content="🗑️ Clear" Width="80" Height="30" Background="#FFC5C5" Margin="0,0,10,0"/>
            <Button x:Name="BtnHtmlSave" Content="💾 Save HTML" Width="100" Height="30" Background="#6c757d" Foreground="White" Margin="0,0,5,0"/>
            <Button x:Name="BtnHtmlOpen" Content="🌐 Open HTML" Width="100" Height="30" Background="#28A745" Foreground="White"/>
        </StackPanel>

        <Border Grid.Row="1" Background="#E9ECEF" Padding="10" CornerRadius="5" Margin="0,0,0,10">
            <WrapPanel>
                <StackPanel Margin="0,0,10,0">
                    <TextBlock Text="Filter User:" FontSize="10"/>
                    <TextBox x:Name="TbUserFilt" Width="120" Height="25"/>
                </StackPanel>
                <StackPanel Margin="0,0,10,0">
                    <TextBlock Text="Filter Event ID:" FontSize="10"/>
                    <TextBox x:Name="TbIdFilt" Width="60" Height="25"/>
                </StackPanel>
                <StackPanel Margin="0,0,10,0">
                    <TextBlock Text="Date Range:" FontSize="10"/>
                    <StackPanel Orientation="Horizontal">
                        <DatePicker x:Name="DpStart" Width="110"/>
                        <DatePicker x:Name="DpEnd" Width="110" Margin="5,0,0,0"/>
                    </StackPanel>
                </StackPanel>
                <StackPanel Margin="0,0,10,0">
                    <TextBlock Text="Filter Activity:" FontSize="10"/>
                    <TextBox x:Name="TbTreeFilt" Width="250" Height="25"/>
                </StackPanel>
                <Button x:Name="BtnApply" Content="⚡ Apply" Width="80" Height="35" VerticalAlignment="Bottom" Background="#0078D4" Foreground="White"/>
            </WrapPanel>
        </Border>

        <DataGrid x:Name="GridEvents" Grid.Row="2" AutoGenerateColumns="False" IsReadOnly="True" FontFamily="Consolas">
            <DataGrid.Columns>
                <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="180" SortMemberPath="RawDate"/>
                <DataGridTextColumn Header="User" Binding="{Binding User}" Width="150"/>
                <DataGridTextColumn Header="ID" Binding="{Binding EventID}" Width="60"/>
                <DataGridTextColumn Header="Activity Tree" Binding="{Binding ActivityTree}" Width="*"/>
            </DataGrid.Columns>
        </DataGrid>
        <StatusBar Grid.Row="3" Background="#F0F0F0"><StatusBarItem><TextBlock x:Name="TxtStatus" Text="Ready"/></StatusBarItem></StatusBar>
    </Grid>
</Window>
"@

$reader = [System.Xml.XmlNodeReader]::new(([xml]$mainXaml))
$window = [Windows.Markup.XamlReader]::Load($reader)
$grid = $window.FindName('GridEvents')
$txtStatus = $window.FindName('TxtStatus')
$script:RawData = @()

if ($script:selectedLogs.Count -gt 0) {
    $script:RawData = Get-CombinedEDREvents -LiveLogs $script:selectedLogs
    $grid.ItemsSource = Get-EDRTreeView -Events $script:RawData
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

$window.FindName('BtnApply').Add_Click({
    $uFilt = $window.FindName('TbUserFilt').Text
    $iFilt = $window.FindName('TbIdFilt').Text
    $tFilt = $window.FindName('TbTreeFilt').Text
    $start = $window.FindName('DpStart').SelectedDate
    $end   = $window.FindName('DpEnd').SelectedDate

    # If all fields are blank, reset to original logs
    if ([string]::IsNullOrWhiteSpace($uFilt) -and [string]::IsNullOrWhiteSpace($iFilt) -and 
        [string]::IsNullOrWhiteSpace($tFilt) -and $null -eq $start -and $null -eq $end) {
        $grid.ItemsSource = Get-EDRTreeView -Events $script:RawData
        return
    }

    $filtered = $script:RawData | Where-Object {
        ([string]::IsNullOrWhiteSpace($uFilt) -or $_.User -like "*$uFilt*") -and
        ([string]::IsNullOrWhiteSpace($iFilt) -or $_.EventID -eq $iFilt) -and
        ($null -eq $start -or $_.TimeCreated -ge $start) -and
        ($null -eq $end -or $_.TimeCreated -le $end.AddDays(1)) -and
        ([string]::IsNullOrWhiteSpace($tFilt) -or $_.Details -like "*$tFilt*" -or $_.Image -like "*$tFilt*")
    }
    $grid.ItemsSource = Get-EDRTreeView -Events $filtered
})

$window.FindName('BtnHtmlOpen').Add_Click({
    if ($null -eq $grid.ItemsSource) { return }
    $txtStatus.Text = "Building Report..."
    [System.Windows.Forms.Application]::DoEvents()

    $tempPath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "EDR_Investigation_$(Get-Date -Format 'HHmm').html")
    $html = ConvertTo-HtmlReport -DataItems $grid.ItemsSource
    Set-Content -Path $tempPath -Value $html
    
    Start-Process $tempPath
    $txtStatus.Text = "Report opened."
})

$window.FindName('BtnHtmlSave').Add_Click({
    if ($null -eq $grid.ItemsSource) { return }
    $dlg = [Microsoft.Win32.SaveFileDialog]::new()
    $dlg.Filter = "HTML Files (*.html)|*.html"
    if ($dlg.ShowDialog()) {
        $html = ConvertTo-HtmlReport -DataItems $grid.ItemsSource
        Set-Content -Path $dlg.FileName -Value $html
        $txtStatus.Text = "Exported to $($dlg.FileName)"
    }
})

$window.FindName('BtnClear').Add_Click({
    $script:RawData = @()
    $grid.ItemsSource = $null
    $txtStatus.Text = "Investigation Cleared."
})

$window.ShowDialog() | Out-Null
