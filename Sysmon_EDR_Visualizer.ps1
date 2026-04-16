<#
    Sysmon EDR Visualizer - Pro Edition
    Copyright (c) 2026 [Your Name]
    License: MIT (https://opensource.org/licenses/MIT)

    - Startup Prompt for live logs
    - Hierarchical Process-Activity Trees
    - Chronological Sorting (Newest First)
#>

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

# ------------------------------
# CORE: UNIVERSAL PARSING ENGINE
# ------------------------------
function Get-SysmonEvents {
    param([string]$Path = $null)

    try {
        if ($Path -and $Path.EndsWith(".xml")) {
            $xmlData = [xml](Get-Content $Path)
            $events = $xmlData.SelectNodes("//Event") 
        } elseif ($Path) {
            # Use -Oldest to read them all, but we will sort Descending later for the view
            $events = Get-WinEvent -Path $Path -Oldest | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-Sysmon' }
        } else {
            $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -Oldest -ErrorAction Stop
        }
    } catch { 
        return @() 
    }

    $parsed = foreach ($e in $events) {
        $xml = if ($e.ToXml) { [xml]$e.ToXml() } else { $e }
        $data = @{}
        $eventDataNodes = if ($xml.Event.EventData.Data) { $xml.Event.EventData.Data } else { $e.EventData.Data }
        foreach ($d in $eventDataNodes) { $data[$d.Name] = $d.'#text' }
        
        $id = if ($xml.Event.System.EventID) { $xml.Event.System.EventID } else { $e.Id }
        
        [PSCustomObject]@{
            # Ensure DateTime is sortable
            TimeCreated     = [datetime]($xml.Event.System.TimeCreated.SystemTime ?? $e.TimeCreated)
            EventID         = [int]$id
            Image           = $data.Image ?? "System/Unknown"
            User            = $data.User ?? "N/A"
            Details         = switch($id) {
                1  { "PROCESS START: $($data.CommandLine)" }
                3  { "NETWORK: $($data.SourceIp) -> $($data.DestinationIp):$($data.DestinationPort) ($($data.DestinationHostname))" }
                11 { "FILE CREATE: $($data.TargetFilename)" }
                22 { "DNS QUERY: $($data.QueryName)" }
                12 { "REGISTRY: Created $($data.TargetObject)" }
                13 { "REGISTRY: ValueSet $($data.TargetObject)" }
                default { "Activity ID $id" }
            }
        }
    }
    # Return events sorted NEWEST to OLDEST
    return $parsed | Sort-Object TimeCreated -Descending
}

# ------------------------------
# LOGIC: TREE GENERATOR
# ------------------------------
function Get-EDRTreeView {
    param([object[]]$Events)
    if ($null -eq $Events) { return @() }

    # Ensure the tree builder respects the descending order
    $results = foreach ($item in ($Events | Sort-Object TimeCreated -Descending)) {
        $visual = "$($item.TimeCreated.ToString('HH:mm:ss.fff')) | ID:$($item.EventID) | $($item.Image)`n ┗━━ $($item.Details)"
        
        [PSCustomObject]@{
            Time         = $item.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss.fff")
            User         = $item.User
            EventID      = $item.EventID
            ActivityTree = $visual
        }
    }
    return $results
}

# ------------------------------
# HTML EXPORT ENGINE
# ------------------------------
function Build-HtmlReport {
    param([object[]]$Data)

    $HtmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #f0f2f5; padding: 20px; }
        .container { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        h2 { color: #0078D4; border-bottom: 2px solid #0078D4; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background: #0078D4; color: white; text-align: left; padding: 10px; }
        td { padding: 8px; border-bottom: 1px solid #ddd; font-size: 13px; vertical-align: top; }
        .tree-cell { font-family: 'Consolas', monospace; white-space: pre-wrap; background: #f8f9fa; padding: 5px; border-left: 4px solid #0078D4; display: block; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Sysmon EDR Activity Report (Newest First) - $(Get-Date)</h2>
        <table><thead><tr><th>Time</th><th>User</th><th>ID</th><th>Activity Tree</th></tr></thead><tbody>
"@
    $Rows = foreach ($row in $Data) {
        "<tr><td>$($row.Time)</td><td>$($row.User)</td><td>$($row.EventID)</td><td><span class='tree-cell'>$($row.ActivityTree)</span></td></tr>"
    }
    $HtmlFooter = "</tbody></table></div></body></html>"
    return ($HtmlHeader + ($Rows -join "") + $HtmlFooter)
}

# ------------------------------
# GUI XAML
# ------------------------------
$xaml = @"
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Sysmon EDR Visualizer (Newest First)" Height="850" Width="1350" Background="#F0F2F5">
    <Grid Margin="15">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <Border Grid.Row="0" Background="White" CornerRadius="8" Padding="15" Margin="0,0,0,15">
            <WrapPanel>
                <Button x:Name="BtnLoad" Content="📂 Load File" Width="90" Height="35" Margin="0,0,15,0"/>
                
                <StackPanel Margin="0,0,10,0">
                    <TextBlock Text="Date Range:" FontSize="10" Foreground="#666"/>
                    <StackPanel Orientation="Horizontal">
                        <DatePicker x:Name="DpStart" Width="105"/>
                        <DatePicker x:Name="DpEnd" Width="105" Margin="5,0,0,0"/>
                    </StackPanel>
                </StackPanel>

                <StackPanel Margin="0,0,10,0">
                    <TextBlock Text="Event ID(s):" FontSize="10" Foreground="#666"/>
                    <TextBox x:Name="TbId" Width="60" Height="25" VerticalContentAlignment="Center"/>
                </StackPanel>

                <StackPanel Margin="0,0,15,0">
                    <TextBlock Text="Search Activity:" FontSize="10" Foreground="#666"/>
                    <TextBox x:Name="TbSearch" Width="150" Height="25" VerticalContentAlignment="Center"/>
                </StackPanel>

                <Button x:Name="BtnApply" Content="⚡ Update" Width="80" Height="35" Background="#0078D4" Foreground="White" Margin="0,0,10,0"/>
                <Button x:Name="BtnHtmlOpen" Content="🌐 Open HTML" Width="110" Height="35" Background="#28A745" Foreground="White" Margin="0,0,5,0"/>
                <Button x:Name="BtnHtmlSave" Content="💾 Save HTML" Width="110" Height="35" Background="#6c757d" Foreground="White"/>
            </WrapPanel>
        </Border>

        <DataGrid x:Name="GridEvents" Grid.Row="1" AutoGenerateColumns="False" IsReadOnly="True" FontFamily="Consolas">
            <DataGrid.Columns>
                <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="180"/>
                <DataGridTextColumn Header="User" Binding="{Binding User}" Width="150"/>
                <DataGridTextColumn Header="ID" Binding="{Binding EventID}" Width="50"/>
                <DataGridTextColumn Header="Activity Tree" Binding="{Binding ActivityTree}" Width="*"/>
            </DataGrid.Columns>
        </DataGrid>

        <StatusBar Grid.Row="2" Background="Transparent" Margin="0,5,0,0">
            <StatusBarItem><TextBlock x:Name="TxtStatus" Text="Ready"/></StatusBarItem>
        </StatusBar>
    </Grid>
</Window>
"@

$reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

$btnLoad = $window.FindName('BtnLoad'); $btnApply = $window.FindName('BtnApply')
$btnHtmlOpen = $window.FindName('BtnHtmlOpen'); $btnHtmlSave = $window.FindName('BtnHtmlSave')
$grid = $window.FindName('GridEvents'); $txtStatus = $window.FindName('TxtStatus')
$dpStart = $window.FindName('DpStart'); $dpEnd = $window.FindName('DpEnd')
$tbId = $window.FindName('TbId'); $tbSearch = $window.FindName('TbSearch')

$script:RawData = @()

# --- INITIAL PROMPT ---
$window.Add_Loaded({
    $msg = "Do you want to open the current sysmon events?`n`nNote: Logs will be sorted newest first."
    $response = [System.Windows.MessageBox]::Show($msg, "Load Live Logs", "YesNo", "Question")

    if ($response -eq 'Yes') {
        $txtStatus.Text = "Status: Parsing live Sysmon logs..."
        $script:RawData = Get-SysmonEvents
        if ($script:RawData.Count -eq 0) {
            [System.Windows.MessageBox]::Show("Could not access live logs. Ensure you are running as Administrator.")
        } else {
            $grid.ItemsSource = Get-EDRTreeView -Events $script:RawData
            $txtStatus.Text = "Status: Loaded $($script:RawData.Count) live events (Newest First)."
        }
    }
})

$btnLoad.Add_Click({
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    if ($dlg.ShowDialog()) {
        $script:RawData = Get-SysmonEvents -Path $dlg.FileName
        $grid.ItemsSource = Get-EDRTreeView -Events $script:RawData
        $txtStatus.Text = "Status: Loaded from file (Newest First)."
    }
})

$btnApply.Add_Click({
    $idArray = if ($tbId.Text) { $tbId.Text.Split(',').Trim() } else { $null }
    $searchFilt = $tbSearch.Text
    $start = $dpStart.SelectedDate
    $end = if ($dpEnd.SelectedDate) { $dpEnd.SelectedDate.AddDays(1) } else { $null }

    $filtered = $script:RawData | Where-Object {
        $pass = $true
        if ($idArray) { if ($idArray -notcontains $_.EventID) { $pass = $false } }
        if ($start) { if ($_.TimeCreated -lt $start) { $pass = $false } }
        if ($end) { if ($_.TimeCreated -ge $end) { $pass = $false } }
        $pass
    }
    # Ensure final view maintains Newest First
    $results = Get-EDRTreeView -Events $filtered
    if ($searchFilt) { $results = $results | Where-Object { $_.ActivityTree -like "*$searchFilt*" } }
    $grid.ItemsSource = $results
})

$btnHtmlOpen.Add_Click({
    if ($grid.ItemsSource) {
        $html = Build-HtmlReport -Data $grid.ItemsSource
        $TempPath = [System.IO.Path]::GetTempFileName() + ".html"
        $html | Out-File -FilePath $TempPath -Encoding utf8
        Start-Process $TempPath
    }
})

$btnHtmlSave.Add_Click({
    if ($grid.ItemsSource) {
        $dlg = New-Object Microsoft.Win32.SaveFileDialog
        $dlg.Filter = "HTML Files (*.html)|*.html"
        if ($dlg.ShowDialog()) {
            $html = Build-HtmlReport -Data $grid.ItemsSource
            $html | Out-File -FilePath $dlg.FileName -Encoding utf8
        }
    }
})

$window.ShowDialog() | Out-Null
