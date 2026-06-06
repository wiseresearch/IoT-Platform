param(
    [string]$Server = "http://localhost:8080",
    [int]$IntervalSeconds = 0
)

function Get-PrimaryIpInfo {
    $excludePattern = 'Hyper-V|Virtual|VMware|VirtualBox|Loopback|Bluetooth|TAP|WSL|Docker|vEthernet'
    $candidates = Get-NetIPConfiguration `
        | Where-Object {
            $_.IPv4Address -and $_.IPv4DefaultGateway -and $_.NetAdapter -and $_.NetAdapter.Status -eq 'Up'
        } `
        | Where-Object {
            $_.NetAdapter.InterfaceDescription -notmatch $excludePattern
        }

    $best = $null
    if ($candidates) {
        $best = $candidates | Select-Object -First 1
    }

    if (-not $best) {
        $ip = Get-NetIPAddress -AddressFamily IPv4 `
            | Where-Object { $_.IPAddress -notlike "169.254.*" -and $_.IPAddress -ne "127.0.0.1" } `
            | Select-Object -First 1
        if (-not $ip) {
            return $null
        }
        $adapter = Get-NetAdapter -InterfaceIndex $ip.InterfaceIndex -ErrorAction SilentlyContinue
        return [PSCustomObject]@{
            IpAddress = $ip.IPAddress
            MacAddress = if ($adapter) { $adapter.MacAddress } else { "" }
        }
    }

    return [PSCustomObject]@{
        IpAddress = $best.IPv4Address.IPAddress
        MacAddress = $best.NetAdapter.MacAddress
    }
}

function Send-Report {
    $ipInfo = Get-PrimaryIpInfo
    if (-not $ipInfo) {
        Write-Host "No valid IPv4 address found."
        return
    }

    $os = Get-CimInstance Win32_OperatingSystem
    $caption = $os.Caption
    $version = $os.Version
    $build = $os.BuildNumber

    $payload = @{
        ip_address = $ipInfo.IpAddress
        mac_address = $ipInfo.MacAddress
        hostname = $env:COMPUTERNAME
        os_name = "Windows"
        os_version = "$caption $version (Build $build)"
        vendor = "Microsoft"
        device_type = "Managed Agent"
    }

    $uri = "$Server/api/agent/report"
    try {
        $json = $payload | ConvertTo-Json
        $resp = Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $json
        Write-Host "Report sent: $($resp.status)"
    } catch {
        Write-Host "Failed to send report: $($_.Exception.Message)"
    }
}

if ($IntervalSeconds -gt 0) {
    while ($true) {
        Send-Report
        Start-Sleep -Seconds $IntervalSeconds
    }
} else {
    Send-Report
}
