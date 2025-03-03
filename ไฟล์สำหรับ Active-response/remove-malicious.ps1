################################
## Script to remove malicious IOC for detection in MISP
################################
# Read the alert that triggered the active response from the manager
$INPUT_JSON = Read-Host
# Convert the JSON input to a PowerShell object (no need to convert twice)
$INPUT_ARRAY = $INPUT_JSON | ConvertFrom-Json

# Suppress error messages
$ErrorActionPreference = "SilentlyContinue"

# Define the log file path (updated path)
$logFile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

# Extract the command and host IP from the input
$command = $INPUT_ARRAY.command
$hostip = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.DHCPEnabled -and $_.DefaultIPGateway }).IPAddress | Select-Object -First 1

# Extract IOC (Indicator of Compromise) details from the input
$IOCvalue = $INPUT_ARRAY.parameters.alert.data.misp.value
$IOCtype = $INPUT_ARRAY.parameters.alert.data.misp.type
$IOCdescription = $INPUT_ARRAY.parameters.alert.data.misp.source.description

# If the IOC value is not an array, wrap it in an array for proper looping
if ($IOCvalue -isnot [System.Array]) {
    $IOCvalue = @($IOCvalue)
}

################################
# Deduplication settings for domain IOC events
################################
# Define a cache file to store processed domains and a threshold (in minutes)
$cacheFile = "C:\Program Files (x86)\ossec-agent\active-response\blocked_cache.txt"
$cacheThresholdMinutes = 5

# Ensure the cache file exists
if (-not (Test-Path $cacheFile)) {
    New-Item -Path $cacheFile -ItemType File -Force | Out-Null
}

################################
# Process based on the IOC type
################################

if ($IOCtype -eq 'ip' -or $IOCtype -eq 'ip-src' -or $IOCtype -eq 'ip-dst') {
    foreach ($ip in $IOCvalue) {
        # Check if a firewall rule for this IP already exists
        $existingRule = Get-NetFirewallRule -DisplayName "Wazuh Active Response - $ip" -ErrorAction SilentlyContinue
        if ($command -eq 'add' -and $ip -ne '127.0.0.1' -and $ip -ne '0.0.0.0' -and $ip -ne $hostip -and -not $existingRule) {
            # Add a new firewall rule to block the IP
            New-NetFirewallRule -DisplayName "Wazuh Active Response - $ip" -Direction Outbound -LocalPort Any -Protocol Any -Action Block -RemoteAddress $ip
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $ip added to blocklist via Windows Firewall" | Out-File -FilePath $logFile -Append -Encoding ascii
        } elseif ($command -eq 'delete' -and $ip -ne '127.0.0.1' -and $ip -ne '0.0.0.0' -and $ip -ne $hostip -and $existingRule) {
            # Remove the existing firewall rule for the IP
            Remove-NetFirewallRule -DisplayName "Wazuh Active Response - $ip"
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $ip removed from blocklist via Windows Firewall" | Out-File -FilePath $logFile -Append -Encoding ascii
        }
    }
} elseif ($IOCtype -eq 'domain') {
    foreach ($domain in $IOCvalue) {
        $processDomain = $true
        $cacheEntries = @{}
        # Read the cache file content
        $cacheContent = @()
        if (Test-Path $cacheFile) {
            $cacheContent = Get-Content $cacheFile
        }
        # Parse cache file lines formatted as "domain,timestamp"
        foreach ($line in $cacheContent) {
            if ($line -match "^(.*?),(.*)$") {
                $cachedDomain = $matches[1]
                $cachedTime = [datetime]$matches[2]
                $cacheEntries[$cachedDomain] = $cachedTime
            }
        }
        # Check if the domain was processed recently
        if ($cacheEntries.ContainsKey($domain)) {
            $lastTime = $cacheEntries[$domain]
            $diff = (Get-Date) - $lastTime
            if ($diff.TotalMinutes -lt $cacheThresholdMinutes) {
                $processDomain = $false
            }
        }
        if ($processDomain) {
            # Update the cache: set/update the timestamp for this domain
            $cacheEntries[$domain] = Get-Date
            # Write the updated cache back to the file
            $cacheEntries.GetEnumerator() | ForEach-Object { "$($_.Key),$($_.Value)" } | Out-File -FilePath $cacheFile -Encoding ascii
            # Resolve the domain to IP addresses
            $resolvedIPs = (Resolve-DnsName $domain -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress)
            if ($resolvedIPs) {
                foreach ($ip in $resolvedIPs) {
                    # Check if a firewall rule for this IP already exists
                    $existingRule = Get-NetFirewallRule -DisplayName "Wazuh Active Response - $ip" -ErrorAction SilentlyContinue
                    if ($command -eq 'add' -and $ip -ne '127.0.0.1' -and $ip -ne '0.0.0.0' -and $ip -ne $hostip -and -not $existingRule) {
                        New-NetFirewallRule -DisplayName "Wazuh Active Response - $ip" -Direction Outbound -LocalPort Any -Protocol Any -Action Block -RemoteAddress $ip
                        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $ip (resolved from $domain) added to blocklist via Windows Firewall" | Out-File -FilePath $logFile -Append -Encoding ascii
                    } elseif ($command -eq 'delete' -and $existingRule) {
                        Remove-NetFirewallRule -DisplayName "Wazuh Active Response - $ip"
                        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $ip (resolved from $domain) removed from blocklist via Windows Firewall" | Out-File -FilePath $logFile -Append -Encoding ascii
                    }
                }
            } else {
                "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Could not resolve domain $domain" | Out-File -FilePath $logFile -Append -Encoding ascii
            }
        } else {
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Domain $domain was processed recently, skipping" | Out-File -FilePath $logFile -Append -Encoding ascii
        }
    }
} elseif ($IOCtype -eq 'md5' -or $IOCtype -eq 'sha1' -or $IOCtype -eq 'sha256') {
    # For hash types (md5, sha1, sha256)
    # Extract file path from IOC description using a regex pattern (searching for 'FileCreate' in the description)
    $pathPattern = "[C-Z]:.*?(?=\sFileCreate)"
    $pathMatches = [regex]::Matches($IOCdescription, $pathPattern) | Select-Object -First 1
    $pathmalicious = if ($pathMatches) { $pathMatches.Value } else { "Path not found in description" }
    if (Test-Path $pathmalicious) {
        Remove-Item -Path $pathmalicious -Force
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - File $pathmalicious deleted" | Out-File -FilePath $logFile -Append -Encoding ascii
    } else {
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - File $pathmalicious not found" | Out-File -FilePath $logFile -Append -Encoding ascii
    }
}
