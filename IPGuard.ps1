$appName = "IPGuard"
$npmFiles = @("whatismyip", "dos2unix")
$configFileName = "$appName.ini"
$hostname = $([System.Net.Dns]::GetHostName()).ToUpper()
$moduleNames = @()
$logDir = "/logs"

# Function to read an INI file and return its contents as a hash table

function Parse-IniFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $content = Get-Content -Path $Path -Raw
    $lines = $content -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_ -notmatch '^#' -and $_ -ne '' }

    $result = @{}

    foreach ($line in $lines) {
        $pos = $line.IndexOf('=')
        if ($pos -gt 0) {
            $key = $line.Substring(0, $pos).Trim()
            $value = $line.Substring($pos + 1).Trim()
            $result[$key] = $value
        }
    }

    return $result
}

# Function to check if an npm package is installed and install it if necessary

function npmCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$npmApps
    )
    foreach ($app in $npmApps) {
        if (-not (npm list -g --depth 0 | Select-String $app)) {
            # Log that the package is being installed

            $stream.WriteLine("[{0:yyyyMMdd_HHmm}] {1} not installed. Installing now...", [DateTime]::Now, $app)

            # Install the package

            npm install -g $app -y
        }
    }
}

# Function to check if a Powershell module is installed and install it if necessary

function Check-ModulesInstalled {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Modules
    )

    foreach ($module in $Modules) {
        if (-not (Get-Module -Name $module -ErrorAction SilentlyContinue)) {
            $stream.WriteLine("Module '$module' is not installed. Importing module...")
            Install-Module -Name $module -Force -ErrorAction SilentlyContinue
            Import-Module -Name $module -Force -ErrorAction SilentlyContinue
        }
    }
}

# Define the path of the log file

if (-not (Test-Path $logDir)) {
    mkdir $logDir 2>nul
}
$logPath = "$($logDir)\$(Get-Date -Format 'yyyyMMdd').log"

# Create or append to the log file

if (-not (Test-Path $logPath)) {
    New-Item -Path $logPath -ItemType File | Out-Null
}
$stream = [System.IO.StreamWriter]::new($logPath, $true)

try {
    # Check for required npm packages

    npmCheck $npmFiles

    # Check for the config.ini file and create a default one if it doesn't exist

    $configPath = Join-Path -Path $PSScriptRoot -ChildPath $configFileName
    if (-not (Test-Path $configPath)) {
        $defaultConfig = @"
REAL_IP=x.x.x.x
VPN_IP=x.x.x.x
KILL=notepad.exe,calc.exe
FORCED=true
"@
        $defaultConfig | Out-File -Encoding ASCII -Path $configPath
        Start-Process -FilePath "npm" -ArgumentList "run", "dos2unix", "--", "-n", "$configPath" -Wait
    }

    # Config Powershell Modules are installed
    If ($moduleNames) { Check-ModulesInstalled $moduleNames }

    # Read the config.ini file
    $config = $(Parse-IniFile -Path "IPGuard.ini")

    # Get the REAL_IP and VPN_IP values from the config

    $realIP = $config.REAL_IP
    $vpnIP = $config.VPN_IP

    # Log the REAL_IP and VPN_IP values

    $stream.WriteLine("[{0:yyyyMMdd_HHmm}] REAL_IP = {1}", [DateTime]::Now, $realIP)
    $stream.WriteLine("[{0:yyyyMMdd_HHmm}] VPN_IP = {1}", [DateTime]::Now, $vpnIP)

    # Check if the config was forced to be generated and restart the computer if necessary

    if ($config.FORCED -eq "true") {
        $stream.WriteLine("[{0:yyyyMMdd_HHmm}] Config was generated or updated with FORCED=true. Restarting computer.", [DateTime]::Now)
        Restart-Computer -Force
    }

    # Run the "whatismyip" command and capture the output

    $ipOutput = & whatismyip

    # Extract the IP address from the output using regex

    $ipRegex = [regex] "[^0-9\.]"
    $ip = $ipRegex.Replace($ipOutput, "")
    $vpnIP = $vpnIP.Trim()
    $realIP = $realIP.Trim()
    $ip = $ip.Trim()

    # Log the IP address

    $stream.WriteLine("[{0:yyyyMMdd_HHmm}] IP = {1}", [DateTime]::Now, $ip)

    $vpnStatus = $false
    $realIPMatch = $($ip -eq $realIP)
    $vpnIPMatch = $($ip -eq $vpnIP)
    if ($(-not $realIPMatch) -or $(vpnIPMatch)) {
        $vpnStatus = $true
    }

    # Check if the IP matches the REAL_IP

    if (-not $vpnStatus) {
        # Kill the specified processes

        $killList = $config.KILL -split ","
        foreach ($processName in $killList) {
            taskkill -IM $processName -F 2>nul
            Stop-Process -Name $processName -Force -ErrorAction SilentlyContinue | Out-Null
        }

        # Log the success message

        $stream.WriteLine("[{0:yyyyMMdd_HHmm}] IP matches REAL_IP. Processes killed.", [DateTime]::Now)

    }
    else {
        if ($vpnIPMatch) {
            $stream.WriteLine("[{0:yyyyMMdd_HHmm}] IP matches VPN_IP.  ALL CLEAR!", [DateTime]::Now)
        }
        else {
            $stream.WriteLine("[{0:yyyyMMdd_HHmm}] IP does not match REAL_IP or VPN_IP.  But Can Continue!", [DateTime]::Now)
        }
    }
}
catch {
    # Log the error

    $stream.WriteLine("[{0:yyyyMMdd_HHmm}] ERROR: {1}", [DateTime]::Now, $_.Exception.Message)
    try {
        # Send the failure notification

        Send-Notification -Message "$appName [$hostname] - FAILURE - $(Get-Date -Format 'yyyy.MM.dd HH:mm (zzz)') [$([TimeZoneInfo]::Local.DisplayName)]" -Result $false
    }
    catch {
        # Ignore any errors that occur while sending the notification

    }

    # Restart the computer

    Restart-Computer -Force

}
finally {
    # Close the log file
    
    $stream.Close()
}
# SIG # Begin signature block
# MIItFwYJKoZIhvcNAQcCoIItCDCCLQQCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCDC0//sOZstZ35
# /Xz0E1FrIuTY6esVWjYJNagYO2rEIKCCEhkwggVvMIIEV6ADAgECAhBI/JO0YFWU
# jTanyYqJ1pQWMA0GCSqGSIb3DQEBDAUAMHsxCzAJBgNVBAYTAkdCMRswGQYDVQQI
# DBJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcMB1NhbGZvcmQxGjAYBgNVBAoM
# EUNvbW9kbyBDQSBMaW1pdGVkMSEwHwYDVQQDDBhBQUEgQ2VydGlmaWNhdGUgU2Vy
# dmljZXMwHhcNMjEwNTI1MDAwMDAwWhcNMjgxMjMxMjM1OTU5WjBWMQswCQYDVQQG
# EwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS0wKwYDVQQDEyRTZWN0aWdv
# IFB1YmxpYyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQCN55QSIgQkdC7/FiMCkoq2rjaFrEfUI5ErPtx94jGgUW+s
# hJHjUoq14pbe0IdjJImK/+8Skzt9u7aKvb0Ffyeba2XTpQxpsbxJOZrxbW6q5KCD
# J9qaDStQ6Utbs7hkNqR+Sj2pcaths3OzPAsM79szV+W+NDfjlxtd/R8SPYIDdub7
# P2bSlDFp+m2zNKzBenjcklDyZMeqLQSrw2rq4C+np9xu1+j/2iGrQL+57g2extme
# me/G3h+pDHazJyCh1rr9gOcB0u/rgimVcI3/uxXP/tEPNqIuTzKQdEZrRzUTdwUz
# T2MuuC3hv2WnBGsY2HH6zAjybYmZELGt2z4s5KoYsMYHAXVn3m3pY2MeNn9pib6q
# RT5uWl+PoVvLnTCGMOgDs0DGDQ84zWeoU4j6uDBl+m/H5x2xg3RpPqzEaDux5mcz
# mrYI4IAFSEDu9oJkRqj1c7AGlfJsZZ+/VVscnFcax3hGfHCqlBuCF6yH6bbJDoEc
# QNYWFyn8XJwYK+pF9e+91WdPKF4F7pBMeufG9ND8+s0+MkYTIDaKBOq3qgdGnA2T
# OglmmVhcKaO5DKYwODzQRjY1fJy67sPV+Qp2+n4FG0DKkjXp1XrRtX8ArqmQqsV/
# AZwQsRb8zG4Y3G9i/qZQp7h7uJ0VP/4gDHXIIloTlRmQAOka1cKG8eOO7F/05QID
# AQABo4IBEjCCAQ4wHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQwHQYD
# VR0OBBYEFDLrkpr/NZZILyhAQnAgNpFcF4XmMA4GA1UdDwEB/wQEAwIBhjAPBgNV
# HRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMDMBsGA1UdIAQUMBIwBgYE
# VR0gADAIBgZngQwBBAEwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21v
# ZG9jYS5jb20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEE
# KDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZI
# hvcNAQEMBQADggEBABK/oe+LdJqYRLhpRrWrJAoMpIpnuDqBv0WKfVIHqI0fTiGF
# OaNrXi0ghr8QuK55O1PNtPvYRL4G2VxjZ9RAFodEhnIq1jIV9RKDwvnhXRFAZ/ZC
# J3LFI+ICOBpMIOLbAffNRk8monxmwFE2tokCVMf8WPtsAO7+mKYulaEMUykfb9gZ
# pk+e96wJ6l2CxouvgKe9gUhShDHaMuwV5KZMPWw5c9QLhTkg4IUaaOGnSDip0TYl
# d8GNGRbFiExmfS9jzpjoad+sPKhdnckcW67Y8y90z7h+9teDnRGWYpquRRPaf9xH
# +9/DUp/mBlXpnYzyOmJRvOwkDynUWICE5EV7WtgwggYaMIIEAqADAgECAhBiHW0M
# UgGeO5B5FSCJIRwKMA0GCSqGSIb3DQEBDAUAMFYxCzAJBgNVBAYTAkdCMRgwFgYD
# VQQKEw9TZWN0aWdvIExpbWl0ZWQxLTArBgNVBAMTJFNlY3RpZ28gUHVibGljIENv
# ZGUgU2lnbmluZyBSb290IFI0NjAeFw0yMTAzMjIwMDAwMDBaFw0zNjAzMjEyMzU5
# NTlaMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxKzAp
# BgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYwggGiMA0G
# CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCbK51T+jU/jmAGQ2rAz/V/9shTUxjI
# ztNsfvxYB5UXeWUzCxEeAEZGbEN4QMgCsJLZUKhWThj/yPqy0iSZhXkZ6Pg2A2NV
# DgFigOMYzB2OKhdqfWGVoYW3haT29PSTahYkwmMv0b/83nbeECbiMXhSOtbam+/3
# 6F09fy1tsB8je/RV0mIk8XL/tfCK6cPuYHE215wzrK0h1SWHTxPbPuYkRdkP05Zw
# mRmTnAO5/arnY83jeNzhP06ShdnRqtZlV59+8yv+KIhE5ILMqgOZYAENHNX9SJDm
# +qxp4VqpB3MV/h53yl41aHU5pledi9lCBbH9JeIkNFICiVHNkRmq4TpxtwfvjsUe
# dyz8rNyfQJy/aOs5b4s+ac7IH60B+Ja7TVM+EKv1WuTGwcLmoU3FpOFMbmPj8pz4
# 4MPZ1f9+YEQIQty/NQd/2yGgW+ufflcZ/ZE9o1M7a5Jnqf2i2/uMSWymR8r2oQBM
# dlyh2n5HirY4jKnFH/9gRvd+QOfdRrJZb1sCAwEAAaOCAWQwggFgMB8GA1UdIwQY
# MBaAFDLrkpr/NZZILyhAQnAgNpFcF4XmMB0GA1UdDgQWBBQPKssghyi47G9IritU
# pimqF6TNDDAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNV
# HSUEDDAKBggrBgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEsG
# A1UdHwREMEIwQKA+oDyGOmh0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1B1
# YmxpY0NvZGVTaWduaW5nUm9vdFI0Ni5jcmwwewYIKwYBBQUHAQEEbzBtMEYGCCsG
# AQUFBzAChjpodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2Rl
# U2lnbmluZ1Jvb3RSNDYucDdjMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0
# aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAgEABv+C4XdjNm57oRUgmxP/BP6YdURh
# w1aVcdGRP4Wh60BAscjW4HL9hcpkOTz5jUug2oeunbYAowbFC2AKK+cMcXIBD0Zd
# OaWTsyNyBBsMLHqafvIhrCymlaS98+QpoBCyKppP0OcxYEdU0hpsaqBBIZOtBajj
# cw5+w/KeFvPYfLF/ldYpmlG+vd0xqlqd099iChnyIMvY5HexjO2AmtsbpVn0OhNc
# WbWDRF/3sBp6fWXhz7DcML4iTAWS+MVXeNLj1lJziVKEoroGs9Mlizg0bUMbOalO
# hOfCipnx8CaLZeVme5yELg09Jlo8BMe80jO37PU8ejfkP9/uPak7VLwELKxAMcJs
# zkyeiaerlphwoKx1uHRzNyE6bxuSKcutisqmKL5OTunAvtONEoteSiabkPVSZ2z7
# 6mKnzAfZxCl/3dq3dUNw4rg3sTCggkHSRqTqlLMS7gjrhTqBmzu1L90Y1KWN/Y5J
# KdGvspbOrTfOXyXvmPL6E52z1NZJ6ctuMFBQZH3pwWvqURR8AgQdULUvrxjUYbHH
# j95Ejza63zdrEcxWLDX6xWls/GDnVNueKjWUH3fTv1Y8Wdho698YADR7TNx8X8z2
# Bev6SivBBOHY+uqiirZtg0y9ShQoPzmCcn63Syatatvx157YK9hlcPmVoa1oDE5/
# L9Uo2bC5a4CH2RwwggaEMIIE7KADAgECAhEA0Y0TWS9vO4B3vbjiNXGZ3TANBgkq
# hkiG9w0BAQwFADBUMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1p
# dGVkMSswKQYDVQQDEyJTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0EgUjM2
# MB4XDTIxMDgwNDAwMDAwMFoXDTI0MDgwMzIzNTk1OVowYjELMAkGA1UEBhMCVVMx
# FzAVBgNVBAgMDlNvdXRoIENhcm9saW5hMRwwGgYDVQQKDBNDbGFya1RyaWJlR2Ft
# ZXMgTExDMRwwGgYDVQQDDBNDbGFya1RyaWJlR2FtZXMgTExDMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAsWq+FQC3gUtU6+xGA22uuBSTeRE6ydR5s2Xm
# jDXE+obKFJnn46Cuho01xjFz6DMYk3ddzjSJBFtjBzm1Lv5rJBceZkJ9w/xMdT1o
# QE6KEUcm6cCHo8gUdGgdS/ZDzb2Yz7stuAwXJ6J9AUn1aM4WTOmNY9jCI2qTE1eR
# fLVLDra/FL4rM0OIyNaccGLo7R6hP8EZlkIYFB1slKmyf/NsD+gDGgOltmzg2ONf
# /qOZk7v/TL0eoGIj4ptHz4lkU/esyl8h1cA9tLRfj6kECjoHMNlaMLRSS9kyK/jw
# ODUZdXNuxWQ47UJZIFzGGIdpjPX52LrmoyZ+yjMB6nZFlwesKO3MWi+BaCuflqJy
# SICeoprGKrgkAZEwV4JTpAnHhD+tEVCV9wempEIl+aSAkzUB3QDSrKzbbBIKXUcN
# 7+NoaYyry3x0orPoCQEKH6Z9XMeDw3C4p4k7seC+WodP86QgSrBmqfwHIEhHm7F8
# kvWK5twCBSYy4/mo+fuC3aWLWLEE/DX+r+CGB6wHVifG7UBXZJVscDZ2nTHe+x+c
# H10QqylE4ap1phNz7yNqpE8cU28PV/14E8ykgq1PBrjgak+W5JkeT4ojTc2gdw8z
# R6auAoVaURl2CfBHjEBadNLHd6/7iF2IP9QcGsu3gV7cnjZOhjfgNg8b44yQfDGw
# ooMFIlkCAwEAAaOCAcEwggG9MB8GA1UdIwQYMBaAFA8qyyCHKLjsb0iuK1SmKaoX
# pM0MMB0GA1UdDgQWBBTXOhBp1AUGSSRdIUi0A8LEBund4jAOBgNVHQ8BAf8EBAMC
# B4AwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDAzARBglghkgBhvhC
# AQEEBAMCBBAwSgYDVR0gBEMwQTA1BgwrBgEEAbIxAQIBAwIwJTAjBggrBgEFBQcC
# ARYXaHR0cHM6Ly9zZWN0aWdvLmNvbS9DUFMwCAYGZ4EMAQQBMEkGA1UdHwRCMEAw
# PqA8oDqGOGh0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY0NvZGVT
# aWduaW5nQ0FSMzYuY3JsMHkGCCsGAQUFBwEBBG0wazBEBggrBgEFBQcwAoY4aHR0
# cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25pbmdDQVIz
# Ni5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMCMGA1Ud
# EQQcMBqBGGluZm9AY2xhcmt0cmliZWdhbWVzLmNvbTANBgkqhkiG9w0BAQwFAAOC
# AYEAHW3WDcsFWd8ke3KliEPuCeQJjXVvRzh4uAYDKlJrj7bGbWk4gPr/9Sa+5QLI
# PdhCLq7hYC4L98fnC9q+tI0ZiG0S7Lf9U90FQAnt5m3RufnPo34h7/Ba7Ql+SM+h
# lhr8zndS7yekXRCRu3U6WZmvdlqr7jiZ9OsQ8d1uUIubiYIkwDcg17gOzj3FPihV
# Es1k+IW2+GZRCiKqbBFqK9jL6k0wKLOaY8FDXIl7Kf/Li7eIPfbyM0VHzgCDy/mq
# cvtEtkT6aNB88wWSFK5qsOECwXefLmm4GYM2BuOKT92yAWldCADqHtg7pJ8VHzGo
# D2a6f6ocm+CXwh76uHEWY/N952Kgeh9dGp3WSUQghiXnBc4ZOl1z9afxj4kkE9pF
# Wr9iWntogKBoU24OH0xGYOn8mIQo0+n441pvyePfTQWz0D9TouszDRIHWQK/93/h
# oyI2NbAYs1fVEjqFPfVPMyGuzRdHVk1X4NpFLihbOlbUt4cv1GXW5XpJY6HEc30v
# jinKMYIaVDCCGlACAQEwaTBUMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGln
# byBMaW1pdGVkMSswKQYDVQQDEyJTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcg
# Q0EgUjM2AhEA0Y0TWS9vO4B3vbjiNXGZ3TANBglghkgBZQMEAgEFAKB8MBAGCisG
# AQQBgjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQB
# gjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDThkrfiLA5r1jH
# Wd7Nesob6twsOcaiwd18cuGtQl5hqDANBgkqhkiG9w0BAQEFAASCAgAJXOolgWLn
# v61XFl1Vbd0Sm0xDrHYqPToaXXH4huOMqch0VGw55MbQtbZiGvlFX9Su0FeSSaS3
# vpA8zlYc+XJFYEsQ2eFrvtnMmld8yxkJVrl740d+O4qN6vzWPRCzIDons9PblwsA
# tVPQvZVSIAObpK4GiacS2LwMc1PNIPj2mD+XVwVnudnxUDxBs9odFYjtrHwkfiom
# ExfZ7sNTaAbw/ppvYiribQIXIVrJsrGJ85cdWRklS8YkNcaWETcCvNkXNT1PEZsl
# xnNB9YCmjX4b45OqnLYmtkM2UXiV3QZgly4eolCr/DSLPxJOLGi3pFKyjzkNpF9y
# Rlr8O47L/CEq1yHmjmftkhKj5SKb7weRge7gckfm6A8gLSng8vQSDs0hEGohmqLs
# 6l8Jcr1W87Jo5bSqINxzkndPhEW2kTsd5MPL7WbbcGQGeZ2Lb/X9ftxsh8IM5GSe
# 5Cg+123gWzujvfDtAXLzsO+j3oyn4MtJkAMPjKt0h8511UCv9UuTvy8mVJldk/5P
# hYf6IdhwCY1K0XaC83GE9Gfg+Vm1uLEnjc5LcTTvb+zG6xDoG3sF2BhHzLfYvxWT
# Gl480ih75rYyP4S/2szaJtoUfn0Qp1p++IF9vpPqdlaOHPKnFQ9QDl25rK8euY+r
# dRmirX5Z4MflNlLrr9oJXcqW/Awwj/QBEaGCFz4wghc6BgorBgEEAYI3AwMBMYIX
# KjCCFyYGCSqGSIb3DQEHAqCCFxcwghcTAgEDMQ8wDQYJYIZIAWUDBAIBBQAweAYL
# KoZIhvcNAQkQAQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUA
# BCB0VpS3yjuvbY9u9BjLsh+usO0LkZPq7LKSaWFV7xsQMgIRAITRAWPXx3Y/zuwC
# 4maNHyQYDzIwMjMwMzI3MTg0ODM4WqCCEwcwggbAMIIEqKADAgECAhAMTWlyS5T6
# PCpKPSkHgD1aMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBS
# U0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjIwOTIxMDAwMDAwWhcN
# MzMxMTIxMjM1OTU5WjBGMQswCQYDVQQGEwJVUzERMA8GA1UEChMIRGlnaUNlcnQx
# JDAiBgNVBAMTG0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIyIC0gMjCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBAM/spSY6xqnya7uNwQ2a26HoFIV0MxomrNAc
# VR4eNm28klUMYfSdCXc9FZYIL2tkpP0GgxbXkZI4HDEClvtysZc6Va8z7GGK6aYo
# 25BjXL2JU+A6LYyHQq4mpOS7eHi5ehbhVsbAumRTuyoW51BIu4hpDIjG8b7gL307
# scpTjUCDHufLckkoHkyAHoVW54Xt8mG8qjoHffarbuVm3eJc9S/tjdRNlYRo44DL
# annR0hCRRinrPibytIzNTLlmyLuqUDgN5YyUXRlav/V7QG5vFqianJVHhoV5Pgxe
# ZowaCiS+nKrSnLb3T254xCg/oxwPUAY3ugjZNaa1Htp4WB056PhMkRCWfk3h3cKt
# pX74LRsf7CtGGKMZ9jn39cFPcS6JAxGiS7uYv/pP5Hs27wZE5FX/NurlfDHn88JS
# xOYWe1p+pSVz28BqmSEtY+VZ9U0vkB8nt9KrFOU4ZodRCGv7U0M50GT6Vs/g9Arm
# FG1keLuY/ZTDcyHzL8IuINeBrNPxB9ThvdldS24xlCmL5kGkZZTAWOXlLimQprdh
# ZPrZIGwYUWC6poEPCSVT8b876asHDmoHOWIZydaFfxPZjXnPYsXs4Xu5zGcTB5rB
# eO3GiMiwbjJ5xwtZg43G7vUsfHuOy2SJ8bHEuOdTXl9V0n0ZKVkDTvpd6kVzHIR+
# 187i1Dp3AgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIw
# ADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgGBmeBDAEEAjAL
# BglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxqII+eyG8wHQYD
# VR0OBBYEFGKK3tBh/I8xFO2XC809KpQU31KcMFoGA1UdHwRTMFEwT6BNoEuGSWh0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZT
# SEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGDMIGAMCQGCCsG
# AQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYBBQUHMAKGTGh0
# dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQw
# OTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggIBAFWq
# KhrzRvN4Vzcw/HXjT9aFI/H8+ZU5myXm93KKmMN31GT8Ffs2wklRLHiIY1UJRjkA
# /GnUypsp+6M/wMkAmxMdsJiJ3HjyzXyFzVOdr2LiYWajFCpFh0qYQitQ/Bu1nggw
# CfrkLdcJiXn5CeaIzn0buGqim8FTYAnoo7id160fHLjsmEHw9g6A++T/350Qp+sA
# ul9Kjxo6UrTqvwlJFTU2WZoPVNKyG39+XgmtdlSKdG3K0gVnK3br/5iyJpU4GYhE
# FOUKWaJr5yI+RCHSPxzAm+18SLLYkgyRTzxmlK9dAlPrnuKe5NMfhgFknADC6Vp0
# dQ094XmIvxwBl8kZI4DXNlpflhaxYwzGRkA7zl011Fk+Q5oYrsPJy8P7mxNfarXH
# 4PMFw1nfJ2Ir3kHJU7n/NBBn9iYymHv+XEKUgZSCnawKi8ZLFUrTmJBFYDOA4CPe
# +AOk9kVH5c64A0JH6EE2cXet/aLol3ROLtoeHYxayB6a1cLwxiKoT5u92ByaUcQv
# mvZfpyeXupYuhVfAYOd4Vn9q78KVmksRAsiCnMkaBXy6cbVOepls9Oie1FqYyJ+/
# jbsYXEP10Cro4mLueATbvdH7WwqocH7wl4R44wgDXUcsY6glOJcB0j862uXl9uab
# 3H4szP8XTE0AotjWAQ64i+7m4HJViSwnGWH2dwGMMIIGrjCCBJagAwIBAgIQBzY3
# tyRUfNhHrP0oZipeWzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMG
# A1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEw
# HwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjIwMzIzMDAwMDAw
# WhcNMzcwMzIyMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNl
# cnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBT
# SEEyNTYgVGltZVN0YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKRN6mXUaHW0oPRnkyibaCwzIP5WvYRoUQV
# Ql+kiPNo+n3znIkLf50fng8zH1ATCyZzlm34V6gCff1DtITaEfFzsbPuK4CEiiIY
# 3+vaPcQXf6sZKz5C3GeO6lE98NZW1OcoLevTsbV15x8GZY2UKdPZ7Gnf2ZCHRgB7
# 20RBidx8ald68Dd5n12sy+iEZLRS8nZH92GDGd1ftFQLIWhuNyG7QKxfst5Kfc71
# ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRAp8ByxbpOH7G1WE15/tePc5OsLDnipUjW
# 8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+gGkcgQ+NDY4B7dW4nJZCYOjgRs/b2nuY7
# W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU8lKVEStYdEAoq3NDzt9KoRxrOMUp88qq
# lnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/FDTP0kyr75s9/g64ZCr6dSgkQe1CvwWc
# ZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwjjVj33GHek/45wPmyMKVM1+mYSlg+0wOI
# /rOP015LdhJRk8mMDDtbiiKowSYI+RQQEgN9XyO7ZONj4KbhPvbCdLI/Hgl27Ktd
# RnXiYKNYCQEoAA6EVO7O6V3IXjASvUaetdN2udIOa5kM0jO0zbECAwEAAaOCAV0w
# ggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLoW2W1NhS9zKXaaL3WM
# aiCPnshvMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB
# /wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1
# aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RH
# NC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIw
# CwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQB9WY7Ak7ZvmKlEIgF+ZtbY
# IULhsBguEE0TzzBTzr8Y+8dQXeJLKftwig2qKWn8acHPHQfpPmDI2AvlXFvXbYf6
# hCAlNDFnzbYSlm/EUExiHQwIgqgWvalWzxVzjQEiJc6VaT9Hd/tydBTX/6tPiix6
# q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQmh2ySvZ180HAKfO+ovHVPulr3qRCyXen/
# KFSJ8NWKcXZl2szwcqMj+sAngkSumScbqyQeJsG33irr9p6xeZmBo1aGqwpFyd/E
# jaDnmPv7pp1yr8THwcFqcdnGE4AJxLafzYeHJLtPo0m5d2aR8XKc6UsCUqc3fpNT
# rDsdCEkPlM05et3/JWOZJyw9P2un8WbDQc1PtkCbISFA0LcTJM3cHXg65J6t5TRx
# ktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0KXzM5h0F4ejjpnOHdI/0dKNPH+ejxmF/7
# K9h+8kaddSweJywm228Vex4Ziza4k9Tm8heZWcpw8De/mADfIBZPJ/tgZxahZrrd
# VcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9gdkT/r+k0fNX2bwE+oLeMt8EifAAzV3C
# +dAjfwAL5HYCJtnwZXZCpimHCUcr5n8apIUP/JiW9lVUKx+A+sDyDivl1vupL0QV
# SucTDh3bNzgaoSv27dZ8/DCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFow
# DQYJKoZIhvcNAQEMBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0
# IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNl
# cnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIz
# NTk1OVowYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcG
# A1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3Rl
# ZCBSb290IEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2je
# u+RdSjwwIjBpM+zCpyUuySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bG
# l20dq7J58soR0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBE
# EC7fgvMHhOZ0O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/N
# rDRAX7F6Zu53yEioZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A
# 2raRmECQecN4x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8
# IUzUvK4bA3VdeGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfB
# aYh2mHY9WV1CdoeJl2l6SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaa
# RBkrfsCUtNJhbesz2cXfSwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZi
# fvaAsPvoZKYz0YkH4b235kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXe
# eqxfjT/JvNNBERJb5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g
# /KEexcCPorF+CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB
# /wQFMAMBAf8wHQYDVR0OBBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQY
# MBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEF
# BQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBD
# BggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# QXNzdXJlZElEUm9vdENBLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3Js
# My5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1Ud
# IAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22
# Ftf3v1cHvZqsoYcs7IVeqRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih
# 9/Jy3iS8UgPITtAq3votVs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYD
# E3cnRNTnf+hZqPC/Lwum6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c
# 2PR3WlxUjG/voVA9/HYJaISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88n
# q2x2zm8jLfR+cWojayL/ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5
# lDGCA3YwggNyAgEBMHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0
# LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hB
# MjU2IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwqSj0pB4A9WjANBglghkgBZQME
# AgEFAKCB0TAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkF
# MQ8XDTIzMDMyNzE4NDgzOFowKwYLKoZIhvcNAQkQAgwxHDAaMBgwFgQU84ciTYYz
# gpI1qZS8vY+W6f4cfHMwLwYJKoZIhvcNAQkEMSIEIMU3K15vDfGgC6I7Md7seArl
# LGtCub8kwwVRTx7loFHDMDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIEIMf04b4yKIkg
# q+ImOr4axPxP5ngcLWTQTIB1V6Ajtbb6MA0GCSqGSIb3DQEBAQUABIICALseNZEI
# 1hYykPayub4sci1pFkm8d9afIt+7NywFq8cYgdupUcR/zxtIK3brB+gn2m+z4NeL
# XKckgmVCyr1RiJtTsRLetYfDB+1cDNZQEf8DrFyn6RUgFi/qAAcFb8ZQJ4FcSDsx
# +bDs9F+/QmV34WNHd22ZdIurF1/iDRRiXshJ13IUKublu0qbmk3wXTx5WrzkPz4y
# wqPZSxI++0J4tR/PgWEP+b0pAqcAc5oKQ89NC9Thcfycp8znojinRbgqDM4lLpy3
# upktKWI2HUsKqFaylBLcrpEEPIiyS4o/caAMoxBiW16RKKAv7Pl1urH7Wxn5wT89
# 0TJxXRBy7ZYlTxax6rW7pL3X8VWJLs4zR9dEKoUMXPiNT7BWYfSB1/ds1EsRfc/g
# Twj4nFeNLoLQa13gcxltCB/uLCyaMy+yAYbpIa216xmXmdpGYKptiTg9HtzB8IZb
# lBIRpt6+aH0CziAco7bfpvhK199eWky2tZkFyDyG7TIu3XEpyfGRVrYWI70vW1fN
# GR/9uewmQGfDsFbX/8oWzVwlLNgVmOhhVxX9GYhZ+dJHxH93xbQVlt5YVrHlSJND
# pFFq76pkeaxUHk8d3guDKDfcsP17ARGKJHhn1Lo42FyVEL+NgROEV14rVThOIk09
# x5faLxNsQKoTXmucjD4UD4mTjFh5WSKk0d6j
# SIG # End signature block
