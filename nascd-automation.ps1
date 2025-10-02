<#
.SYNOPSIS
    Azure Function script to retrieve Azure Storage Account details and register them as source systems
    in Rubrik NAS Cloud Direct (NAS CD), handling both SMB and NFS protocols.

.DESCRIPTION
    This script is designed to run as a timer-triggered Azure Function. It uses the Function App's Managed Identity
    to connect to Azure, retrieve the NAS CD API Token from an Azure Key Vault, and discover Storage Accounts
    across all accessible subscriptions. It retrieves the full File Service URL for each account and uses its
    hostname for the NAS CD API registration.

    It will only register accounts that contain one or more Azure File Shares. Configuration is read from Application Settings.

    - If NFSv3 is enabled, it's registered as 'system-type-generic-nfs4'.
    - Otherwise, it's registered as 'system-type-generic-smb'.

.NOTES
    This script relies on Application Settings within the Azure Function App for configuration:
    - NasCdFqdn: The FQDN of the NAS Cloud Direct instance. (Required)
    - KeyVaultName: The name of the Azure Key Vault storing the API token. (Required)
    - KeyVaultSecretName: The name of the secret in the Key Vault. (Required)
#>
param($Timer)

# --- Helper Function ---
function Register-NasCdSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Fqdn,
        [Parameter(Mandatory)]
        [string]$ApiToken,
        [Parameter(Mandatory)]
        [string]$TargetHost,
        [Parameter(Mandatory)]
        [string]$Username,
        [Parameter(Mandatory)]
        [System.Security.SecureString]$Password,
        [Parameter(Mandatory)]
        [ValidateSet("system-type-generic-smb", "system-type-generic-nfs4")]
        [string]$SystemType
    )
    
    Write-Verbose "Preparing to register source '$TargetHost' as type '$SystemType' in NAS CD instance '$Fqdn'."

    $apiUrl = "https://$($Fqdn)/x/igneous/v2/systems"
    $headers = @{
        "Authorization" = $ApiToken
        "Content-Type"  = "application/json"
    }

    # Convert SecureString to plain text only for the API call
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $plainTextPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

    $body = @{
        "SystemType" = $SystemType
        "Host"       = $TargetHost
        "User"       = $Username
        "Password"   = $plainTextPassword
    } | ConvertTo-Json

    try {
        Write-Verbose "Sending POST request to $apiUrl."
        $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Headers $headers -Body $body
        Write-Verbose "API Response: $($response | ConvertTo-Json -Depth 3)"
        
        if ($response.ID) {
            return "Success (Job ID: $($response.ID))"
        }
        else {
            return "Failed (Unexpected Response)"
        }
    }
    catch {
        $errorMessage = $_.Exception.Response.GetResponseStream() | ForEach-Object { (New-Object System.IO.StreamReader($_)).ReadToEnd() }
        Write-Warning "Failed to register source '$TargetHost' in NAS CD. API Error: $errorMessage"
        return "Failed (API Error)"
    }
}

# --- Main Script Body ---

# Get configuration from environment variables (Application Settings in Azure Function)
$NasCdFqdn = $env:NasCdFqdn
$KeyVaultName = $env:KeyVaultName
$KeyVaultSecretName = $env:KeyVaultSecretName

Write-Information "Azure Function execution started."
Write-Information "Timer schedule: $($Timer.ScheduleStatus.Next)"

if (-not $NasCdFqdn -or -not $KeyVaultName -or -not $KeyVaultSecretName) {
    Write-Error "One or more required application settings are missing: NasCdFqdn, KeyVaultName, KeyVaultSecretName."
    return
}

$ErrorActionPreference = 'Stop'
$results = [System.Collections.Generic.List[object]]::new()
$NasCdApiToken = $null

try {
    Write-Information "Connecting to Azure using Managed Identity..."
    Connect-AzAccount -Identity
    Write-Information "Successfully connected to Azure."
}
catch {
    Write-Error "Failed to connect to Azure using Managed Identity. Please ensure this Function App has a Managed Identity with appropriate permissions."
    return
}

# Retrieve NAS CD API Token from Azure Key Vault
try {
    Write-Information "Retrieving NAS CD API Token from Key Vault '$KeyVaultName'..."
    $secret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $KeyVaultSecretName -AsPlainText
    $NasCdApiToken = $secret
    Write-Information "Successfully retrieved the API token secret."
}
catch {
    Write-Error "Failed to retrieve secret '$KeyVaultSecretName' from Key Vault '$KeyVaultName'. Please ensure the Function App's Managed Identity has 'Key Vault Secrets User' permissions on the Key Vault."
    return
}

# Get all subscriptions the Managed Identity has access to
try {
    Write-Information "Discovering all accessible subscriptions..."
    $subscriptions = Get-AzSubscription
    if (-not $subscriptions) {
        Write-Error "The Managed Identity does not have access to any subscriptions."
        return
    }
    Write-Information "Found $($subscriptions.Count) accessible subscriptions."
}
catch {
    Write-Error "Failed to retrieve subscription list. Please ensure the Managed Identity has at least 'Reader' access at a scope that includes subscriptions."
    return
}

foreach ($subscription in $subscriptions) {
    $subId = $subscription.Id
    try {
        Write-Information "`nProcessing Subscription: $($subscription.Name) (ID: $subId)"
        Set-AzContext -Subscription $subId | Out-Null
        $storageAccounts = Get-AzStorageAccount
        
        if (-not $storageAccounts) {
            Write-Warning "No storage accounts found in subscription '$($subscription.Name)'."
            continue
        }

        Write-Information "Found $($storageAccounts.Count) storage accounts. Retrieving details..."

        foreach ($account in $storageAccounts) {
            Write-Verbose "Processing storage account: $($account.StorageAccountName)"
            $accessKeySecure = $null
            $nasCdStatus = "Not Attempted"
            $fileServiceUrl = $null
            $fileServiceHostName = $null
            $hasFileShares = $false
            
            $protocolType = if ($account.EnableNfsV3) { "NFSv4.1" } else { "SMB" }
            $nasCdSystemType = if ($account.EnableNfsV3) { "system-type-generic-nfs4" } else { "system-type-generic-smb" }
            Write-Verbose "Detected protocol for '$($account.StorageAccountName)' is $protocolType. Will use NAS CD SystemType '$nasCdSystemType'."

            try {
                $fileServiceUrl = $account.PrimaryEndpoints.File
                if ($fileServiceUrl) {
                    $fileServiceHostName = ([System.Uri]$fileServiceUrl).Host
                }
            }
            catch {
                Write-Warning "Could not parse File Service URL for account '$($account.StorageAccountName)'."
            }

            try {
                $keys = Get-AzStorageAccountKey -ResourceGroupName $account.ResourceGroupName -Name $account.StorageAccountName
                if ($keys) { $accessKeySecure = $keys[0].Value | ConvertTo-SecureString -AsPlainText -Force }
            }
            catch {
                Write-Warning "Could not retrieve access key for account '$($account.StorageAccountName)'. Check permissions."
            }

            # Check for existing file shares before attempting registration
            if ($accessKeySecure) {
                try {
                    $plainTextKey = [System.Net.NetworkCredential]::new('', $accessKeySecure).Password
                    $context = New-AzStorageContext -StorageAccountName $account.StorageAccountName -StorageAccountKey $plainTextKey
                    $shares = Get-AzStorageShare -Context $context
                    if ($shares.Count -gt 0) {
                        $hasFileShares = $true
                        Write-Information "  - Found $($shares.Count) file share(s) in '$($account.StorageAccountName)'. Eligible for registration."
                    } else {
                        Write-Information "  - Found 0 file shares in '$($account.StorageAccountName)'. Skipping registration."
                    }
                } catch {
                    Write-Warning "Could not check for file shares in account '$($account.StorageAccountName)'. Error: $_"
                }
            }
            
            if ($accessKeySecure -and $fileServiceHostName -and $hasFileShares) {
                Write-Information "  -> Registering '$($fileServiceHostName)' in NAS CD..."
                $nasCdStatus = Register-NasCdSource -Fqdn $NasCdFqdn -ApiToken $NasCdApiToken -TargetHost $fileServiceHostName -Username $account.StorageAccountName -Password $accessKeySecure -SystemType $nasCdSystemType
            } elseif (-not $hasFileShares) {
                $nasCdStatus = "Skipped (No File Shares)"
            } else {
                $nasCdStatus = "Skipped (Missing Key or Host)"
            }

            $results.Add([PSCustomObject]@{
                SubscriptionName    = $subscription.Name
                StorageAccountName  = $account.StorageAccountName
                DetectedProtocol    = $protocolType
                FileServiceUrl      = $fileServiceUrl
                FileServiceHost     = $fileServiceHostName
                NasCdRegistration   = $nasCdStatus
            })
        }
    }
    catch {
        Write-Error "An error occurred while processing subscription '$($subscription.Name)': $_"
    }
}

Write-Information "`n--- Script Execution Summary ---"
if ($results.Count -gt 0) {
    $results | Format-Table | Out-String | Write-Information
}
else {
    Write-Information "No storage account information was collected."
}

Write-Information "Script finished."

