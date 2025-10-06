<#
.SYNOPSIS
    Azure Function script to retrieve Azure Storage Account details and register them as source systems
    in Rubrik NAS Cloud Direct (NAS CD) using the 'system-type-azurefiles' type.

.DESCRIPTION
    This script is designed to run as a timer-triggered Azure Function. It uses the Function App's Managed Identity
    to connect to Azure, retrieve the NAS CD API Token from an Azure Key Vault, and discover Storage Accounts
    across all accessible subscriptions. It automatically detects and uses private endpoints for Azure Files where available.
    It checks if a system already exists in NAS CD before attempting to add it.
    It will only register accounts that contain one or more Azure File Shares. Configuration is read from Application Settings.

.NOTES
    This script relies on Application Settings within the Azure Function App for configuration:
    - NasCdFqdn: The FQDN of the NAS Cloud Direct instance. (Required)
    - KeyVaultName: The name of the Azure Key Vault storing the API token. (Required)
    - KeyVaultSecretName: The name of the secret in the Key Vault. (Required)

    REQUIRED AZURE PERMISSIONS:
    The Function App's System-Assigned Managed Identity requires the following IAM role assignments:

    Scoped to each Subscription to be scanned:
    1. Reader: Allows the function to list subscriptions, storage accounts, and private endpoints.
    2. Storage Account Key Operator Service Role: Allows the function to retrieve access keys for storage accounts.
    3. Storage File Data SMB Share Reader: Allows the function to list file shares within a storage account.

    Scoped to the Azure Key Vault resource:
    1. Key Vault Secrets User: Allows the function to read the NAS CD API token secret from the vault.

    NETWORKING PREREQUISITE FOR PRIVATE ENDPOINTS:
    For the script to successfully connect to and list shares on a storage account via a private endpoint,
    the Azure Function App MUST be configured with VNet Integration. The selected VNet must have DNS
    resolution for the private DNS zone associated with the storage account's privatelink.
#>
# Input bindings are passed in via param block.
param($Timer)

# --- Helper Functions ---

function Get-NasCdSystems {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Fqdn,
        [Parameter(Mandatory)]
        [string]$ApiToken
    )

    Write-Information "Retrieving list of existing systems from NAS CD..."
    $apiUrl = "https://$($Fqdn)/x/igneous/v2/systems"
    $headers = @{ "Authorization" = $ApiToken }

    try {
        $response = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers $headers
        if ($response.Systems) {
            # Use a HashSet for efficient lookups
            $hostSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$response.Systems.Name, [System.StringComparer]::OrdinalIgnoreCase)
            Write-Information "Successfully retrieved $($hostSet.Count) existing systems."
            return $hostSet
        }
        return [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    }
    catch {
        $fullError = $_ | Format-List -Force | Out-String
        Write-Error "Failed to get existing systems from NAS CD. Full Error: $fullError"
        # Return null on failure to stop the script from proceeding
        return $null
    }
}


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
        [string]$SystemType,
        [Parameter(Mandatory)]
        [string]$Region
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
        "SystemType"     = $SystemType
        "Host"           = $TargetHost
        "User"           = $Username
        "Password"       = $plainTextPassword
        "Region"         = $Region
        "VerifySSL"      = $false
        "ManagementInfo" = @{}
    } | ConvertTo-Json

    try {
        Write-Verbose "Sending POST request to $apiUrl with body: $body"
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
        $fullError = $_ | Format-List -Force | Out-String
        Write-Warning "Failed to register source '$TargetHost' in NAS CD. API Error: $errorMessage"
        Write-Error "Full exception details for '$TargetHost' registration failure: $fullError"
        return "Failed (API Error)"
    }
}

# --- Main Script Body ---

# Get configuration from environment variables (Application Settings in Azure Function)
$NasCdFqdn = $env:NasCdFqdn
$KeyVaultName = $env:KeyVaultName
$KeyVaultSecretName = $env:KeyVaultSecretName

Write-Information "Azure Function execution started by timer."
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
    $errorMessage = "Error connecting with Managed Identity. Message: $($_.Exception.Message). StackTrace: $($_.Exception.StackTrace)."
    Write-Error $errorMessage
    Write-Error "Full exception object: $($_.Exception | Out-String)"
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
    $fullError = $_ | Format-List -Force | Out-String
    Write-Error "Failed to retrieve secret '$KeyVaultSecretName' from Key Vault '$KeyVaultName'. Please ensure the Function App's Managed Identity has 'Key Vault Secrets User' permissions on the Key Vault. Full Error: $fullError"
    return
}

# Get a list of all systems already registered in NAS CD
$existingNasCdHosts = Get-NasCdSystems -Fqdn $NasCdFqdn -ApiToken $NasCdApiToken
if ($null -eq $existingNasCdHosts) {
    Write-Error "Could not retrieve existing systems from NAS CD. Halting execution."
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
    $fullError = $_ | Format-List -Force | Out-String
    Write-Error "Failed to retrieve subscription list. Please ensure the Managed Identity has at least 'Reader' access at a scope that includes subscriptions. Full Error: $fullError"
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
            
            # --- TESTING FILTER: Only process storage accounts containing 'seanc' ---
            # To process all storage accounts, remove or comment out this 'if' block.
            if ($account.StorageAccountName -notlike '*seanc*') {
                Write-Information "  - Skipping account '$($account.StorageAccountName)' as it does not match the test filter."
                continue
            }
            # --- END TESTING FILTER ---

            Write-Verbose "Processing storage account: $($account.StorageAccountName)"
            $accessKeySecure = $null
            $nasCdStatus = "Not Attempted"
            $hasFileShares = $false
            $nasCdSystemType = "system-type-azurefiles"
            $endpointType = "Public"
            $fileServiceHostName = $null

            # Determine the endpoint FQDN (Private or Public)
            try {
                $privateEndpoint = Get-AzPrivateEndpoint -ResourceGroupName $account.ResourceGroupName | Where-Object { 
                    $_.PrivateLinkServiceConnections.PrivateLinkServiceId -eq $account.Id -and $_.PrivateLinkServiceConnections.GroupIds -contains 'file' 
                }

                if ($privateEndpoint -and $privateEndpoint.CustomDnsConfigs.Fqdn) {
                    $fileServiceHostName = $privateEndpoint[0].CustomDnsConfigs.Fqdn[0]
                    $endpointType = "Private"
                    Write-Information "  - Detected Private Endpoint: $fileServiceHostName"
                } else {
                    $fileServiceHostName = ([System.Uri]$account.PrimaryEndpoints.File).Host
                    Write-Verbose "  - No private endpoint found for file service, using public endpoint: $fileServiceHostName"
                }
            } catch {
                 Write-Warning "Could not determine endpoint for account '$($account.StorageAccountName)'. Full Error: $($_.Exception.Message)"
                 $fileServiceHostName = ([System.Uri]$account.PrimaryEndpoints.File).Host
            }
            

            # If we don't have a hostname, we can't continue with this account
            if (-not $fileServiceHostName) {
                 $nasCdStatus = "Skipped (No File Service URL)"
            }
            # Check if the host is already registered in NAS CD
            elseif ($existingNasCdHosts.Contains($fileServiceHostName)) {
                Write-Information "  - Skipping account '$($account.StorageAccountName)' as host '$($fileServiceHostName)' is already registered."
                $nasCdStatus = "Skipped (Already Exists)"
            }
            else {
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
                        $fullError = $_ | Format-List -Force | Out-String
                        Write-Warning "Could not check for file shares in account '$($account.StorageAccountName)'. Full Error: $fullError"
                    }
                }
                
                if ($accessKeySecure -and $hasFileShares) {
                    Write-Information "  -> Registering '$($fileServiceHostName)' in NAS CD..."
                    $nasCdStatus = Register-NasCdSource -Fqdn $NasCdFqdn -ApiToken $NasCdApiToken -TargetHost $fileServiceHostName -Username $account.StorageAccountName -Password $accessKeySecure -SystemType $nasCdSystemType -Region $account.Location
                } elseif (-not $hasFileShares) {
                    $nasCdStatus = "Skipped (No File Shares)"
                } else {
                    $nasCdStatus = "Skipped (Missing Key)"
                }
            }

            $results.Add([PSCustomObject]@{
                SubscriptionName     = $subscription.Name
                StorageAccountName   = $account.StorageAccountName
                EndpointType         = $endpointType
                FileServiceHost      = $fileServiceHostName
                NasCdRegistration    = $nasCdStatus
            })
        }
    }
    catch {
        $fullError = $_ | Format-List -Force | Out-String
        Write-Error "An unhandled error occurred while processing subscription '$($subscription.Name)': $fullError"
    }
}

Write-Information "`n--- Script Execution Summary ---"
if ($results.Count -gt 0) {
    $results | Format-Table -Property SubscriptionName, StorageAccountName, EndpointType, FileServiceHost, NasCdRegistration | Out-String | Write-Information
}
else {
    Write-Information "No storage account information was collected."
}

Write-Information "Script finished."

