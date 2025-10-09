Azure Storage Auto-Discovery for Rubrik NAS Cloud Direct
This project contains a PowerShell script designed to run as a timer-triggered Azure Function. It automatically discovers Azure Storage Accounts containing File Shares across all accessible subscriptions and registers them as source systems in a Rubrik NAS Cloud Direct (NAS CD) instance.

The script leverages an Azure Function App's System-Assigned Managed Identity for secure, passwordless authentication to Azure resources. It is designed to be efficient and resilient, checking for pre-existing registrations and automatically using private endpoints where available.

Features ✨
Automated Discovery: Scans all accessible Azure subscriptions for Storage Accounts.

Secure by Design: Uses a Managed Identity for Azure authentication and retrieves the Rubrik API token from Azure Key Vault.

Private Endpoint Aware: Automatically detects and uses the FQDN of a private endpoint for the Azure Files service if one exists, ensuring traffic can remain on your virtual network.

Intelligent Registration:

Checks if a storage account is already registered in NAS CD to prevent duplicates.

Verifies that a storage account contains at least one file share before attempting to register it.

Centralized Configuration: All settings are managed via the Azure Function App's Application Settings.

Comprehensive Logging: Provides clear and detailed logs during execution for easy monitoring and troubleshooting.

Prerequisites
Before deploying the function, you will need the following:

An Azure Subscription.

A Rubrik NAS Cloud Direct instance with API access.

An Azure Function App (PowerShell stack, Consumption Plan is suitable).

An Azure Key Vault to securely store the Rubrik API token.

Setup and Deployment 🚀
1. Configure Azure IAM Permissions
The script runs using the Function App's System-Assigned Managed Identity. You must enable it and grant it the following Azure IAM roles.

A. Scoped to each Subscription to be scanned:

Reader: Allows the function to list subscriptions, resource groups, storage accounts, and network resources.

Storage Account Key Operator Service Role: Allows the function to retrieve the access keys required to connect to the storage account.

Storage File Data SMB Share Reader: Allows the function to list file shares to verify the account is not empty.

B. Scoped to the Azure Key Vault resource:

Key Vault Secrets User: Allows the function to read the NAS CD API token secret from the vault.

2. Configure Azure Key Vault
Navigate to your Azure Key Vault.

Create a new secret (e.g., nas-cd-api-token).

The value of the secret should be the full API token string from your Rubrik NAS CD instance (e.g., Bearer eyJhbGciOi...).

3. Deploy the Azure Function
Clone this repository or copy the run.ps1 script.

Deploy the script to a PowerShell-based Azure Function App. You can do this via VS Code, Azure CLI, or by pasting the code into the portal's editor.

In the Function App, create a Timer Trigger function and replace its default run.ps1 with the script's content. A schedule of once every 24 hours (0 0 4 * * *) is a reasonable starting point.

4. Configure Application Settings
In your Function App, navigate to Settings -> Configuration and add the following Application Settings. These are used as environment variables by the script.

Setting Name

Description

Example Value

NasCdFqdn

Required. The Fully Qualified Domain Name of your NAS CD instance.

my-instance.nascd.rubrik.com

KeyVaultName

Required. The name of the Azure Key Vault storing the API token.

my-secure-keyvault

KeyVaultSecretName

Required. The name of the secret containing the NAS CD API token.

nas-cd-api-token

5. Configure PowerShell Dependencies
The script requires specific PowerShell modules. In your Function App, open the requirements.psd1 file (located under App files) and ensure it contains the following to enable the Az modules:

# This file enables modules to be automatically managed by the Functions service.
# See [https://aka.ms/functionsmanageddependency](https://aka.ms/functionsmanageddependency) for more information.
#
@{
    # For latest supported version, go to '[https://www.powershellgallery.com/packages/Az](https://www.powershellgallery.com/packages/Az)'.
    'Az' = '10.*'
}

6. Configure Networking (For Private Endpoints)
For the script to successfully connect to a storage account via a private endpoint, the Azure Function App MUST be configured with VNet Integration. The selected virtual network must have DNS resolution for the private DNS zone associated with the storage account's private link (e.g., privatelink.file.core.windows.net).

Disclaimer of Warranty / Use at Your Own Risk ⚠️
This software is provided "as is" and "with all faults." The authors and contributors make no representations or warranties of any kind concerning the safety, suitability, lack of viruses, inaccuracies, typographical errors, or other harmful components of this software.

There are inherent dangers in the use of any software, and you are solely responsible for determining whether this software is compatible with your equipment and other software installed on your equipment. You are also solely responsible for the protection of your equipment and backup of your data, and the provider will not be liable for any damages you may suffer in connection with using, modifying, or distributing this software.

In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software. Use this script at your own risk.

License
This project is licensed under the MIT License.

MIT License

Copyright (c) 2025 Sean Comrie

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
