# xDSCResources
Resources and Tools for Desired State Configuration.

## Installation
To install xDSCResources module either...

* Unzip the content under $env:ProgramFiles\WindowsPowerShell\Modules folder.
* Or `Install-Module xDSCResources` in an elevated PowerShell session.

Run `Get-DSCResource -ModuleName xDSCResources` to see resources available in this module.

## Requirements
This module requires at least PowerShell 5.1, which ships with Windows Server 2016 and Windows 10.
You can also download WMF 5.1 from [https://www.microsoft.com/en-us/download/details.aspx?id=54616].

## Example
The following example demonstrates creating a Self-Signed Certificate with the tools.

```powershell
Configuration CreateSSCert {
    Import-DSCResource -ModuleName xDSCResources;

    Node $AllNodes.NodeName {
        xSelfSignedCertificate {
            Ensure          = "Present";
            CommonName      = "CN=mydomain.local";
            FriendlyName    = "My Self-Signed Certificate";
            CERPath         = "c:\temp\publickey.cer";
            PFXPath         = "c:\temp\privatekey.pfx";
            ThumbprintPath  = "c:\temp\thumbprint.txt";
        }
    }
}
