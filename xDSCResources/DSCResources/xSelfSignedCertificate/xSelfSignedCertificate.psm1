
Import-Module "$PSScriptRoot\..\..\bin\DSCHelper.psm1" -Force;

Function Get-TargetResource {
    Param(
        [Parameter(Mandatory = $true)][System.String]$CommonName,
        [Parameter(Mandatory = $true)][System.String]$FriendlyName,
        [Parameter(Mandatory = $false)][Switch]$IsDSCCert,
        [Parameter(Mandatory = $false)][System.String]$Password,
        [Parameter(Mandatory = $false)][System.String]$PFXPath,
        [Parameter(Mandatory = $false)][System.String]$CERPath,
        [Parameter(Mandatory = $false)][System.String]$ThumbprintPath,
        [Parameter(Mandatory = $true)][ValidateSet("Present", "Absent")][System.String]$Ensure);
    $script:lastResult = $null;
    if ((Test-DSCCert -commonName $CommonName)) {
        $cert = Get-DSCCert -commonName $CommonName;
        if (![string]::IsNullOrEmpty($PFXPath)) {
            if ([string]::IsNullOrEmpty($Password)) { Throw "I need a password!"; }
            $bytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $Password);
            [System.IO.File]::WriteAllBytes($PFXPath, $bytes);
        }
        if (![string]::IsNullOrEmpty($CERPath)) {
            $bytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert);
            [System.IO.File]::WriteAllBytes($CERPath, $bytes);
        }
        if (![string]::IsNullOrEmpty($ThumbprintPath)) {
            $cert.Thumbprint | Out-File -LiteralPath $ThumbprintPath;
        }
        $script:lastResult = @{
            CommonName     = $cert.CommonName;
            FriendlyName   = $cert.FriendlyName;
            Password       = "Redacted";
            IsDSCCert      = $IsDSCCert;
            PFXPath        = $PFXPath;
            CERPath        = $CERPath;
            ThumbprintPath = $ThumbprintPath;
            Ensure         = "Present";
        }
    }
    else {
        $script:lastResult = @{
            CommonName     = $CommonName;
            FriendlyName   = $FriendlyName;
            Password       = "Redacted";
            IsDSCCert      = $IsDSCCert;
            PFXPath        = $PFXPath;
            CERPath        = $CERPath;
            ThumbprintPath = $ThumbprintPath;
            Ensure         = "Absent";
        }
    }
    return $script:lastResult;
}

Function Set-TargetResource {
    Param(
        [Parameter(Mandatory = $true)][System.String]$CommonName,
        [Parameter(Mandatory = $true)][System.String]$FriendlyName,
        [Parameter(Mandatory = $false)][Switch]$IsDSCCert,
        [Parameter(Mandatory = $false)][System.String]$Password,
        [Parameter(Mandatory = $false)][System.String]$PFXPath,
        [Parameter(Mandatory = $false)][System.String]$CERPath,
        [Parameter(Mandatory = $false)][System.String]$ThumbprintPath,
        [Parameter(Mandatory = $true)][ValidateSet("Present", "Absent")][System.String]$Ensure);
    if ($Ensure -ieq "Present") {
        New-DSCCert -commonName $CommonName -friendlyName $FriendlyName -IsDSCCert:$ISDSCCert;
        if (![string]::IsNullOrEmpty($PFXPath)) {
            Export-DSCCertPrivateKey -commonName $CommonName -fileName $PFXPath -Password $password;
        }
        if (![string]::IsNullOrEmpty($CERPath)) {
            Export-DSCCertPublicKey -commonName $CommonName -fileName $CERPath -thumbprintPath $ThumbprintPath;
        }
    }
    else {
        Remove-DSCCert -commonName $CommonName -PFXPath $PFXPath -CERPath $CERPath;
    }
}

Function Test-TargetResource {
    Param(
        [Parameter(Mandatory = $true)][System.String]$CommonName,
        [Parameter(Mandatory = $true)][System.String]$FriendlyName,
        [Parameter(Mandatory = $false)][Switch]$IsDSCCert,
        [Parameter(Mandatory = $false)][System.String]$Password,
        [Parameter(Mandatory = $false)][System.String]$PFXPath,
        [Parameter(Mandatory = $false)][System.String]$CERPath,
        [Parameter(Mandatory = $false)][System.String]$ThumbprintPath,
        [Parameter(Mandatory = $true)][ValidateSet("Present", "Absent")][System.String]$Ensure);
    $script:lastResult = (Test-DSCCert -commonName $CommonName -PFXPath $PFXPath -CERPath $CERPath -ThumbprintPath $ThumbprintPath);
    if ($Ensure -ieq "Present") {
        return $script:lastResult;
    }
    else {
        return !$script:lastResult;
    }
}

Export-ModuleMember -Function *-TargetResource;
