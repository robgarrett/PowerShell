
[CmdletBinding()]Param();

# Dependent files.
. "$PSScriptRoot\DSCHelperCerts.ps1";

# What to export from this inner module.
Export-ModuleMember -Function *-DSC*;
