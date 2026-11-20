# Dot source this entrypoint for the portable constructor/method API.
# The package manifest remains the compatibility command entrypoint.
if ($MyInvocation.InvocationName -ne '.') {
    throw 'Dot source bin/ADAnalyzer.ps1 to load the constructor API.'
}

# Explicit statements preserve variables owned by a dot-sourcing caller.
. (Join-Path $PSScriptRoot 'ADProfile.ps1')
. (Join-Path $PSScriptRoot 'ADGpo.ps1')
. (Join-Path $PSScriptRoot 'ADPolicyAnalysis.ps1')
. (Join-Path $PSScriptRoot 'ADDirectoryAnalysis.ps1')
. (Join-Path $PSScriptRoot 'ADHostAnalysis.ps1')
. (Join-Path $PSScriptRoot 'ADOperations.ps1')
. (Join-Path $PSScriptRoot 'ADAssessment.ps1')
