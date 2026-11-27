# Authenticode status of the Windows installers a release build collected.
#
#   pwsh -NoProfile -File scripts/release/authenticode-status.ps1 -Dir dist/<target> `
#     [-Route pfx|artifact-signing-oidc|artifact-signing-secret|none] [-Thumbprint <sha1>] [-ProfileEku <oid>]
#
# Prints one line, tab-separated: "Valid<TAB><signer subject><TAB><identity>"
# when there is at least one .msi / -setup.exe, every one has a Valid
# signature, and every signer is the configured identity; otherwise
# "Invalid<TAB><file>=<status or reason>,...". The identity depends on the
# route, because Azure Artifact Signing renews its leaf certificate daily:
#
#   pfx                  every signer certificate has -Thumbprint (the imported
#                        certificate)
#   artifact-signing-*   every signer certificate carries the code-signing EKU,
#                        the Artifact Signing Public Trust EKU
#                        (1.3.6.1.4.1.311.97.1.0) and the same certificate
#                        profile EKU (1.3.6.1.4.1.311.97.<profile>), which stays
#                        fixed across renewals; with -ProfileEku, that exact one
#   none                 every signer has the same subject (nothing is expected
#                        to be signed; reported for the evidence only)
#
# Used by release.yml's signature verification; it reads the files only and
# never signs anything.
param(
  [Parameter(Mandatory = $true)][string]$Dir,
  [string]$Route = "none",
  [string]$Thumbprint = "",
  [string]$ProfileEku = ""
)
$ErrorActionPreference = "Stop"

$CodeSigning = "1.3.6.1.5.5.7.3.3"
$ArtifactSigningPublic = "1.3.6.1.4.1.311.97.1.0"

function Get-Ekus($cert) {
  $ext = $cert.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } | Select-Object -First 1
  if (-not $ext) { return @() }
  return @($ext.EnhancedKeyUsages | ForEach-Object { $_.Value })
}

$files = @(Get-ChildItem -LiteralPath $Dir -File | Where-Object { $_.Name -like "*.msi" -or $_.Name -like "*-setup.exe" })
if ($files.Count -eq 0) {
  "Invalid`tno installers in $Dir"
  exit 0
}

$problems = @()
$identities = @()
$subjects = @()
foreach ($f in $files) {
  $sig = Get-AuthenticodeSignature -LiteralPath $f.FullName
  if ($sig.Status -ne "Valid" -or -not $sig.SignerCertificate) {
    $problems += "$($f.Name)=$($sig.Status)"
    continue
  }
  $cert = $sig.SignerCertificate
  $subjects += $cert.Subject
  switch -Wildcard ($Route) {
    "pfx" {
      if (-not $Thumbprint -or $cert.Thumbprint -ne $Thumbprint.ToUpperInvariant()) { $problems += "$($f.Name)=signer is not the imported certificate" }
      $identities += "thumbprint $($cert.Thumbprint)"
    }
    "artifact-signing-*" {
      $ekus = Get-Ekus $cert
      $profile = @($ekus | Where-Object { $_.StartsWith("1.3.6.1.4.1.311.97.") -and $_ -ne $ArtifactSigningPublic -and -not $_.StartsWith("1.3.6.1.4.1.311.97.1.") })
      if ($ekus -notcontains $CodeSigning -or $ekus -notcontains $ArtifactSigningPublic -or $profile.Count -ne 1) {
        $problems += "$($f.Name)=signer is not an Artifact Signing Public Trust certificate profile"
      } elseif ($ProfileEku -and $profile[0] -ne $ProfileEku) {
        $problems += "$($f.Name)=certificate profile EKU $($profile[0]) is not ARTIFACT_SIGNING_PROFILE_EKU"
      }
      $identities += "profile EKU $($profile -join '+')"
    }
    default { $identities += "subject $($cert.Subject)" }
  }
}
$identities = @($identities | Sort-Object -Unique)
$subjects = @($subjects | Sort-Object -Unique)
if ($problems.Count -eq 0 -and $identities.Count -ne 1) { $problems += "signers differ: $($identities -join '; ')" }
if ($problems.Count -eq 0 -and $subjects.Count -ne 1) { $problems += "signer subjects differ: $($subjects -join '; ')" }
if ($problems.Count -eq 0) {
  "Valid`t$($subjects[0])`t$($identities[0])"
} else {
  "Invalid`t$($problems -join ',')"
}
