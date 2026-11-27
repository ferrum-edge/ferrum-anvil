# Authenticode status of the Windows installers a release build collected.
#
#   pwsh -NoProfile -File scripts/authenticode-status.ps1 -Dir dist/<target>
#
# Prints one line, tab-separated: "Valid<TAB><signer subject>" when there is at
# least one .msi / -setup.exe and every one has a Valid signature from the same
# signer, otherwise "Invalid<TAB><file>=<status>,..." (NotSigned, HashMismatch,
# UnknownError, ...). Used by release.yml's signature verification; it reads
# the files only and never signs anything.
param([Parameter(Mandatory = $true)][string]$Dir)
$ErrorActionPreference = "Stop"

$files = @(Get-ChildItem -LiteralPath $Dir -File | Where-Object { $_.Name -like "*.msi" -or $_.Name -like "*-setup.exe" })
if ($files.Count -eq 0) {
  "Invalid`tno installers in $Dir"
  exit 0
}
$sigs = @($files | ForEach-Object { Get-AuthenticodeSignature -LiteralPath $_.FullName })
$invalid = @($sigs | Where-Object { $_.Status -ne "Valid" })
$signers = @($sigs | Where-Object { $_.SignerCertificate } | ForEach-Object { $_.SignerCertificate.Thumbprint } | Sort-Object -Unique)
if ($invalid.Count -eq 0 -and $signers.Count -eq 1) {
  "Valid`t$($sigs[0].SignerCertificate.Subject)"
} else {
  $states = ($sigs | ForEach-Object { "$(Split-Path -Leaf $_.Path)=$($_.Status)" }) -join ","
  if ($signers.Count -gt 1) { $states += ",signers=$($signers.Count)" }
  "Invalid`t$states"
}
