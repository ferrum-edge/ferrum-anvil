# Clean-install release smoke (REL-001) on a GitHub-hosted Windows runner.
# Installs one published, unsigned release installer the way a user would
# (NSIS -setup.exe or .msi, silently), launches the installed app (twice: on
# an empty store and after the example import), and imports the sample
# workspace and makes a loopback call with the release CLI archive.
#
# Run by .github/workflows/release-smoke.yml; every step, the exact surface
# driven and every OS protection that was not exercised are recorded with
# record.py into $env:OUT (finalized into result.json by the workflow).
#
# Environment: TARGET_ID, PACKAGE (nsis | msi), EXPECT_ARCH (x86_64),
# RUST_TARGET, ASSET, CLI_ASSET, INPUTS, OUT, VERSION, ALIVE_SECONDS
# (default 30); see smoke-unix.sh for their meaning.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$here = $PSScriptRoot
foreach ($v in 'TARGET_ID', 'PACKAGE', 'EXPECT_ARCH', 'RUST_TARGET', 'ASSET', 'CLI_ASSET', 'INPUTS', 'OUT', 'VERSION') {
  if (-not [Environment]::GetEnvironmentVariable($v)) { throw "$v is not set" }
}
$Version = $env:VERSION
$Asset = $env:ASSET
$CliAsset = $env:CLI_ASSET
$Alive = if ($env:ALIVE_SECONDS) { [int]$env:ALIVE_SECONDS } else { 30 }
$Inputs = (Resolve-Path $env:INPUTS).Path
New-Item -ItemType Directory -Force -Path (Join-Path $env:OUT 'logs'), (Join-Path $env:OUT 'screenshots') | Out-Null
$Out = (Resolve-Path $env:OUT).Path
$Logs = Join-Path $Out 'logs'
$Work = Join-Path $env:RUNNER_TEMP "rel001-$PID"
New-Item -ItemType Directory -Force -Path $Work | Out-Null
$WS = 'Anvil samples (lab core)'
$SampleRequests = @('OK', 'Backend refuses connections', 'Backend name does not resolve', 'Backend ends the body early', 'Application 500 (not the gateway)', 'Application 403 (not a WAF)')

# Arguments go to record.py as an array of strings: a PowerShell function
# would parse tokens such as --dir as its own parameters.
$RecordPy = Join-Path $here 'record.py'
function Rec([string[]]$argv) { & python -I $RecordPy @argv; if ($LASTEXITCODE) { throw "record.py $($argv[0]) failed" } }
function Step($name, $result, $detail) { Rec @('step', '--dir', $Out, '--name', $name, '--result', $result, '--detail', $detail) }
function Pass($name, $detail) { Step $name 'pass' $detail }
function Info($name, $detail) { Step $name 'info' $detail }
# Every failure is classified (record.py FAILURE_CLASSES): Fail when the
# shipped asset is at fault (checksum, install, launch, import, local call),
# HFail when the harness is (runner, test tools, artifact fetch). Only a
# package failure is grounds to act on a published asset.
function Fail($name, $detail, $class = 'package') {
  Rec @('step', '--dir', $Out, '--name', $name, '--result', 'fail', '--failure-class', $class, '--detail', $detail)
  Write-Host "::error title=$($env:TARGET_ID) $name ($class failure)::$detail"
  exit 1
}
function HFail($name, $detail) { Fail $name $detail 'harness' }
# The runner ran out of disk: a harness fault, whatever command hit it.
function FailUnlessRunner($name, $text, $detail) {
  if ("$text" -match 'not enough space on the disk|There is not enough space|disk is full') { HFail $name "$detail (runner disk)" }
  Fail $name $detail
}
# The full command-by-command mapping is in docs/release.md ("Failure
# classes"); keep the two in step. $script:Step names the step in progress for
# the safety net at the end of the script.
$script:Step = 'setup'
function Bypass($protection, $what) { Rec @('bypass', '--dir', $Out, '--protection', $protection, '--what', $what) }
function Meta { Rec (@('meta', '--dir', $Out) + [string[]]$args) }
function MetaJson($key, $value) { Rec @('meta', '--dir', $Out, '--json', "$key=$($value | ConvertTo-Json -Compress -Depth 6)") }
function Tail($path, $n = 5) { if (Test-Path $path) { ((Get-Content $path -Tail $n) -join ' ') } else { '' } }

$script:serverProc = $null
$script:appPids = @()

try {
  # --- inputs and runner ---------------------------------------------------
  $script:Step = 'asset_integrity'
  try {
    $releaseJson = Get-Content -Raw (Join-Path $Inputs 'release.json')
    $exampleJson = Get-Content -Raw (Join-Path $Inputs 'example.json')
    $fetchResult = Get-Content -Raw (Join-Path $Inputs 'fetch.json') | ConvertFrom-Json
  } catch { HFail 'asset_integrity' "the fetch job's results did not arrive: $($_.Exception.Message)" }
  Rec @('meta', '--dir', $Out, '--json', "release=$releaseJson", "example=$exampleJson")
  Meta "target_triple=$($env:RUST_TARGET)" "package=$($env:PACKAGE)"

  $sums = Join-Path $Inputs 'SHA256SUMS'
  foreach ($pair in @(@($Asset, 'asset'), @($CliAsset, 'cli_asset'))) {
    $name, $key = $pair
    $f = Join-Path $Inputs $name
    # The fetch job checked the published asset against SHA256SUMS (fetch.sh):
    # a problem it found is the published release's, a package failure.
    $fetched = @($fetchResult.assets | Where-Object { $_.name -eq $name })
    if (-not $fetched) { Fail 'asset_integrity' "the fetch result does not name $name" 'harness' }
    if ($fetched[0].status -ne 'ok') { Fail 'asset_integrity' "published asset ${name}: $($fetched[0].detail) (fetch status $($fetched[0].status))" }
    # Here the check is of the hand-over between jobs: a difference now is a
    # transfer error, a harness failure.
    if (-not (Test-Path $f)) { HFail 'asset_integrity' "$name did not arrive from the fetch job" }
    $want = (& python -I $RecordPy sums --sums $sums --name $name)
    if ($LASTEXITCODE) { HFail 'asset_integrity' "SHA256SUMS from the fetch job does not list $name" }
    try { $got = (Get-FileHash -Algorithm SHA256 $f).Hash.ToLowerInvariant() } catch { HFail 'asset_integrity' "cannot hash ${f}: $($_.Exception.Message)" }
    if ($want -ne $got) { HFail 'asset_integrity' "$name changed between the fetch job and this one (sha256 $got, SHA256SUMS $want)" }
    Meta "$key.name=$name" "$key.sha256=$got"
    MetaJson "$key.size" (Get-Item $f).Length
    MetaJson "$key.sha256sums_match" $true
  }
  $example = Join-Path $Inputs 'anvil-samples.anvil'
  try {
    $exampleSha = (Get-FileHash -Algorithm SHA256 $example).Hash.ToLowerInvariant()
    $wantExample = ($exampleJson | ConvertFrom-Json).sha256
  } catch { HFail 'asset_integrity' "the example bundle did not arrive from the fetch job: $($_.Exception.Message)" }
  if ($exampleSha -ne $wantExample) { HFail 'asset_integrity' "the example bundle changed after it was fetched ($exampleSha, expected $wantExample)" }
  Pass 'asset_integrity' "$Asset and $CliAsset match the release's SHA256SUMS; example bundle sha256 $exampleSha"

  $script:Step = 'native_arch'
  try {
    $osInfo = Get-CimInstance Win32_OperatingSystem
    $cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
  } catch { HFail 'native_arch' "cannot query the runner's OS and CPU: $($_.Exception.Message)" }
  $osArch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
  $procArch = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
  Meta "runner.label=$($env:RUNNER_LABEL)" "runner.os=$($osInfo.Caption) $($osInfo.Version) (build $($osInfo.BuildNumber))" "runner.machine=$($env:PROCESSOR_ARCHITECTURE)" `
    "runner.cpu=$cpu" "runner.image=$($env:ImageOS)/$($env:ImageVersion)" "runner.os_architecture=$osArch" "runner.container=none"
  if ($osArch -ne 'X64' -or $procArch -ne 'X64' -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    HFail 'native_arch' "runner is $osArch (process $procArch, PROCESSOR_ARCHITECTURE $($env:PROCESSOR_ARCHITECTURE)), expected native X64"
  }
  Pass 'native_arch' "$($osInfo.Caption) $($osInfo.Version) on $osArch ($cpu), native x64 process"

  # --- install ---------------------------------------------------------------
  $script:Step = 'install'
  $installer = Join-Path $Inputs $Asset
  $motw = Get-Item -LiteralPath $installer -Stream Zone.Identifier -ErrorAction SilentlyContinue
  $motwText = if ($motw) { (Get-Content -LiteralPath $installer -Stream Zone.Identifier) -join ' ' } else { 'absent' }
  try { $sig = (Get-AuthenticodeSignature -LiteralPath $installer).Status } catch { $sig = "unreadable ($($_.Exception.Message))" }
  $wv2 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}' -ErrorAction SilentlyContinue
  Meta "harness.webview2_runtime=$(if ($wv2) { $wv2.pv } else { 'not found in HKLM' })"

  if ($env:PACKAGE -eq 'nsis') {
    $log = Join-Path $Logs 'nsis-install.txt'
    # Windows refusing to start the shipped installer is the installer's failure.
    try { $p = Start-Process -FilePath $installer -ArgumentList '/S' -Wait -PassThru } catch { Fail 'install' "Windows could not start the NSIS installer: $($_.Exception.Message)" }
    "exit code: $($p.ExitCode)" | Set-Content $log
    if ($p.ExitCode -ne 0) { Fail 'install' "the NSIS installer /S exited $($p.ExitCode)" }
    $method = 'NSIS installer run silently (/S), per-user default'
  } elseif ($env:PACKAGE -eq 'msi') {
    $log = Join-Path $Logs 'msiexec-install.log'
    # msiexec.exe is the runner's: failing to start it is a harness fault.
    try { $p = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', "`"$installer`"", '/qn', '/norestart', '/l*v', "`"$log`"") -Wait -PassThru } catch { HFail 'install' "msiexec.exe could not be started: $($_.Exception.Message)" }
    # 1618: another installation is already in progress on the runner.
    if ($p.ExitCode -eq 1618) { HFail 'install' "msiexec /i /qn exited 1618 (another installation in progress on the runner)" }
    # 1601 (Windows Installer service unavailable) and 1603 with a full disk
    # are the runner's; any other failure is the package's.
    if ($p.ExitCode -eq 1601) { HFail 'install' 'msiexec /i /qn exited 1601 (the Windows Installer service is not available on the runner)' }
    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { FailUnlessRunner 'install' (Tail $log 40) "msiexec /i /qn exited $($p.ExitCode): $(Tail $log 8)" }
    $method = 'msiexec /i /qn /norestart (Windows Installer, per-machine, run as the runner administrator)'
  } else {
    HFail 'install' "unknown package kind $($env:PACKAGE)"
  }

  $uninstallKeys = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )
  $entries = @(Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq 'Ferrum Anvil' })
  $entries | Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation, DisplayIcon, UninstallString, PSPath | Format-List | Out-String | Set-Content (Join-Path $Logs 'uninstall-entries.txt')
  if (-not $entries) { Fail 'install' 'no "Ferrum Anvil" entry under Apps & features (Uninstall registry keys) after the install' }
  $dirs = @()
  foreach ($e in $entries) {
    if ($e.InstallLocation) { $dirs += $e.InstallLocation.Trim('"') }
    if ($e.DisplayIcon) { $dirs += (Split-Path -Parent ($e.DisplayIcon.Trim('"') -replace ',\d+$', '')) }
  }
  $dirs += @((Join-Path $env:LOCALAPPDATA 'Ferrum Anvil'), (Join-Path $env:ProgramFiles 'Ferrum Anvil'))
  $exe = $null
  foreach ($d in ($dirs | Where-Object { $_ } | Select-Object -Unique)) {
    if (Test-Path $d) {
      $exe = Get-ChildItem -Path $d -Filter '*.exe' -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^(uninstall|unins)' } | Select-Object -First 1
      if ($exe) { break }
    }
  }
  if (-not $exe) { Fail 'install' "no installed application executable under: $(($dirs | Select-Object -Unique) -join '; ')" }
  $exe = $exe.FullName
  # PE machine type: 0x8664 = x64.
  # A malformed installed executable is the package's failure, not an
  # unclassified script error.
  try {
    $fs = [IO.File]::OpenRead($exe)
    try {
      $br = New-Object IO.BinaryReader($fs)
      $fs.Seek(0x3C, 'Begin') | Out-Null
      $pe = $br.ReadInt32()
      $fs.Seek($pe + 4, 'Begin') | Out-Null
      $machine = $br.ReadUInt16()
    } finally { $fs.Dispose() }
  } catch { Fail 'install' "cannot read the PE header of ${exe}: $($_.Exception.Message)" }
  if ($machine -ne 0x8664) { Fail 'install' ("{0} is not an x64 PE (machine 0x{1:X4})" -f $exe, $machine) }
  try { $fileVersion = (Get-Item $exe).VersionInfo.ProductVersion } catch { Fail 'install' "cannot read the version resource of ${exe}: $($_.Exception.Message)" }
  $displayVersion = ($entries | Select-Object -First 1).DisplayVersion
  if ("$displayVersion" -notlike "$Version*") { Fail 'install' "Apps & features lists version $displayVersion, expected $Version" }
  $shortcut = @(Get-ChildItem -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs" -Recurse -Filter '*.lnk' -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*Ferrum Anvil*' }) | Select-Object -First 1
  Meta "install.method=$method" "install.executable=$exe" "install.version=$displayVersion" "install.file_version=$fileVersion" `
    "install.start_menu_shortcut=$(if ($shortcut) { $shortcut.FullName } else { 'none found' })"
  Pass 'install' "$method; Apps & features entry 'Ferrum Anvil' $displayVersion; executable $exe (x64 PE, product version $fileVersion)"

  try { $exeSig = (Get-AuthenticodeSignature -LiteralPath $exe).Status } catch { $exeSig = "unreadable ($($_.Exception.Message))" }
  Meta "signing.installer_authenticode=$sig" "signing.app_authenticode=$exeSig"
  Info 'signing' "Authenticode: installer $sig, installed executable $exeSig"
  Info 'mark_of_the_web' "Zone.Identifier on the downloaded installer: $motwText"
  Bypass 'smartscreen' "SmartScreen was never consulted: the installer carried no Mark-of-the-Web (Zone.Identifier: $motwText) because it was fetched through the GitHub API and an Actions artifact, not a browser, and it was run silently ($method), so no SmartScreen, publisher or installer prompt was shown or answered. Authenticode status of the installer: $sig."
  if ($env:PACKAGE -eq 'msi') {
    Bypass 'uac' 'msiexec ran as the runner account, which is an administrator with UAC prompts disabled, so no elevation prompt was shown.'
  }

  # --- release CLI ---------------------------------------------------------------
  $script:Step = 'cli_ready'
  $cliDir = Join-Path $Work 'cli'
  # A ZIP that matches SHA256SUMS but does not extract is the package's; a
  # full disk is the runner's.
  try { Expand-Archive -LiteralPath (Join-Path $Inputs $CliAsset) -DestinationPath $cliDir -Force }
  catch { FailUnlessRunner 'cli_ready' $_.Exception.Message "could not extract ${CliAsset}: $($_.Exception.Message)" }
  $cli = Join-Path $cliDir "anvil-cli-$Version-$($env:RUST_TARGET)\anvil.exe"
  if (-not (Test-Path $cli)) { Fail 'cli_ready' "$CliAsset has no anvil-cli-$Version-$($env:RUST_TARGET)\anvil.exe" }
  # Windows refusing to load the shipped CLI is the package's failure.
  try { $cliVersion = (& $cli --version 2>&1) -join ' ' } catch { Fail 'cli_ready' "Windows could not run ${cli}: $($_.Exception.Message)" }
  if ($cliVersion -notlike "*$Version*") { Fail 'cli_ready' "anvil --version printed '$cliVersion', expected $Version" }
  # Recorded, not checked: best-effort.
  try { & $cli doctor *> (Join-Path $Logs 'cli-doctor-before.txt') } catch { "doctor could not run: $($_.Exception.Message)" | Set-Content (Join-Path $Logs 'cli-doctor-before.txt') }
  $dataDir = ((Get-Content (Join-Path $Logs 'cli-doctor-before.txt') -ErrorAction SilentlyContinue) | Where-Object { $_ -like 'data dir: *' } | Select-Object -First 1) -replace '^data dir: ', ''
  $dataState = if ($dataDir -and (Test-Path $dataDir)) { "present ($(@(Get-ChildItem -Recurse -Force $dataDir -ErrorAction SilentlyContinue).Count) entries)" } else { 'absent' }
  Meta "cli.version=$cliVersion" "cli.data_dir=$dataDir" "cli.data_dir_before_first_launch=$dataState"
  Pass 'cli_ready' "release CLI archive $CliAsset extracted ($cliVersion); default data dir ${dataDir}: $dataState"

  Meta "surfaces.install=$method" `
    'surfaces.launch=Start-Process on the installed executable (as the Start menu shortcut does)' `
    "surfaces.import_and_call=release CLI archive $CliAsset from the same release (the CLI is a separate release asset, not inside the desktop installer), on the app's default data directory" `
    'surfaces.gui_driven=no: the installed app was launched and observed (process, top-level window, WebView2 processes), but no UI automation clicked or typed in it'

  # --- launch ------------------------------------------------------------------
  # Returns $null when the process query itself fails (a probe error, not
  # "no webview").
  function Get-WebViewChildren($appPid) {
    try { $all = Get-CimInstance Win32_Process } catch { return $null }
    $ids = @($appPid)
    $found = @()
    for ($round = 0; $round -lt 4; $round++) {
      $kids = @($all | Where-Object { $ids -contains $_.ParentProcessId -and $found.ProcessId -notcontains $_.ProcessId })
      if (-not $kids) { break }
      $found += $kids
      $ids += $kids.ProcessId
    }
    @($found | Where-Object { $_.Name -eq 'msedgewebview2.exe' })
  }

  function Launch($name) {
    $script:Step = $name
    # Windows refusing to load the installed app is the package's failure.
    try { $proc = Start-Process -FilePath $exe -PassThru } catch { Fail $name "Windows could not start ${exe}: $($_.Exception.Message)" }
    $script:appPids += $proc.Id
    $win = $false; $title = ''; $first = 'never'; $web = 0
    for ($i = 1; $i -le $Alive; $i++) {
      Start-Sleep -Seconds 1
      $proc.Refresh()
      if ($proc.HasExited) { Fail $name "the app exited ${i}s after launch with code $($proc.ExitCode)" }
      if (-not $win -and $proc.MainWindowHandle -ne [IntPtr]::Zero) { $win = $true; $title = $proc.MainWindowTitle; $first = "${i}s" }
    }
    $proc.Refresh()
    if ($proc.MainWindowHandle -ne [IntPtr]::Zero) { $win = $true; $title = $proc.MainWindowTitle }
    $children = Get-WebViewChildren $proc.Id
    $probeError = $null -eq $children
    $web = if ($probeError) { 0 } else { @($children).Count }
    $shot = 'none'
    try {
      Add-Type -AssemblyName System.Windows.Forms, System.Drawing
      $b = [Windows.Forms.SystemInformation]::VirtualScreen
      $bmp = New-Object Drawing.Bitmap $b.Width, $b.Height
      $g = [Drawing.Graphics]::FromImage($bmp)
      $g.CopyFromScreen($b.Left, $b.Top, 0, 0, $bmp.Size)
      $bmp.Save((Join-Path $Out "screenshots\$name.png"), [Drawing.Imaging.ImageFormat]::Png)
      $g.Dispose(); $bmp.Dispose()
      $shot = "screenshots/$name.png"
    } catch { }
    try { Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name | Format-Table -AutoSize | Out-String -Width 200 | Set-Content (Join-Path $Logs "$name.processes.txt") } catch { }
    & taskkill.exe /PID $proc.Id /T /F *> $null
    Start-Sleep -Seconds 2
    $logDir = Join-Path $env:LOCALAPPDATA 'com.ferrumedge.anvil\logs'
    $hasLog = Test-Path $logDir
    if ($hasLog) { Copy-Item -Recurse -Force $logDir (Join-Path $Logs "app-log-$name") -ErrorAction SilentlyContinue }
    MetaJson "launches.$name" @{ pid = $proc.Id; alive_seconds = $Alive; top_level_window = $win; window_title = $title; first_window_after = $first; webview_processes = $web; app_log_dir_exists = $hasLog; screenshot = $shot }
    if (-not $win) { Fail $name "the app stayed up ${Alive}s but showed no top-level window" }
    if ($title -ne 'Ferrum Anvil') { Fail $name "the top-level window is titled '$title', expected 'Ferrum Anvil'" }
    if ($web -lt 1 -and $probeError) { HFail $name 'the process query (Get-CimInstance Win32_Process) failed, so a missing WebView2 process proves nothing' }
    if ($web -lt 1) { Fail $name 'the app showed a window but started no WebView2 (msedgewebview2.exe) child process' }
    Pass $name "installed app stayed up ${Alive}s (pid $($proc.Id)); top-level window '$title' after $first; $web WebView2 process(es); screenshot: $shot"
  }

  Launch 'launch_first_run'

  # --- example import and a local call through the release CLI -------------------
  $script:Step = 'profile_create'
  $bytes = New-Object byte[] 24
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  $env:ANVIL_PASSPHRASE = 'rel001-' + (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
  $pcLog = Join-Path $Logs 'profile-create.log'
  # The release CLI's failures are the package's, unless the runner's disk is
  # at fault.
  try { (& $cli profile create rel001-smoke 2>&1) | ForEach-Object { "$_" -replace 'RECOVERY KEY.*', 'RECOVERY KEY (withheld from the log)' } | Set-Content $pcLog } catch { Fail 'profile_create' "the release CLI could not run: $($_.Exception.Message)" }
  if ($LASTEXITCODE) { FailUnlessRunner 'profile_create' (Tail $pcLog 20) "anvil profile create exited ${LASTEXITCODE}: $(Tail $pcLog)" }
  try { & $cli profile list *> (Join-Path $Logs 'profile-list.txt') } catch { Fail 'profile_create' "the release CLI could not run: $($_.Exception.Message)" }
  if ($LASTEXITCODE) { FailUnlessRunner 'profile_create' (Tail (Join-Path $Logs 'profile-list.txt') 20) "anvil profile list exited ${LASTEXITCODE}" }
  Pass 'profile_create' "passphrase profile created with the release CLI in ${dataDir}: $(Get-Content $pcLog -TotalCount 1)"

  $script:Step = 'example_import'
  try { & $cli import $example 2> (Join-Path $Logs 'import.stderr') | Set-Content (Join-Path $Logs 'import-report.json') } catch { Fail 'example_import' "the release CLI could not run: $($_.Exception.Message)" }
  if ($LASTEXITCODE) { FailUnlessRunner 'example_import' (Tail (Join-Path $Logs 'import.stderr') 20) "anvil import exited ${LASTEXITCODE}: $(Tail (Join-Path $Logs 'import.stderr'))" }
  $treeLog = Join-Path $Logs 'workspace-tree.txt'
  try { & $cli workspace tree $WS *> $treeLog } catch { Fail 'example_import' "the release CLI could not run: $($_.Exception.Message)" }
  if ($LASTEXITCODE) { FailUnlessRunner 'example_import' (Tail $treeLog 20) "anvil workspace tree '$WS' failed: $(Tail $treeLog)" }
  $tree = "$(Get-Content -Raw $treeLog -ErrorAction SilentlyContinue)"
  foreach ($r in $SampleRequests) { if (-not $tree.Contains($r)) { Fail 'example_import' "the imported workspace has no request '$r'" } }
  Pass 'example_import' "imported the sample bundle samples/workspaces/anvil-samples.anvil (sha256 $exampleSha) with the release CLI; workspace '$WS' holds all $($SampleRequests.Count) sample requests"

  $script:Step = 'local_call'
  $reqLog = Join-Path $Logs 'local-server-requests.jsonl'
  # The listener is the harness's.
  try {
    $script:serverProc = Start-Process -FilePath 'python' -ArgumentList @('-I', "`"$(Join-Path $here 'local-server.py')`"", '--port', '18080', '--log', "`"$reqLog`"") `
      -PassThru -NoNewWindow -RedirectStandardError (Join-Path $Logs 'local-server.log')
  } catch { HFail 'local_call' "the loopback listener could not be started: $($_.Exception.Message)" }
  $up = $false
  for ($i = 0; $i -lt 30 -and -not $up; $i++) {
    try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 1 -Uri 'http://127.0.0.1:18080/__ready' | Out-Null; $up = $true } catch { Start-Sleep -Milliseconds 500 }
  }
  if (-not $up) { HFail 'local_call' 'the loopback listener on 127.0.0.1:18080 did not start' }
  try { $before = [int](& python -I $RecordPy requests --log $reqLog --method GET --path /ok/echo) } catch { HFail 'local_call' "cannot read the listener's request log: $($_.Exception.Message)" }
  try { & $cli send 'Healthy/OK' --workspace $WS --json 2> (Join-Path $Logs 'send.stderr') | Set-Content (Join-Path $Logs 'send.json') } catch { Fail 'local_call' "the release CLI could not run: $($_.Exception.Message)" }
  $rc = $LASTEXITCODE
  $listenerAlive = -not $script:serverProc.HasExited
  try { $after = [int](& python -I $RecordPy requests --log $reqLog --method GET --path /ok/echo) } catch { HFail 'local_call' "cannot read the listener's request log: $($_.Exception.Message)" }
  $statuses = (& python -I $RecordPy statuses (Join-Path $Logs 'send.json') 2>$null) -join ' '
  try { & $cli history -n 5 --workspace $WS *> (Join-Path $Logs 'history.txt') } catch { }
  Stop-Process -Id $script:serverProc.Id -Force -ErrorAction SilentlyContinue
  $script:serverProc = $null
  # A listener that died during the call explains a failed call: harness.
  if (-not $listenerAlive) { HFail 'local_call' "the loopback listener exited during the call: $(Tail (Join-Path $Logs 'local-server.log') 3)" }
  if ($rc -ne 0) { FailUnlessRunner 'local_call' (Tail (Join-Path $Logs 'send.stderr') 20) "anvil send exited ${rc}: $(Tail (Join-Path $Logs 'send.stderr'))" }
  if ($after -le $before) { Fail 'local_call' 'the loopback listener logged no GET /ok/echo' }
  if (" $statuses " -notlike '* 200 *') { Fail 'local_call' "the execution record shows no HTTP 200 (statuses found: $statuses)" }
  try { $ua = ((Get-Content $reqLog | Where-Object { $_ -like '*/ok/echo*' } | Select-Object -Last 1) | ConvertFrom-Json).user_agent } catch { $ua = 'unknown' }
  Meta "local_call.request=Healthy/OK in '$WS'" 'local_call.url=http://127.0.0.1:18080/ok/echo' "local_call.user_agent=$ua"
  MetaJson 'local_call.exit_code' $rc
  MetaJson 'local_call.listener_requests' ($after - $before)
  Pass 'local_call' "anvil send 'Healthy/OK' made GET http://127.0.0.1:18080/ok/echo; the loopback listener logged $($after - $before) request(s) (User-Agent: $ua) and answered 200; exit 0"

  Launch 'launch_with_example'
  Write-Host "REL-001 smoke for $($env:TARGET_ID) finished; finalize with record.py."
} catch {
  # Safety net: an error no mapping anticipated is recorded, with its step
  # and message, as `unclassified` instead of ending the job silently.
  $msg = "unexpected error in step $($script:Step): $($_.Exception.Message) (at $($_.InvocationInfo.PositionMessage -replace '\s+', ' '))"
  try { Rec @('step', '--dir', $Out, '--name', $script:Step, '--result', 'fail', '--failure-class', 'unclassified', '--detail', $msg) } catch { }
  Write-Host "::error title=$($env:TARGET_ID) $($script:Step) (unclassified failure)::$msg"
  exit 1
} finally {
  foreach ($p in $script:appPids) { & taskkill.exe /PID $p /T /F *> $null }
  if ($script:serverProc) { Stop-Process -Id $script:serverProc.Id -Force -ErrorAction SilentlyContinue }
}
# Reached only when every step passed (Fail exits 1 above). The cleanup's
# taskkill of already-stopped processes leaves a non-zero $LASTEXITCODE that
# would otherwise become the step's exit code.
exit 0
