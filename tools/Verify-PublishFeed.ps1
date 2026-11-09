#requires -Version 7.4
# PUBLIC downloads-repository verifier/promoter. Contains only the product PUBLIC key.
param([ValidateSet('windows','android')][string]$Platform='windows',[string]$Version='', [string]$ManifestSha256='')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:Repository='Mostsport/smart-analysis-releases'
$script:ProductKey='MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEO3fM0oGQhMaqIt6MQ1fE46oG+pVOjpLH3GAEpBHDp2TxdzF0harvsKUCgH0+rwzsmCUsgaEQ4sRy+8tg/CFJeA=='
function Assert-Version([string]$Version) {
    if ($Version -cnotmatch '^(0|[1-9][0-9]{0,8})(\.(0|[1-9][0-9]{0,8})){2,3}$') { throw 'Use a three/four component numeric version.' }
    $null = [Version]::Parse($Version)
}
function Get-NormalVersion([string]$Version) {
    Assert-Version $Version
    $v=[Version]::Parse($Version)
    [Version]::new($v.Major,$v.Minor,[Math]::Max(0,$v.Build),[Math]::Max(0,$v.Revision))
}
function Read-StrictJson([string]$Text) {
    $doc=[Text.Json.JsonDocument]::Parse($Text)
    try {
        function Walk($node) {
            if ($node.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
                $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                foreach ($p in $node.EnumerateObject()) { if (!$seen.Add($p.Name)) { throw 'Duplicate JSON property.' }; Walk $p.Value }
            } elseif ($node.ValueKind -eq [Text.Json.JsonValueKind]::Array) { foreach ($v in $node.EnumerateArray()) { Walk $v } }
        }
        Walk $doc.RootElement
        $Text | ConvertFrom-Json -AsHashtable
    } finally { $doc.Dispose() }
}
function Read-SignedUpdate([string]$Text,[string]$PublicKey=$script:ProductKey) {
    if ($Text.Length -gt 32768 -or $Text -cnotmatch '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$') { throw 'Invalid signed feed.' }
    function Decode($v) { [Convert]::FromBase64String($v.Replace('-','+').Replace('_','/') + ('=' * ((4-$v.Length%4)%4))) }
    $parts=$Text.Split('.'); $bytes=Decode $parts[0]; $sig=Decode $parts[1]
    $key=[Security.Cryptography.ECDsa]::Create()
    try {
        $key.ImportSubjectPublicKeyInfo([Convert]::FromBase64String($PublicKey),[ref]0)
        if (!$key.VerifyData($bytes,$sig,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation)) { throw 'Invalid signature.' }
    } finally { $key.Dispose() }
    $m=Read-StrictJson ([Text.UTF8Encoding]::new($false,$true).GetString($bytes))
    $fields=@('schema','purpose','product','platform','applicationId','version','versionCode','protocol','architecture','size','sha256','url','notesAr','notesEn','publishedUtc')
    if ($m.Count -ne $fields.Count -or @($m.Keys | Where-Object { $_ -cnotin $fields }).Count) { throw 'Invalid feed fields.' }
    foreach ($field in @('schema','protocol','size','versionCode')) { if ($m[$field] -isnot [int] -and $m[$field] -isnot [long]) { throw 'Feed numeric fields must be integers.' } }
    if ($m.schema -ne 1 -or $m.protocol -ne 1 -or $m.purpose -cne 'smart-analysis.update' -or $m.product -cne 'smart-analysis') { throw 'Invalid update identity.' }
    Assert-Version $m.version
    if ($m.platform -ceq 'windows') { if ($m.applicationId -cne 'SmartAnalysisV2' -or $m.architecture -cne 'x64' -or $m.versionCode -ne 0) { throw 'Invalid Windows identity.' } }
    elseif ($m.platform -ceq 'android') { if ($m.applicationId -cne 'com.smartanalysis.app' -or $m.architecture -cne 'android' -or $m.versionCode -le 0) { throw 'Invalid Android identity.' } }
    else { throw 'Invalid platform.' }
    if ($m.size -le 0 -or $m.size -gt 536870912 -or $m.sha256 -notmatch '^[a-fA-F0-9]{64}$' -or $m.notesAr -isnot [string] -or $m.notesEn -isnot [string] -or $m.notesAr.Length -gt 4000 -or $m.notesEn.Length -gt 4000) { throw 'Invalid size/hash/notes.' }
    $null=[DateTimeOffset]::Parse($m.publishedUtc)
    $extension=if ($m.platform -eq 'windows') { 'zip' } else { 'apk' }
    $expected="https://github.com/$script:Repository/releases/download/$($m.platform)-$($m.version)/SmartAnalysis-$($m.platform)-$($m.version).$extension"
    if ($m.url -cne $expected) { throw 'Artifact URL must be the exact immutable version URL.' }
    return $m
}
function Assert-FileHash($Path,$Size,$Hash) {
    if ((Get-Item -LiteralPath $Path).Length -ne $Size -or (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ne $Hash) { throw 'Artifact size/SHA256 mismatch.' }
}
function Invoke-CheckedTool([string]$File,[string[]]$Arguments) {
    $info=[Diagnostics.ProcessStartInfo]::new($File); $info.UseShellExecute=$false; $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true; $info.CreateNoWindow=$true
    foreach ($a in $Arguments) { $info.ArgumentList.Add($a) }
    $p=[Diagnostics.Process]::Start($info)
    try {
        $out=$p.StandardOutput.ReadToEndAsync(); $err=$p.StandardError.ReadToEndAsync()
        if (!$p.WaitForExit(300000)) { $p.Kill($true); throw 'Tool timed out.' }
        $null=$err.GetAwaiter().GetResult() # Never echo authentication/tool diagnostics (may contain secrets).
        if ($p.ExitCode -ne 0) { throw "Tool failed: $([IO.Path]::GetFileName($File)) (exit $($p.ExitCode))." }
        $out.GetAwaiter().GetResult()
    } finally { $p.Dispose() }
}
function Get-PublicAsset {
    param($url,$destination)
    $handler=[Net.Http.HttpClientHandler]::new(); $handler.AllowAutoRedirect=$false
    $client=[Net.Http.HttpClient]::new($handler); $client.Timeout=[TimeSpan]::FromMinutes(5)
    $timeout=[Threading.CancellationTokenSource]::new([TimeSpan]::FromMinutes(5))
    try {
        $uri=[Uri]$url
        for ($redirect=0; $redirect -le 5; $redirect++) {
            if ($uri.Scheme -cne 'https' -or !$uri.IsDefaultPort -or $uri.UserInfo -or $uri.Host -notin @('github.com','release-assets.githubusercontent.com','objects.githubusercontent.com')) { throw 'Unsafe release redirect.' }
            $response=$client.GetAsync($uri,[Net.Http.HttpCompletionOption]::ResponseHeadersRead,$timeout.Token).GetAwaiter().GetResult()
            try {
                if ([int]$response.StatusCode -in @(301,302,303,307,308)) { $uri=[Uri]::new($uri,$response.Headers.Location); continue }
                $null=$response.EnsureSuccessStatusCode()
                if ($response.Content.Headers.ContentLength -gt 536870912) { throw 'Download too large.' }
                $input=$response.Content.ReadAsStream(); $output=[IO.File]::Create($destination)
                try {
                    $buffer=[byte[]]::new(65536); $count=0L
                    while (($read=$input.ReadAsync($buffer,0,$buffer.Length,$timeout.Token).GetAwaiter().GetResult()) -gt 0) { $count+=$read; if ($count -gt 536870912) { throw 'Download too large.' }; $output.Write($buffer,0,$read) }
                } finally { $input.Dispose(); $output.Dispose() }
                return
            } finally { $response.Dispose() }
        }
        throw 'Too many redirects.'
    } finally { $timeout.Dispose(); $client.Dispose() }
}

function Invoke-CentralPromotion($Manifest,[string]$Candidate,[scriptblock]$Gh,[scriptblock]$Download,[string]$TemporaryDirectory) {
    # ONLY called from the vetted Actions workflow while its per-platform concurrency lock is held.
    $releases=ConvertFrom-Json -InputObject (& $Gh @('api',"repos/$script:Repository/releases",'--paginate','--slurp','-q','add'))
    $stable=@($releases | Where-Object { $_.tag_name -ceq 'updates' })
    if ($stable.Count) {
        if ($stable[0].draft -or $stable[0].prerelease) { throw 'Stable release is not public/final.' }
        $details=Read-StrictJson (& $Gh @('release','view','updates','--repo',$script:Repository,'--json','assets'))
        if (@($details.assets | Where-Object { $_.name -ceq "$($Manifest.platform)-update.saup" }).Count) {
            $previousFile=Join-Path $TemporaryDirectory 'previous.saup'
            $null=& $Download "https://github.com/$script:Repository/releases/download/updates/$($Manifest.platform)-update.saup" $previousFile
            $previous=Read-SignedUpdate ([IO.File]::ReadAllText($previousFile))
            if ($previous.platform -cne $Manifest.platform) { throw 'Wrong stable platform.' }
            $order=(Get-NormalVersion $Manifest.version).CompareTo((Get-NormalVersion $previous.version))
            if ($order -lt 0 -or ($Manifest.platform -ceq 'android' -and $Manifest.versionCode -lt $previous.versionCode)) { throw 'Downgrade refused under central platform lock.' }
            if ($order -eq 0) {
                if ((Get-FileHash -LiteralPath $Candidate).Hash -ne (Get-FileHash -LiteralPath $previousFile).Hash) { throw 'Same version conflicting signed metadata/bytes.' }
                return 'Already promoted; identical signed feed.'
            }
            if ($Manifest.platform -ceq 'android' -and $Manifest.versionCode -le $previous.versionCode) { throw 'Android versionCode must increase.' }
        }
    }
    # Verify actual artifact again INSIDE serialized promotion, immediately before stable write.
    $downloaded=Join-Path $TemporaryDirectory 'artifact'
    $null=& $Download $Manifest.url $downloaded
    Assert-FileHash $downloaded $Manifest.size $Manifest.sha256
    if (!$stable.Count) { $null=& $Gh @('release','create','updates','--repo',$script:Repository,'--title','Update feeds','--notes','Signed optional update feeds') }
    $null=& $Gh @('release','upload','updates',$Candidate,'--repo',$script:Repository,'--clobber')
    $result=Join-Path $TemporaryDirectory 'public-result.saup'
    $null=& $Download "https://github.com/$script:Repository/releases/download/updates/$($Manifest.platform)-update.saup" $result
    Assert-FileHash $result (Get-Item -LiteralPath $Candidate).Length (Get-FileHash -LiteralPath $Candidate).Hash
    'Promoted and independently verified under central platform lock.'
}
if ($MyInvocation.InvocationName -ne '.') {
    if ($env:GITHUB_ACTIONS -cne 'true' -or $env:GITHUB_REPOSITORY -cne $script:Repository -or $env:GITHUB_WORKFLOW_REF -notlike 'Mostsport/smart-analysis-releases/.github/workflows/publish-updates.yml@refs/heads/*') { throw 'Stable promotion requires the vetted GitHub Actions workflow.' }
    Assert-Version $Version
    if ($ManifestSha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'Invalid candidate hash.' }
    $temp=Join-Path ([IO.Path]::GetTempPath()) ('sa-promote-'+[guid]::NewGuid())
    New-Item -ItemType Directory $temp | Out-Null
    try {
        $candidate=Join-Path $temp "$Platform-update.saup"
        Get-PublicAsset "https://github.com/$script:Repository/releases/download/$Platform-$Version/$Platform-update.saup" $candidate
        if ((Get-FileHash -LiteralPath $candidate).Hash -ne $ManifestSha256) { throw 'Candidate metadata hash mismatch.' }
        $manifest=Read-SignedUpdate ([IO.File]::ReadAllText($candidate))
        if ($manifest.platform -cne $Platform -or $manifest.version -cne $Version) { throw 'Candidate identity mismatch.' }
        $gh={param($arguments) Invoke-CheckedTool 'gh' $arguments}
        $download={param($url,$destination) Get-PublicAsset $url $destination}
        Invoke-CentralPromotion $manifest $candidate $gh $download $temp
    } finally {
        $parent=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('/','\')
        $resolved=[IO.Path]::GetFullPath($temp).TrimEnd('/','\')
        if ([IO.Path]::GetDirectoryName($resolved) -cne $parent -or [IO.Path]::GetFileName($resolved) -notmatch '^sa-promote-[a-f0-9-]{36}$' -or ((Get-Item -LiteralPath $resolved).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unsafe promotion cleanup target.' }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
