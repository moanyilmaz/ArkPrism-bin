param(
    [Parameter(Mandatory=$true)][string]$JdkHome,
    [Parameter(Mandatory=$true)][string]$Es2abc,
    [string]$LibraryDirectory = 'dist/ArkPrism-bin-latest-20261102/lib'
)
$ErrorActionPreference = 'Stop'
$repository = Split-Path $PSScriptRoot -Parent
Push-Location $repository
try {
    $work = Join-Path $repository ('target/reachability-tests-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path "$work/classes" -Force | Out-Null
    $dependencies = @(Get-ChildItem $LibraryDirectory -Filter '*.jar' | Where-Object Name -ne 'arkprism-main.jar' | ForEach-Object FullName) -join ';'
    Get-ChildItem src/main/java -Recurse -Filter '*.java' | ForEach-Object { '"' + $_.FullName.Replace('\','/') + '"' } | Set-Content "$work/sources.txt" -Encoding utf8
    & "$JdkHome/bin/javac.exe" --release 21 -encoding UTF-8 -cp $dependencies -d "$work/classes" "@$work/sources.txt"
    if ($LASTEXITCODE -ne 0) { throw 'Source compilation failed' }
    $classpath = "$work/classes;$dependencies"

    function New-Sample([string]$name, [string]$entrySource) {
        $app = Join-Path "$work/input" $name
        foreach ($module in @('entry','@sample')) {
            New-Item -ItemType Directory -Force "$app/$module/ets" | Out-Null
            $type = if ($module -eq 'entry') { 'entry' } else { 'shared' }
            @{ app=@{bundleName='org.example.reachability'}; module=@{name=$module;type=$type} } | ConvertTo-Json | Set-Content "$app/$module/module.json"
        }
        & $Es2abc --module --merge-abc --record-name entry --target-api-version 12 --output "$app/entry/ets/modules.abc" "tests/fixtures/library-reachability/$entrySource.js"
        if ($LASTEXITCODE -ne 0) { throw 'Entry ABC compilation failed' }
        & $Es2abc --module --merge-abc --record-name sdk --target-api-version 12 --output "$app/@sample/ets/modules.abc" tests/fixtures/library-reachability/sdk.js
        if ($LASTEXITCODE -ne 0) { throw 'Library ABC compilation failed' }
        return $app
    }
    function Analyze([string]$inputPath, [string]$name, [bool]$disabled=$false) {
        $vm = @('-Xms128m','-Xmx2g','-Xss16m')
        if ($disabled) { $vm += '-Dfilter.library.apis=false' }
        & "$JdkHome/bin/java.exe" @vm -cp $classpath com.huawei.hisec.Main $inputPath config/privacy_apis.json "$work/output/$name" *> "$work/$name.log"
        if ($LASTEXITCODE -ne 0) { throw "Analysis failed: $name" }
        $files = @(Get-ChildItem "$work/output/$name" -Recurse -Filter '*privacy_report.json')
        if ($files.Count -eq 0) { throw "No reports: $name" }
        return @($files | ForEach-Object { Get-Content $_.FullName -Raw | ConvertFrom-Json })
    }
    function Check([bool]$condition, [string]$message) {
        if (-not $condition) { throw $message }
        Write-Output "PASS: $message"
    }
    $called = New-Sample 'called' 'entry'
    $unused = New-Sample 'unused' 'not-called'
    $same = New-Sample 'same-api' 'same-api'
    $callback = New-Sample 'callback' 'callback'
    $dynamic = New-Sample 'dynamic' 'dynamic'
    $transitive = New-Sample 'transitive' 'transitive'
    & $Es2abc --module --merge-abc --record-name forward --target-api-version 12 --output "$transitive/@sample/ets/forward.abc" tests/fixtures/library-reachability/forward.js
    if ($LASTEXITCODE -ne 0) { throw 'Forwarding ABC compilation failed' }

    $r = @(Analyze $called 'called')[0]
    Check ($r.privacyApiUsages.Count -eq 1 -and $r.privacyApiUsages[0].declaringMethod -eq 'used' -and $r.libraryFiltering.removedUnreachable -eq 1) 'cross-ABC called API retained, unused function removed'
    Check ($r.privacyApiUsages[0].entryReachability.status -eq 'reachable' -and $r.privacyApiUsages[0].entryReachability.path.Count -ge 2) 'entry-to-library evidence path emitted'
    Check ($r.callChains[0].entryMethod.name -eq 'onCreate') 'library call chain starts at application lifecycle'
    $r = @(Analyze $unused 'unused')[0]
    Check ($r.privacyApiUsages.Count -eq 0 -and $r.libraryFiltering.removedUnreachable -eq 2) 'library without application callers excluded'
    $r = @(Analyze $same 'same')[0]
    Check ($r.privacyApiUsages.Count -eq 1 -and $r.privacyApiUsages[0].codeOrigin -eq 'app' -and $r.libraryFiltering.removedUnreachable -eq 2) 'same API in app does not retain unrelated library call sites'
    $r = @(Analyze $callback 'callback')[0]
    Check (@($r.privacyApiUsages | Where-Object { $_.declaringMethod -eq 'used' -and $_.entryReachability.status -eq 'reachable' }).Count -eq 1) 'registered imported callback remains reachable'
    $r = @(Analyze $dynamic 'dynamic')[0]
    Check ($r.libraryFiltering.removedUnreachable -eq 0 -and $r.libraryFiltering.retainedUnknown -eq 2) 'unresolved dynamic calls retain unknown library hits'
    $r = @(Analyze $transitive 'transitive')[0]
    Check ($r.libraryFiltering.retainedReachable -eq 1 -and $r.libraryFiltering.removedUnreachable -eq 1 -and $r.privacyApiUsages[0].entryReachability.path.Count -eq 3) 'three-ABC transitive import path'
    $r = @(Analyze $called 'disabled' $true)[0]
    Check ($r.privacyApiUsages.Count -eq 2 -and -not $r.libraryFiltering.enabled) 'explicit disable retains full library inventory'
    $batch = @(Analyze "$work/input" 'batch')
    Check ($batch.Count -eq 6) 'batch preserves separate application boundaries'
    $isolated = @($batch | Where-Object projectName -eq 'unused')[0]
    Check ($isolated.libraryFiltering.removedUnreachable -eq 2 -and $isolated.privacyApiUsages.Count -eq 0) 'another app cannot make unused library functions reachable'
    foreach ($report in $batch) {
        Check ($report.summary.totalApiUsages -eq $report.privacyApiUsages.Count -and $report.summary.callChainCount -eq $report.callChains.Count -and $report.summary.warnings.Count -eq 0) "consistent report: $($report.projectName)"
        foreach ($chain in $report.callChains) { if ($chain.apiUsageIndex -lt 0 -or $chain.apiUsageIndex -ge $report.privacyApiUsages.Count) { throw 'Invalid API index' } }
    }
    $incomplete = New-Sample 'incomplete' 'not-called'
    Set-Content "$incomplete/@sample/ets/broken.abc" 'invalid bytecode'
    $r = @(Analyze $incomplete 'incomplete')[0]
    Check ($r.libraryFiltering.removedUnreachable -eq 0 -and $r.libraryFiltering.retainedUnknown -eq 2 -and $r.summary.warnings.Count -gt 0) 'missing ABC information prevents false exclusion'
    $inline = Join-Path $work 'inline'
    New-Item -ItemType Directory -Force "$inline/ets" | Out-Null
    Set-Content "$inline/module.json" '{"module":{"type":"entry"}}'
    & $Es2abc --module --merge-abc --record-name entry --target-api-version 12 --output "$inline/ets/modules.abc" tests/fixtures/library-reachability/inline-library.js
    if ($LASTEXITCODE -ne 0) { throw 'Inline application compile failed' }
    & $Es2abc --module --merge-abc --record-name entry/oh_modules/sample/sdk --target-api-version 12 --output "$inline/ets/library.abc" tests/fixtures/library-reachability/sdk.js
    if ($LASTEXITCODE -ne 0) { throw 'Inline SDK compile failed' }
    $r = @(Analyze $inline 'inline')[0]
    Check ($r.libraryFiltering.retainedReachable -eq 1 -and $r.libraryFiltering.removedUnreachable -eq 1) 'embedded oh_modules record provenance identifies library code'
    $singleBatch = Join-Path $work 'single-module-batch'
    New-Item -ItemType Directory -Force $singleBatch | Out-Null
    Copy-Item -LiteralPath "$same/entry" -Destination "$singleBatch/app-one" -Recurse
    Copy-Item -LiteralPath "$same/entry" -Destination "$singleBatch/app-two" -Recurse
    $r = @(Analyze $singleBatch 'same-bundle-batch')
    Check ($r.Count -eq 2) 'two entry apps sharing bundle name are not merged'
    Write-Output "All reachability regressions passed. Evidence: $work"
} finally { Pop-Location }
