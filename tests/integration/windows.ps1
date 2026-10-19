param([switch]$SkipBuild, [switch]$KeepRelay, [string]$Executable)
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Set-Location $projectRoot
$fixtures = Join-Path $projectRoot 'work/integration'
$stateDir = Join-Path $fixtures 'windows-state'
$assh = Join-Path $projectRoot 'bin/assh.exe'
if ($Executable) { $assh = (Resolve-Path $Executable).Path }
$container = 'agent-ssh-integration'
$started = $false

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed ($LASTEXITCODE)" }
}

function Get-AsshStatus {
    $raw = & $assh status --state-dir $stateDir --json
    if ($LASTEXITCODE -ne 0) { throw 'status failed' }
    return $raw | ConvertFrom-Json
}

function Wait-Online {
    $deadline = (Get-Date).AddSeconds(75)
    do {
        $status = Get-AsshStatus
        if ($status.phase -eq 'online') { return $status }
        Start-Sleep -Milliseconds 300
    } while ((Get-Date) -lt $deadline)
    throw "Tunnel not online: $($status | ConvertTo-Json -Compress)"
}

try {
    Invoke-Checked docker @('build', '-f', '.devcontainer/Dockerfile', '-t', 'agent-ssh-dev:local', '.')
    if (-not $SkipBuild) {
        Invoke-Checked docker @('run', '--rm', '-v', "${projectRoot}:/workspace", '-v', 'agent_ssh_go_cache:/go/pkg/mod', '-v', 'agent_ssh_go_build:/root/.cache/go-build', '-w', '/workspace', 'agent-ssh-dev:local', 'sh', '-c', 'go test -timeout 90s ./... && go vet ./... && go build -o bin/assh ./cmd/assh && GOOS=windows go build -o bin/assh.exe ./cmd/assh && GOOS=windows go test -c -o bin/localssh.test.exe ./internal/localssh && GOOS=windows go test -c -o bin/state.test.exe ./internal/state && GOOS=windows go test -c -o bin/platform.test.exe ./internal/platform && GOOS=windows go test -c -o bin/app.test.exe ./internal/app && GOOS=windows go test -c -o bin/tunnel.test.exe ./internal/tunnel && GOOS=windows go test -c -o bin/reverseagent.test.exe ./internal/reverseagent')
    }
    Invoke-Checked (Join-Path $projectRoot 'bin/localssh.test.exe') @('-test.v', '-test.timeout=90s')
    Invoke-Checked (Join-Path $projectRoot 'bin/state.test.exe') @('-test.v')
    Invoke-Checked (Join-Path $projectRoot 'bin/platform.test.exe') @('-test.v')
    Invoke-Checked (Join-Path $projectRoot 'bin/app.test.exe') @('-test.v')
    Invoke-Checked (Join-Path $projectRoot 'bin/tunnel.test.exe') @('-test.v','-test.timeout=60s')
    Invoke-Checked (Join-Path $projectRoot 'bin/reverseagent.test.exe') @('-test.v')
    foreach ($package in @('execsvc','filesvc','tools','sysinfo','toolrpc','telemetry')) {
        if (-not $SkipBuild) { Invoke-Checked docker @('run','--rm','-v',"${projectRoot}:/workspace",'-v','agent_ssh_go_cache:/go/pkg/mod','-v','agent_ssh_go_build:/root/.cache/go-build','-w','/workspace','agent-ssh-dev:local','sh','-c',"GOOS=windows go test -c -o bin/$package.test.exe ./internal/$package") }
        Invoke-Checked (Join-Path $projectRoot "bin/$package.test.exe") @('-test.v','-test.timeout=120s')
    }
    New-Item -ItemType Directory -Force $fixtures | Out-Null
    # Isolated disposable keys. Never read or edit the user's ~/.ssh directory.
    Invoke-Checked docker @('run', '--rm', '-v', "${projectRoot}:/workspace", 'agent-ssh-dev:local', 'sh', '-c', 'for name in relay agent; do test -f /workspace/work/integration/$name || ssh-keygen -q -t ed25519 -N "" -f /workspace/work/integration/$name; done')
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    Invoke-Checked icacls @((Join-Path $fixtures 'relay'), '/inheritance:r', '/grant:r', "*${sid}:(F)")
    # Fail rather than remove a pre-existing container owned by another run.
    Invoke-Checked docker @('run', '-d', '--name', $container, '-p', '127.0.0.1:22220:22', '-v', "${projectRoot}:/workspace", '-v', 'agent_ssh_go_cache:/go/pkg/mod', '-v', 'agent_ssh_go_build:/root/.cache/go-build', '-w', '/workspace', 'agent-ssh-dev:local', 'sh', '/workspace/tests/integration/relay-entrypoint.sh')
    $started = $true
    $hostKey = $null
    for ($i = 0; $i -lt 30; $i++) {
        $hostKey = & docker exec $container cat /etc/ssh/ssh_host_ed25519_key.pub 2>$null
        if ($LASTEXITCODE -eq 0 -and $hostKey) { break }
        Start-Sleep -Milliseconds 200
    }
    if (-not $hostKey) { throw 'Relay host key unavailable' }
    "[127.0.0.1]:22220 $hostKey" | Set-Content -Encoding utf8NoBOM (Join-Path $fixtures 'relay_known_hosts')
    $identityPath = (Join-Path $fixtures 'relay').Replace('\', '/')
    $knownPath = (Join-Path $fixtures 'relay_known_hosts').Replace('\', '/')
    @"
Host assh-test
    HostName 127.0.0.1
    User root
    Port 22220
    IdentityFile "$identityPath"
    IdentitiesOnly yes
    UserKnownHostsFile "$knownPath"
    StrictHostKeyChecking yes
"@ | Set-Content -Encoding utf8NoBOM (Join-Path $fixtures 'ssh_config')
    Invoke-Checked $assh @('init', '--state-dir', $stateDir)
    Invoke-Checked $assh @('authorize', '--state-dir', $stateDir, (Join-Path $fixtures 'agent.pub'))
    Invoke-Checked $assh @('start', 'assh-test', '--state-dir', $stateDir, '--workdir', $fixtures, '-F', (Join-Path $fixtures 'ssh_config'), '-o', 'ServerAliveInterval=3', '-o', 'ServerAliveCountMax=3')
    $before = Wait-Online
    Invoke-Checked $assh @('start', '--state-dir', $stateDir, '--workdir', $fixtures, '-F', (Join-Path $fixtures 'ssh_config'), 'assh-test', '-o', 'ServerAliveInterval=3', '-o', 'ServerAliveCountMax=3')
    if ((Get-AsshStatus).pid -ne $before.pid) { throw 'Repeated start replaced the running process' }
    $control = Get-Content (Join-Path $stateDir 'runtime.json') -Raw | ConvertFrom-Json
    $response = Invoke-WebRequest -Uri "http://$($control.address)/status" -SkipHttpErrorCheck
    if ($response.StatusCode -ne 401) { throw 'Unauthenticated local control request was accepted' }
    Write-Host 'PASS idempotent start and authenticated local control'
    Invoke-Checked docker @('exec', $container, 'python3', '/workspace/tests/integration/agent_checks.py')
    # Restart the real Linux SSH server; Windows must reconnect unaided.
    Invoke-Checked docker @('restart', $container)
    $deadline = (Get-Date).AddSeconds(75)
    do {
        Start-Sleep -Milliseconds 300
        $after = Get-AsshStatus
        if ($after.phase -eq 'online' -and $after.attempt -gt $before.attempt) { break }
    } while ((Get-Date) -lt $deadline)
    if ($after.phase -ne 'online' -or $after.attempt -le $before.attempt) { throw 'Automatic reconnection failed' }
    if ($before.device_id -ne $after.device_id -or $before.host_key -ne $after.host_key) { throw 'Device identity changed during reconnection' }
    Write-Host 'PASS automatic reconnection after Linux relay restart; stable device identity'
    Invoke-Checked docker @('exec', $container, 'python3', '/workspace/tests/integration/agent_checks.py')
    $healthDeadline = (Get-Date).AddSeconds(10)
    do {
        $health = Get-AsshStatus
        if ($health.metrics.round_trip_ms -gt 0 -and $health.metrics.received_bytes -gt 0 -and $health.metrics.sent_bytes -gt 0) { break }
        Start-Sleep -Milliseconds 300
    } while ((Get-Date) -lt $healthDeadline)
    if ($health.metrics.round_trip_ms -le 0 -or $health.metrics.received_bytes -le 0 -or $health.metrics.sent_bytes -le 0) { throw "Missing live SSH health metrics: $($health | ConvertTo-Json -Compress -Depth 5)" }
    $events = @(Get-Content (Join-Path $stateDir 'events.jsonl') | ForEach-Object { $_ | ConvertFrom-Json })
    if (-not ($events | Where-Object phase -eq 'online')) { throw 'Missing online event' }
    Write-Host 'PASS live SSH roundtrip, byte counters and connection events'
    Invoke-Checked $assh @('stop', '--state-dir', $stateDir)
    if ((Get-AsshStatus).phase -ne 'stopped') { throw 'Background process still running' }
    # PowerShell 5.1 remains the fallback on stock Windows installations.
    Invoke-Checked $assh @('start', '--state-dir', $stateDir, '--shell', 'powershell.exe', '--workdir', $fixtures, '-F', (Join-Path $fixtures 'ssh_config'), 'assh-test')
    $null = Wait-Online
    Invoke-Checked docker @('exec', $container, 'python3', '/workspace/tests/integration/agent_checks.py')
    Invoke-Checked $assh @('stop', '--state-dir', $stateDir)
    Write-Host 'PASS Windows PowerShell 5.1 fallback and background stop/start'
    # Fresh profile: no authorize and no local OpenSSH authorized_keys required.
    # No files in the relay's .ssh may be added or modified.
    $remoteBefore = & docker exec $container sh -c 'find /root/.ssh -type f -exec sha256sum {} \; | sort'
    Invoke-Checked docker @('exec', '-d', $container, 'python3', '-c', 'import socket,time; a=socket.socket(); a.bind(("127.0.0.1",22222)); a.listen(); b=socket.socket(); b.bind(("127.0.0.1",22223)); b.listen(); open("/tmp/assh-ports-busy","w").close(); time.sleep(600)')
    for ($i = 0; $i -lt 30; $i++) {
        & docker exec $container test -f /tmp/assh-ports-busy
        if ($LASTEXITCODE -eq 0) { break }
        Start-Sleep -Milliseconds 100
    }
    if ($LASTEXITCODE -ne 0) { throw 'Could not occupy test relay ports' }
    $stateDir = Join-Path $fixtures ('auto-state-' + [guid]::NewGuid().ToString('N'))
    Invoke-Checked $assh @('start', 'assh-test', '--state-dir', $stateDir, '--workdir', $fixtures, '-F', (Join-Path $fixtures 'ssh_config'))
    $auto = Wait-Online
    if ($auto.remote_port -ne 22224) { throw "Automatic port selection failed: $($auto.remote_port)" }
    if (-not $auto.agent_socket) { throw 'Agent forwarding did not publish socket' }
    if ((Get-Item (Join-Path $stateDir 'authorized_keys')).Length -ne 0) { throw 'Fresh profile unexpectedly required imported authorization' }
    $stateName = Split-Path -Leaf $stateDir
    Invoke-Checked docker @('exec', $container, 'python3', '/workspace/tests/integration/agent_checks.py', '--state', $stateName, '--agent-socket', $auto.agent_socket, '--port', $auto.remote_port)
    Invoke-Checked $assh @('stop', '--state-dir', $stateDir)
    # Exercise the actual native Windows login argv and in-memory Bash helpers.
    $psi = [Diagnostics.ProcessStartInfo]::new($assh)
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    foreach ($arg in @('assh-test', '--state-dir', $stateDir, '--workdir', $fixtures, '-F', (Join-Path $fixtures 'ssh_config'))) { $psi.ArgumentList.Add($arg) }
    $login = [Diagnostics.Process]::Start($psi)
    $login.StandardInput.NewLine = "`n"
    $loginOut = $login.StandardOutput.ReadToEndAsync()
    $loginErr = $login.StandardError.ReadToEndAsync()
    $owned = Wait-Online
    if ($owned.pid -ne $login.Id) { throw 'Default connection spawned a detached agent process' }
    $info = & $assh info --state-dir $stateDir --json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $info.identity.username) { throw 'Local streaming tool control failed' }
    $login.StandardInput.WriteLine('python3 /workspace/tests/integration/env_checks.py && python3 /workspace/tests/integration/tool_exec_checks.py && python3 /workspace/tests/integration/tool_file_checks.py && python3 /workspace/tests/integration/tool_mcp_checks.py || exit $?; assh ''[Console]::Write("ASSH_HELPER_OK")''; asscp agent@127.0.0.1:relay.pub /tmp/assh-helper-copy; cmp /tmp/assh-helper-copy /workspace/work/integration/relay.pub && echo ASSCP_HELPER_OK; rm -f /tmp/assh-helper-copy; exit')
    $login.StandardInput.Close()
    if (-not $login.WaitForExit(240000)) { $login.Kill($true); throw 'Interactive helper test timed out' }
    $loginText = $loginOut.GetAwaiter().GetResult()
    $loginErrors = $loginErr.GetAwaiter().GetResult()
    $loginText | Set-Content -Encoding utf8NoBOM (Join-Path $fixtures 'tools-login.stdout.log')
    $loginErrors | Set-Content -Encoding utf8NoBOM (Join-Path $fixtures 'tools-login.stderr.log')
    if ($login.ExitCode -ne 0 -or $loginText -notmatch 'ASSH_HELPER_OK' -or $loginText -notmatch 'ASSCP_HELPER_OK' -or $loginText -notmatch 'ASSH_ENV_OK' -or $loginText -notmatch 'ASSH_TEST_REAL_MOTD') { throw "Interactive helpers or real login banner failed: $loginText $loginErrors" }
    foreach ($marker in @('TOOL_EXEC_OK','ASSH_FILES_OK','ASSH_MCP_OK')) { if ($loginText -notmatch $marker) { throw "Agent tool integration missing $marker`: $loginText $loginErrors" } }
    Write-Host 'PASS SSH execution/session/job, verified files/sync/watch, MCP and dry-run'
    Write-Host 'PASS native Windows login and in-memory assh/asscp helpers'
    if ([regex]::Matches($loginText, 'ASSH_TEST_PROFILE_ONCE').Count -ne 1) { throw "Login profile was skipped or loaded twice: $loginText" }
    if ($loginText -match 'ASSH_QUIET_|__assh_data|ASSH_READY_[a-f0-9]') { throw 'Session bootstrap leaked into terminal output' }
    if ((Get-AsshStatus).phase -ne 'stopped') { throw 'SSH exit left the agent service running' }
    Invoke-Checked docker @('exec', $container, 'test', '!', '-e', $owned.agent_socket)
    $env:ASSH_TEST_LOGIN_EXE = $assh
    $env:ASSH_TEST_LOGIN_ARGS = ConvertTo-Json -Compress -InputObject @('assh-test', '--state-dir', $stateDir, '--workdir', $fixtures, '-F', (Join-Path $fixtures 'ssh_config'))
    try { Invoke-Checked (Join-Path $projectRoot 'bin/app.test.exe') @('-test.run=^TestNativeConsoleLogin$', '-test.timeout=60s', '-test.v') }
    finally { Remove-Item Env:ASSH_TEST_LOGIN_EXE, Env:ASSH_TEST_LOGIN_ARGS }
    # Closing/killing the owning terminal process must also release the tunnel.
    $aborted = [Diagnostics.Process]::Start($psi)
    $abortOut = $aborted.StandardOutput.ReadToEndAsync()
    $abortErr = $aborted.StandardError.ReadToEndAsync()
    $owned = Wait-Online
    $aborted.Kill()
    if (-not $aborted.WaitForExit(10000)) { throw 'Default connection process did not exit' }
    if (-not $abortOut.Wait(10000) -or -not $abortErr.Wait(10000)) { throw 'SSH child survived its owning process' }
    $aborted.StandardInput.Close()
    $deadline = (Get-Date).AddSeconds(10)
    do {
        & docker exec $container test '!' -e $owned.agent_socket
        if ($LASTEXITCODE -eq 0) { break }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    if ($LASTEXITCODE -ne 0) { throw 'Owner termination left the remote agent socket alive' }
    if ((Get-AsshStatus).phase -ne 'stopped') { throw 'Owner termination left the service online' }
    Write-Host 'PASS SSH exit and forced owner termination clean up the session agent and SSH children'
    Invoke-Checked $assh @('start', 'assh-test', '--state-dir', $stateDir, '--workdir', $fixtures, '-F', (Join-Path $fixtures 'ssh_config'))
    $auto = Wait-Online
    Invoke-Checked docker @('restart', $container)
    $deadline = (Get-Date).AddSeconds(75)
    do {
        Start-Sleep -Milliseconds 300
        $autoReconnected = Get-AsshStatus
        if ($autoReconnected.phase -eq 'online' -and $autoReconnected.attempt -gt $auto.attempt) { break }
    } while ((Get-Date) -lt $deadline)
    if ($autoReconnected.phase -ne 'online' -or $autoReconnected.attempt -le $auto.attempt) { throw 'Memory-only agent did not recover after relay restart' }
    if ($autoReconnected.remote_port -ne $auto.remote_port) { throw 'Reconnect changed the selected relay port' }
    $auto = $autoReconnected
    Invoke-Checked docker @('exec', $container, 'python3', '/workspace/tests/integration/agent_checks.py', '--state', $stateName, '--agent-socket', $auto.agent_socket, '--port', $auto.remote_port)
    Invoke-Checked docker @('exec', $container, 'sh', '-c', 'test ! -d /root/.ssh/agent_ssh')
    if (Test-Path (Join-Path $stateDir 'relay_pair.json')) { throw 'Memory-only pairing was persisted' }
    Invoke-Checked $assh @('stop', '--state-dir', $stateDir)
    Invoke-Checked docker @('exec', $container, 'test', '!', '-e', $auto.agent_socket)
    Invoke-Checked $assh @('start', 'assh-test', '--state-dir', $stateDir, '--workdir', $fixtures, '-F', (Join-Path $fixtures 'ssh_config'))
    $autoAgain = Wait-Online
    if ($auto.device_id -ne $autoAgain.device_id) { throw 'Device host identity changed on restart' }
    Invoke-Checked docker @('exec', $container, 'python3', '/workspace/tests/integration/agent_checks.py', '--state', $stateName, '--agent-socket', $autoAgain.agent_socket, '--port', $autoAgain.remote_port)
    Invoke-Checked $assh @('stop', '--state-dir', $stateDir)
    Invoke-Checked docker @('exec', $container, 'test', '!', '-e', $autoAgain.agent_socket)
    $remoteAfter = & docker exec $container sh -c 'find /root/.ssh -type f -exec sha256sum {} \; | sort'
    if (($remoteBefore -join "`n") -ne ($remoteAfter -join "`n")) { throw 'Remote OpenSSH files changed' }
    Write-Host 'PASS memory-only agent authorization, socket cleanup and unchanged remote OpenSSH files'
} finally {
    if (Test-Path $assh) {
        $status = Get-AsshStatus
        if ($status.phase -ne 'stopped') { & $assh stop --state-dir $stateDir }
    }
    if ($started -and -not $KeepRelay) { & docker rm -f $container }
}
