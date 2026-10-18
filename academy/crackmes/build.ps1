# Builds the Academy crackmes with rustc. The resulting .exe files are committed in
# bin/ and embedded in ORRESS, so users do not need to build anything.
#
#   powershell -ExecutionPolicy Bypass -File academy\crackmes\build.ps1
#       builds only the crackmes that have no bin\<name>.exe yet (new ones)
#   ... build.ps1 -Only crackme05[,crackme06]
#       rebuilds these, after changing their source
#
# Rebuilding is not byte-identical (the linker writes a timestamp and a PDB id), and
# ORRESS keeps a learner's names and comments per file hash, so a rebuilt crackme loses
# them. Only rebuild a crackme whose source changed, and check that the addresses its
# lessons quote still match (orress-cli disasm / strings).
#
# opt-level=1 keeps the code close to the source (opt-level=0 adds a lot of noise,
# higher levels merge and reorder too much for beginners). panic=abort and stripped
# symbols keep the files small; the lessons teach you to find main without names.

param([string[]]$Only = @())

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
New-Item -ItemType Directory -Force (Join-Path $here "bin") | Out-Null

# Every crackmeNN.rs here; ORRESS embeds each one that has a built bin\crackmeNN.exe.
$names = Get-ChildItem (Join-Path $here "crackme*.rs") | ForEach-Object { $_.BaseName } | Sort-Object
foreach ($n in $Only) {
    if ($names -notcontains $n) { throw "no source $n.rs in $here" }
}
foreach ($name in $names) {
    $src = Join-Path $here "$name.rs"
    $exe = Join-Path $here "bin\$name.exe"
    $wanted = if ($Only.Count -gt 0) { $Only -contains $name } else { -not (Test-Path $exe) }
    if (-not $wanted) { continue }
    rustc --edition 2024 -C opt-level=1 -C panic=abort -C debuginfo=0 -C strip=symbols `
        -C codegen-units=1 --remap-path-prefix "$here=crackmes" $src -o $exe
    if ($LASTEXITCODE -ne 0) { throw "building $name failed" }
    Remove-Item -ErrorAction SilentlyContinue (Join-Path $here "bin\$name.pdb")
    Write-Host "built $exe"
}
