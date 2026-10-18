# Builds the Academy crackmes with rustc. The resulting .exe files are committed in
# bin/ and embedded in ORRESS, so users do not need to build anything. Re-run this
# after changing a crackme source:
#
#   powershell -ExecutionPolicy Bypass -File academy\crackmes\build.ps1
#
# opt-level=1 keeps the code close to the source (opt-level=0 adds a lot of noise,
# higher levels merge and reorder too much for beginners). panic=abort and stripped
# symbols keep the files small; the lessons teach you to find main without names.

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
New-Item -ItemType Directory -Force (Join-Path $here "bin") | Out-Null

# Every crackmeNN.rs here; ORRESS embeds each one that has a built bin\crackmeNN.exe.
$names = Get-ChildItem (Join-Path $here "crackme*.rs") | ForEach-Object { $_.BaseName } | Sort-Object
foreach ($name in $names) {
    $src = Join-Path $here "$name.rs"
    $exe = Join-Path $here "bin\$name.exe"
    rustc --edition 2024 -C opt-level=1 -C panic=abort -C debuginfo=0 -C strip=symbols `
        -C codegen-units=1 --remap-path-prefix "$here=crackmes" $src -o $exe
    if ($LASTEXITCODE -ne 0) { throw "building $name failed" }
    Remove-Item -ErrorAction SilentlyContinue (Join-Path $here "bin\$name.pdb")
    Write-Host "built $exe"
}
