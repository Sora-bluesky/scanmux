param([Parameter(Mandatory=$true)][string]$OutputDirectory, [string]$SourcePath)
$ErrorActionPreference = 'Stop'
$env:PSModulePath = Join-Path $PSHOME 'Modules'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$source = if ($SourcePath) { [IO.Path]::GetFullPath($SourcePath) } else { [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../internal/windows-process-owner.cs')) }
$destination = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $destination) { throw 'Use a new dedicated output directory.' }
[void][IO.Directory]::CreateDirectory($destination)
$assembly = Join-Path $destination 'scanmux-windows-process-owner.exe'
$compiler = [System.CodeDom.Compiler.CompilerParameters]::new()
$compiler.CompilerOptions = '/platform:x64 /optimize+'
$compiler.GenerateExecutable = $true
$compiler.GenerateInMemory = $false
$compiler.OutputAssembly = $assembly
$compiler.TempFiles = [System.CodeDom.Compiler.TempFileCollection]::new($destination, $false)
[void]$compiler.ReferencedAssemblies.Add('System.dll')
[void]$compiler.ReferencedAssemblies.Add('System.Core.dll')
[void]$compiler.ReferencedAssemblies.Add('System.Web.Extensions.dll')
Add-Type -Path $source -CompilerParameters $compiler
if (!(Test-Path -LiteralPath $assembly -PathType Leaf)) { throw 'Process owner build did not produce an assembly.' }
@{ schema='scanmux.windows-process-owner-build/v1'; version='1.4.0'; sourceSha256=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant(); assemblySha256=(Get-FileHash -LiteralPath $assembly -Algorithm SHA256).Hash.ToLowerInvariant(); assemblyBytes=(Get-Item -LiteralPath $assembly).Length } | ConvertTo-Json -Compress
