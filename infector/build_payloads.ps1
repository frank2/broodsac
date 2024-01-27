param([string]$cmake,
      [string]$infection,
      [string]$binary_dir,
      [string]$config)

$cmake = (Resolve-Path -Path $cmake).Path
$infection = (Resolve-Path -Path $infection).Path
$binary_dir = (Resolve-Path -Path $binary_dir).Path
$payload32 = ("{0}/32" -f $binary_dir)
$payload64 = ("{0}/64" -f $binary_dir)

if (!(Test-Path -Path $payload32))
{
    New-Item -Path $binary_dir -Name "32" -ItemType Directory -Force
}

Push-Location $payload32

if (!(Test-Path -Path ("{0}/CMakeCache.txt" -f $payload32) -PathType Leaf))
{
    $cmake -A Win32 ("{0}/32" -f $infection)
}

$cmake --build ./ --config $config
Pop-Location

if (!(Test-Path -Path $payload64))
{
    New-Item -Path $binary_dir -Name "64" -ItemType Directory -Force
}

Push-Location $payload64

if (!(Test-Path -Path ("{0}/CMakeCache.txt" -f $payload64) -PathType Leaf))
{
    $cmake -A Win64 ("{0}/64" -f $infection)
}

$cmake --build ./ --config $config
Pop-Location

