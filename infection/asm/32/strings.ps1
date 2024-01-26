param([string]$launch_command,
      [string]$download_command,
      [string]$output)

function Encrypt-String {
    param([string]$str, [string]$label)

    Write-Output $str
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($str);
    $total = $bytes.Length;
    $key = (Get-Random -Minimum 0x40 -Maximum 0xF0)

    Write-Output ("%macro {0} 0" -f $label)
    
    for ($i=0; $i -lt $total; $i += 1)
    {
        $bytes[$i] = $bytes[$i] -bxor $key; # this is stupid, go away powershell
    }
    
    Write-Output ("    dd {0}" -f $total)
    Write-Output ("    db {0}" -f $key)

    for ($total; $total -gt 16; $total -= 16)
    {
        $start = $bytes.Length - $total;
        write-output ("    db {0}," -f ($bytes[$start..($start+15)] -join ', '))
    }

    if ($total -gt 0)
    {
        write-output ("    db {0}," -f ($bytes[($bytes.Length-$total)..$bytes.Length] -join ', '))
    }

    write-output ("    db 0")
    write-output ("%endmacro")
}

Encrypt-String -str $launch_command -label "LAUNCH_COMMAND" | Out-File -FilePath $output -Encoding UTF8
Encrypt-String -str $download_command -label "DOWNLOAD_COMMAND" | Out-File -FilePath $output -Encoding UTF8 -Append
