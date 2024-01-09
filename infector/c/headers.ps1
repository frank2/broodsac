param([string]$infection32,
      [string]$infection64,
      [string]$output)

function Dump-Binary {
    param([string]$filename, [string]$label)

    $bytes = [System.IO.File]::ReadAllBytes($filename);
    $total = $bytes.Length;

    write-output ("const unsigned char {0}[] = {{" -f $label)

    for ($total; $total -gt 16; $total -= 16)
    {
        $start = $bytes.Length - $total;
        write-output ("`t{0}," -f ($bytes[$start..($start+15)] -join ', '))
    }

    if ($total -gt 0)
    {
        write-output ("`t{0}" -f ($bytes[($bytes.Length-$total)..$bytes.Length] -join ', '))
    }
    
    write-output "};"
}

Dump-Binary -filename $infection32 -label "infection32" | Out-File -FilePath $output -Encoding UTF8
Dump-Binary -filename $infection64 -label "infection64" | Out-File -FilePath $output -Encoding UTF8 -Append
