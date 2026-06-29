$ini = Get-Content 'c:\Users\YUN\Desktop\SSLClaw\x64\Release\sslclaw.ini' -Raw
$ini = $ini -replace 'autoRenew=1','autoRenew=0'
[System.IO.File]::WriteAllText('c:\Users\YUN\Desktop\SSLClaw\x64\Release\sslclaw.ini', $ini, [System.Text.Encoding]::UTF8)
Write-Host "Done"
