$code = Read-Host "請輸入代碼"

$SuricataExe = "C:\Program Files\Suricata\suricata.exe"
$PcapDir = ".\pcap"
$OutBase = ".\${code}"

mkdir $OutBase

Get-ChildItem -Path $PcapDir -Filter *.pcap | ForEach-Object {
    $name = $_.BaseName
    $outDir = Join-Path $OutBase $name
    if (-not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir | Out-Null
    }
    Write-Host "開始處理 $($_.FullName)..."
    & "$SuricataExe" -r $_.FullName -l $outDir
}

Write-Host "分析完成，正在合併結果..."

$MERGED_FAST = Join-Path $OutBase "merged_fast.log"

Get-ChildItem -Path $OutBase -Filter "fast.log" -Recurse | 
    Get-Content | 
    Out-File -FilePath $MERGED_FAST -Encoding UTF8

Write-Host "合併完成，結果儲存於 $MERGED_FAST"
