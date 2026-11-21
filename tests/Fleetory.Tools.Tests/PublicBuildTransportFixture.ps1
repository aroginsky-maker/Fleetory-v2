param([string]$Mode)
$ErrorActionPreference='Stop'
$body=[Text.Encoding]::ASCII.GetBytes('generated-public-source-only')
$digest=[Security.Cryptography.SHA256]::HashData($body)
$header=[byte[]]::new(60)
[Text.Encoding]::ASCII.GetBytes('FLTPUB01').CopyTo($header,0)
$length=if($Mode -ceq 'oversize'){67108865}else{$body.Length}
for($i=0;$i -lt 4;$i++){ $header[8+$i]=[byte](($length -shr (24-8*$i)) -band 255) }
$digest.CopyTo($header,12)
for($i=44;$i -lt 60;$i++){ $header[$i]=49 }
if($Mode -ceq 'magic'){ [Text.Encoding]::ASCII.GetBytes('INVALID!').CopyTo($header,0) }
if($Mode -ceq 'digest'){ for($i=0;$i -lt $body.Length;$i++){ $body[$i]=120 } }
if($Mode -ceq 'stall'){ Start-Sleep -Seconds 10 }
$output=[Console]::OpenStandardOutput(); $inputStream=[Console]::OpenStandardInput()
$output.Write($header,0,60)
$count=if($Mode -ceq 'truncated'){2}else{$body.Length}
$output.Write($body,0,$count);$output.Flush()
if($Mode -ceq 'truncated'){exit 0}
if($inputStream.ReadByte() -eq 83){$output.WriteByte($(if($Mode -ceq 'permit'){0}else{1}));$output.Flush()}
while($inputStream.ReadByte() -ge 0){}
