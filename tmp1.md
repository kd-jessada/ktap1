wevtutil ep | findstr /i CAPI2

Get-WinEvent -ListLog "*CAPI2*" -ErrorAction SilentlyContinue

$tcp = [Net.Sockets.TcpClient]::new("199.36.153.8",443)
$ssl = [Net.Security.SslStream]::new($tcp.GetStream(),$false)

try {
    $ssl.AuthenticateAsClient("storage.googleapis.com")

    $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $ssl.RemoteCertificate
    )

    $file = "$env:TEMP\storage-googleapis.cer"

    [IO.File]::WriteAllBytes(
        $file,
        $cert.Export(
            [Security.Cryptography.X509Certificates.X509ContentType]::Cert
        )
    )

    $cert | Format-List Subject,Issuer,NotAfter,Thumbprint

    $cert.Extensions |
        Where-Object {
            $_.Oid.Value -in @(
                "1.3.6.1.5.5.7.1.1",
                "2.5.29.31"
            )
        } |
        ForEach-Object {
            $_.Oid.FriendlyName
            $_.Format($true)
        }
}
finally {
    $ssl.Dispose()
    $tcp.Dispose()
}

certutil.exe -verify -urlfetch "$env:TEMP\storage-googleapis.cer" `
  > "$env:TEMP\gcp-cert-verify.txt" 2>&1

Select-String -Path "$env:TEMP\gcp-cert-verify.txt" `
  -Pattern "http://|https://|offline|0x80092013|OCSP|CRL|ERROR" |
  Select-Object -First 60