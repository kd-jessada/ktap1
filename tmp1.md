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
  


============================================

$tcp = [Net.Sockets.TcpClient]::new("199.36.153.8",443)

$ssl = [Net.Security.SslStream]::new($tcp.GetStream(),$false)

$ssl.AuthenticateAsClient("storage.googleapis.com")

$file = "$env:TEMP\googleapi.cer"

"[IO.File]::WriteAllBytes($file,$ssl.RemoteCertificate.GetRawCertData())"

$ssl.Dispose()
$tcp.Dispose()

certutil.exe -dump "$env:TEMP\googleapi.cer" |
  Select-String -Pattern "http://|https://|OCSP|CRL"
  
certutil.exe -verify -urlfetch "$env:TEMP\googleapi.cer" > "$env:TEMP\verify.txt" 2>&1

Select-String -Path "$env:TEMP\verify.txt" `
  -Pattern "http://|https://|OCSP|CRL|0x80092013|offline"
  
  
=============================================================

We found the certificate revocation endpoints that Windows Workbench cannot reach.

Your `certutil -verify -urlfetch` output identifies two Google PKI services:

| Endpoint                       | Purpose                                     | Status                        |
| ------------------------------ | ------------------------------------------- | ----------------------------- |
| `http://i.pki.goog/wr2.crt`    | Download Google intermediate CA certificate | Reachability not yet verified |
| `http://c.pki.goog/wr2/...crl` | Download certificate revocation list (CRL)  | Revocation check failed       |

Windows reports:

```
CERT_TRUST_IS_OFFLINE_REVOCATION
CRYPT_E_REVOCATION_OFFLINE (0x80092013)
```

The likely problem is that these public HTTP endpoints cannot be reached directly because of your Workbench egress DENY rule.

We should allow these two hostnames through Squid, while keeping Google APIs on their direct Private Google Access path. No change to the existing GCP routes is required.

## Step 1 — Add the Google PKI hostnames to Squid

Run on `vm-squid-proxy-obk-shd-001`:

```
# Back up the existing allowlist
sudo cp -a /etc/squid/obk-swp-allowed-hosts.regex \
  /etc/squid/obk-swp-allowed-hosts.regex.bak

# Add only the required Google PKI hosts
for host in '^i[.]pki[.]goog$' '^c[.]pki[.]goog$'; do
  grep -Fqx "$host" /etc/squid/obk-swp-allowed-hosts.regex ||
    echo "$host" | sudo tee -a \
      /etc/squid/obk-swp-allowed-hosts.regex >/dev/null
done

# Validate before applying
sudo squid -k parse && sudo squid -k reconfigure
```

These are two additional approved hostnames beyond your original 25 SWP conditions. They are restricted to the Workbench clients by your existing Squid ACL.

## Step 2 — Test certificate URLs through Squid

On Windows Workbench PowerShell:

Test the Google intermediate CA download:

```
curl.exe -v -x http://10.159.144.3:3128 `
  -o NUL http://i.pki.goog/wr2.crt
```

Extract and test the actual CRL URL:

```
$crlURL = certutil.exe -dump "$env:TEMP\googleapi.cer" |
  Select-String 'http://c\.pki\.goog/\S+' |
  ForEach-Object { $_.Matches[0].Value } |
  Select-Object -First 1

$crlURL

curl.exe -v -x http://10.159.144.3:3128 `
  -o NUL "$crlURL"
```

Expected result for both: `HTTP/1.1 200 OK`.

If you receive `403 Forbidden`, check the corresponding Squid access log. If you receive `503`, investigate Squid's upstream connectivity.

## Step 3 — Recheck certificate validation

After both downloads work, run on Workbench:

```
certutil.exe -verify -urlfetch "$env:TEMP\googleapi.cer"
```

Then retest the Google API without disabling revocation validation:

```
curl.exe -4 -v --noproxy "*" `
  https://storage.googleapis.com/storage/v1/b
```

If this now returns Google's HTTP 400 response, the certificate revocation problem is resolved for this test.

## Step 4 — Only if the revocation error persists

Your earlier output showed that WinHTTP is configured for direct access. Some Windows components use WinHTTP, while certificate verification can also use WinINet settings depending on the context.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://techcommunity.microsoft.com\&sz=32)

Microsoft Community Hub

+1



If Squid successfully downloads both certificate resources but validation still fails, the next controlled test is to configure WinHTTP to use Squid, while bypassing it for private Google APIs:

Run as Administrator:

```
netsh winhttp set proxy `
  proxy-server="10.159.144.3:3128" `
  bypass-list="*.googleapis.com;private.googleapis.com;<local>"
```

Verify:

```
netsh winhttp show proxy
```

Retest normal certificate validation. This is a machine-wide change and can affect Windows services, so verify that your required applications and direct Google API connections still work. You can roll it back using:

```
netsh winhttp reset proxy
```

Microsoft documents these proxy configuration and reset operations.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://learn.microsoft.com\&sz=32)

Microsoft Learn



My recommendation: Complete Steps 1–3 first. We now know the exact Google PKI hostnames, so there is no need to open general internet egress or weaken certificate validation. If certificate verification still fails after the proxied downloads succeed, we can isolate the Windows proxy behavior next.

======================================================
