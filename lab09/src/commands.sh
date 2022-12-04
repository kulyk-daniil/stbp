# створення самопідписаного сертифіката
New-SelfSignedCertificate -DnsName email@yourdomain.com -Type CodeSigning -CertStoreLocation cert:\CurrentUser\My

# експорт сертифіката без private ключа
Export-Certificate -Cert (Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert)[0] -FilePath code_signing.crt

# імпортуємо сертифікат як довіреного видавця
# для експорту [0] змусить це працювати для випадків, коли у вас є більше одного сертифіката
Import-Certificate -FilePath .\code_signing.crt -Cert Cert:\CurrentUser\TrustedPublisher

# імпортуємо сертифікат як кореневий центр сертифікації
Import-Certificate -FilePath .\code_signing.crt -Cert Cert:\CurrentUser\Root

# використовуємо команду Set-Authenticodesignature, щоб підписати файл
Set-AuthenticodeSignature .\FileName.exe -Certificate (Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert)