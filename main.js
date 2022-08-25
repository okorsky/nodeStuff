import * as pkijs from './pkijs.es.js';
import * as pvutils from './pkilibs/pvutils.js';
import * as peculiarCrypto from './node_modules/@peculiar/webcrypto/build/webcrypto.js';
import * as fs from 'fs';
//import * as pvtsutils from './pkilibs/pvtsutils.js';
//import * as asn1js from './pkilibs/asn1js.js';

import { KJUR, KEYUTIL } from 'jsrsasign';
import { buffer } from 'stream/consumers';



var rsaKeypair = KEYUTIL.generateKeypair("RSA", 2048);



    const webcrypto = new peculiarCrypto.Crypto();
    const name = "newEngine";
    pkijs.setEngine(name, new pkijs.CryptoEngine({ name, crypto: webcrypto }));



//console.log(rsaKeypair)

var pubPem = KEYUTIL.getPEM(rsaKeypair.pubKeyObj);
var prPem = KEYUTIL.getPEM(rsaKeypair.prvKeyObj, "PKCS8PRV");

console.log(prPem);

var csr = new KJUR.asn1.csr.CertificationRequest({
    subject: {str:"/CN=examplecn.com/C=US/O=Test"},
    sbjpubkey: pubPem,    
    extreq: [{extname:"subjectAltName",array:[{dns:"example.com"}]}],
    sigalg: "SHA256withRSA",
    sbjprvkey: prPem
  });

console.log(csr.getPEM());
  //console.log(pem);


//   var genKeypair =  function() {
//     var keypair = KEYUTIL.generateKeypair('RSA', 2048);
//     return {
//       apiKey: keypair.pubKeyObj,
//       apiSecret: keypair.prvKeyObj
//     };
//   }


  //console.log(csr.getPEM());

//const certificateBASE64 = "MIIDRDCCAi6gAwIBAgIBATALBgkqhkiG9w0BAQswODE2MAkGA1UEBhMCVVMwKQYDVQQDHiIAUABlAGMAdQBsAGkAYQByACAAVgBlAG4AdAB1AHIAZQBzMB4XDTEzMDEzMTIxMDAwMFoXDTE2MDEzMTIxMDAwMFowODE2MAkGA1UEBhMCVVMwKQYDVQQDHiIAUABlAGMAdQBsAGkAYQByACAAVgBlAG4AdAB1AHIAZQBzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4qEnCuFxZqTEM/8cYcaYxexT6+fAHan5/eGCFOe1Yxi0BjRuDooWBPX71+hmWK/MKrKpWTpA3ZDeWrQR2WIcaf/ypd6DAEEWWzlQgBYpEUj/o7cykNwIvZReU9JXCbZu0EmeZXzBm1mIcWYRdk17UdneIRUkU379wVJcKXKlgZsx8395UNeOMk11G5QaHzAafQ1ljEKB/x2xDgwFxNaKpSIq3LQFq0PxoYt/PBJDMfUSiWT5cFh1FdKITXQzxnIthFn+NVKicAWBRaSZCRQxcShX6KHpQ1Lmk0/7QoCcDOAmVSfUAaBl2w8bYpnobFSStyY0RJHBqNtnTV3JonGAHwIDAQABo10wWzAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIA/zAdBgNVHQ4EFgQU5QmA6U960XL4SII2SEhCcxij0JYwHwYDVR0jBBgwFoAU5QmA6U960XL4SII2SEhCcxij0JYwCwYJKoZIhvcNAQELA4IBAQAikQls3LhY8rYQCZ+8jXrdaRTY3L5J3S2xzoAofkEnQNzNMClaWrZbY/KQ+gG25MIFwPOWZn/uYUKB2j0yHTRMPEAp/v5wawSqM2BkdnkGP4r5Etx9pe3mog2xNUBqSeopNNto7QgV0o1yYHtuMKQhNAzcFB1CGz25+lXv8VuuU1PoYNrTjiprkjLDgPurNXUjUh9AZl06+Cakoe75LEkuaZKuBQIMNLJFcM2ZSK/QAAaI0E1DovcsCctW8x/6Qk5fYwNu0jcIdng9dzKYXytzV53+OGxdK5mldyBBkyvTrbO8bWwYT3c+weB1huNpgnpRHJKMz5xVj0bbdnHir6uc";
//const privateKeyBASE64 = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDioScK4XFmpMQz/xxhxpjF7FPr58Adqfn94YIU57VjGLQGNG4OihYE9fvX6GZYr8wqsqlZOkDdkN5atBHZYhxp//Kl3oMAQRZbOVCAFikRSP+jtzKQ3Ai9lF5T0lcJtm7QSZ5lfMGbWYhxZhF2TXtR2d4hFSRTfv3BUlwpcqWBmzHzf3lQ144yTXUblBofMBp9DWWMQoH/HbEODAXE1oqlIirctAWrQ/Ghi388EkMx9RKJZPlwWHUV0ohNdDPGci2EWf41UqJwBYFFpJkJFDFxKFfooelDUuaTT/tCgJwM4CZVJ9QBoGXbDxtimehsVJK3JjREkcGo22dNXcmicYAfAgMBAAECggEBANMO1fdyIVRAWmE6UspUU+7vuvBWMjruE9126NhjOjABz5Z/uYdc3kjcdSCMVNR/VBrnrINmlwZBZnL+hCj5EBE/xlDnOwU/mHx4khnXiYOJglqLwFHcOV+lD3vsxhZLikP8a8GEQCJXbZR+RADzA8gkqJQSxnPkLpqeAyqulKhviQ2lq2ZxeCXI+iZvURQPTSm86+szClwgzr2uW6NSlNKKeeLHMILed4mrwbPOdyhutnqvV79GUYH3yYdzbEbbw5GOat77+xPLt33cfLCL7pg5lGDrKEomu6V1d5KmBOhv0K8gGPKfxPrpeUG5n1q58k/2ouCiyAaKWpVoOWmnbzECgYEA/UzAGZ2N8YE+kC85Nl0wQof+WVm+RUDsv6C3L2vPUht3GwnbxSTMl4+NixbCWG46udVhsM2x7ZzYY1eB7LtnBnjvXZTYU4wqZtGR/+X2Rw5ou+oWm16/OgcEuFjP2zpQtr9r/bpKhyBV+IdSngnLy00RueKGUL6nvtecRklEhQ0CgYEA5Quek+c12qMtrmg5znHPQC7uuieZRzUL9jTlQtuZM5m4B3AfB/N/0qIQS06PHS1ijeHQ9SxEmG72weamUYC0SPi8GxJioFzaJEDVit0Ra38gf0CXQvcYT0XD1CwY/m+jDXDWL5L1CCIr60AzNjM3WEfGO4VHaNsovVLn1Fvy5tsCgYEA4ZOEUEubqUOsb8NedCexXs61mOTvKcWUEWQTP0wHqduDyrSQ35TSDvds2j0+fnpMGksJYOcOWcmge3fm4OhT69Ovd+uia2UcLczc9MPa+5S9ePwTffJ24jp13aZaFaZtUxJOHfvVe1k0tsvsq4mV0EumSaCOdUIVKUPijEWbm9ECgYBpFa+nxAidSwiGYCNFaEnh9KZqmghk9x2J1DLrPb1IQ1p/bx2NlFYs2VYIdv6KMGxrFBO+qJTAKwjjZWMhOZ99a0FCWmkNkgwzXdubXlnDrAvI1mWPv7ZTiHqUObct5SI15HMgWJg7JxJnWIkmcNEPm76DSF6+6O4EDql2cMk8yQKBgF5roj+l90lfwImr6V1NJo3J5VCi9wTT5x9enPY9WRcfSyRjqU7JWy6h0C+Jq+AYAxrkQVjQuv1AOhO8Uhc6amM5FA+gfg5HKKPnwuOe7r7B48LFF8eRjYRtHmrQUrFY0jH6O+t12dEQI+7qE+SffUScsZWCREX7QYEK/tuznv/U";

const myprkey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCEAp4eIWd92CYd0NEvqaLvdr6EE5pdep5Vx5TK506iZF1EnPGj0foLsy+1XaZfnBbD10LUkEC2ApWxaJ1lntz0WcawMLEEhVZtyUCKlA0nK3CUn0Ymw+TCVLR64wPG+sLt4KOuBUseMDXtIWo9OXosoGGleDoKTy0ho7mzPDQnBOBpWj7Ejitz1lB2Hfs0RxrptQerFp5XhTH9vBnnBqr+n1M1KFuU/Y15UDNLzSW3IYBxoMToIvRi9McQgnCx21+AYxu3zG2USQ4CJpf1Q/Bal7SmGYojz1KVrlXtHUh0x77eGawj816xQSoPLTnQlONYcMiwliUzdX6L/r4RvZkJAgMBAAECggEALircMZ1tHE3jxrmo7wpcuXLF3lscuWSQy18pYmzSy2heVgitWaWt1Tmtjbha30UvkP5PmRd6Ci2NPKZhpZCRpcNgAW6F+hbHy01/DPgKQZCnptKtLhGEh5IoLHIIeCZq1daiZ9HiG4Sw12XASfk4CTNt8vjBE6ntFr6zy0Na2eoMrFwteTFKpPiBiz6MVlXF8DfiMPz9MROn/7Vzh7yoOnZ5mPbLDeISJShSr1FtaaAVO5cHc431Nvt7GnLm+t3+xHy0TrJWMGtcMAjMGQBJjv33m2Z01xmp0TAlBc0md78zFKwhOzSQ6MZYmzF8/0iPHIXd/zr9kncpt8lBfy54AQKBgQD1oFu4KxZGkKE11F6c0rLl1drfAdlmHSiD9UBgzJEp1WoVOjTD4o1p+8NkdBf87yJVURd/Bg9B/S8t/zBL8m9DkOg60WSyxdsbNS0nEJ2ucsYlNHYwwhtBA2j4Z4FaJDI+QNA6Qe6zjBUzG8Zn/zatL3SW+RwO+lwtIF67g0owYQKBgQCJld/EdkbLtYMgfMD7UnRZd5iLvshdVOQKHqvwLU+Hg9Pj0/0bzL2E5Sxlf3gT1pbnn6PG+J+HGEs/pavW2xEJ8pGQzPRRmwiRuVmhH9ekSurz3OKFGmpXU0EYpxe6b0IxUFyXD8rPc+azHRtQJ/rHNvVJKPIgFJbnR34hYPhJqQKBgBLF89yqpmQ0T63+klCoJfY9FyJuUMBmQB990jLTz9CDuDzxGvFR0n8kN/XojaDOYjBlJ0eVHftsL3vzgix71hcy7xz3vhuP1cRJly7iLTsVGKHlVZc6brzUVuSNfKx4EcMCTyf0vBrK/R/P4qU2M2afNukHFybp6bulOrhYO4ZhAoGAd2tzEl9nC6G88xHVn07uVkmMSp+J4hiw5mfA7XMmuIUgAXwbEWoghZ01b9O4Md/sk5bo3Ocn8GaRyejOwmra2zuERZ7f4YUjZvjuZv/weFXeoVRz+Pv4mVtWAUPnQJcZaRxLgYLfkjkTYRw+fNB2xztYo+u6XUYBxTU0sVwtpiECgYEAzGgo/8SE75V9Ckx/oT/fugtaVQek2rmjeYNALKA8hKMzE9cLu/cUwS/zzAN+h/FsipApH5na3wxFs0O3fI6HHKbtAwHK7urYq8mE+SjYBztkjDEVxQ0v0kiHZ5Xw0QGeUFRsSC1VF3zplFwPI2pmcl+r1oylOnCfIdnnxGQeE0Y=";
const mycert = "MIIEhjCCA26gAwIBAgITdgAAAEYDu2a61fU9QwAAAAAARjANBgkqhkiG9w0BAQsFADBDMRMwEQYKCZImiZPyLGQBGRYDcGtpMRcwFQYKCZImiZPyLGQBGRYHbGFiMjAxNjETMBEGA1UEAxMKUEtJLUxhYiBDQTAeFw0yMjA4MTAyMjQ2MTJaFw0yNDA1MTUyMTE5MTZaMDQxCzAJBgNVBAYTAlVTMQ0wCwYDVQQKEwRUZXN0MRYwFAYDVQQDEw1leGFtcGxlY24uY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhAKeHiFnfdgmHdDRL6mi73a+hBOaXXqeVceUyudOomRdRJzxo9H6C7MvtV2mX5wWw9dC1JBAtgKVsWidZZ7c9FnGsDCxBIVWbclAipQNJytwlJ9GJsPkwlS0euMDxvrC7eCjrgVLHjA17SFqPTl6LKBhpXg6Ck8tIaO5szw0JwTgaVo+xI4rc9ZQdh37NEca6bUHqxaeV4Ux/bwZ5waq/p9TNShblP2NeVAzS80ltyGAcaDE6CL0YvTHEIJwsdtfgGMbt8xtlEkOAiaX9UPwWpe0phmKI89Sla5V7R1IdMe+3hmsI/NesUEqDy050JTjWHDIsJYlM3V+i/6+Eb2ZCQIDAQABo4IBgDCCAXwwFgYDVR0RBA8wDYILZXhhbXBsZS5jb20wHQYDVR0OBBYEFA9o9TYO5tMOjOn8pTRhG4qvnF+4MB8GA1UdIwQYMBaAFIwWZlymwBKNKrH9uIef1fdcy6iTMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwubGFiMjAxNi5wa2kvcGtpLWxhYi1jYS5jcmwwawYIKwYBBQUHAQEEXzBdMDEGCCsGAQUFBzAChiVodHRwOi8vYWlhLmxhYjIwMTYucGtpL3BraS1sYWItY2EuY3J0MCgGCCsGAQUFBzABhhxodHRwOi8vb2NzcC5sYWIyMDE2LnBraS9vY3NwMA4GA1UdDwEB/wQEAwIFoDA7BgkrBgEEAYI3FQcELjAsBiQrBgEEAYI3FQiDzs45gq2CR4bFmyWH4d4F9pxpLevAJIW50XMCAWQCAQkwEwYDVR0lBAwwCgYIKwYBBQUHAwEwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDATANBgkqhkiG9w0BAQsFAAOCAQEAH9BbP0xv0U+P2R+lKQY+V9hIC46Ef7kzcBhnOAn0jMzhBzZX4aUd/EBSU+5nT1R0gyXaGQGpQNt5k/eWD5ihSaIxEGL7bF37NleR2ZhgrYQHRFxsyrdJFUxonIMyipMspfS9tFFiXxytRb7LXLdCvkS9wx0MudbSxF9tW9ttsxJ0bQI7QGR8nJ1BzRVXUlqL9T+wQfMxo/qqZ3gkfZI7/g54qgTTZd5bbZ6mnEBcPcU2dMLNI15Tic5v5emxjS1jR+cAalidjwIAUyI18UbQmQ9hfJOW0SqpvpEy6+h5ovntIV/N5Sj4lNLWZKh2MCHAl2L8BDrKSEjXFZvd974xfg==";
const ica = "MIIEUjCCAzqgAwIBAgITWAAAABAO7nKfcNrzUQAAAAAAEDANBgkqhkiG9w0BAQsFADBFMRMwEQYKCZImiZPyLGQBGRYDcGtpMRcwFQYKCZImiZPyLGQBGRYHbGFiMjAxNjEVMBMGA1UEAxMMUEtJLUxhYi1Sb290MB4XDTIyMDUxNTIxMDkxNloXDTI0MDUxNTIxMTkxNlowQzETMBEGCgmSJomT8ixkARkWA3BraTEXMBUGCgmSJomT8ixkARkWB2xhYjIwMTYxEzARBgNVBAMTClBLSS1MYWIgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCy7J0p41PNSzNXXM72spJy6fksfNxYoj8qqfdIl3Amw2/kKBXfIcz+aPI6TxhPQuFqxYuEImVuynXOju8LT5UZdoiaf6VysjxHJMQql1WURwBDbUl+My0YEpWksRa3upA+MroKJiDgUfqkFs5nD2LNJkFLQkkGNODYjaPP5Ompo9SCu8oJFo2kvA3zB5U3iqz50Jct2yjo3E2jchOcQPV+Dhpqy6KpF0BLVnk2J6BITQIEFiVq0+j7sz4i6kigq1IcivE6WTj0PTtNrL1FCuST3vFY6evKjPAeesJKUVJt9hgzOzlmw2D69H698BwaBR0LR5qPmiZgolCwEO9gmpjLAgMBAAGjggE7MIIBNzAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQUjBZmXKbAEo0qsf24h5/V91zLqJMwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUwW4VsGooXpMzmj0IkgzcF7hjCY0wOAYDVR0fBDEwLzAtoCugKYYnaHR0cDovL2NybC5sYWIyMDE2LnBraS9wa2ktbGFiLXJvb3QuY3JsMG0GCCsGAQUFBwEBBGEwXzAzBggrBgEFBQcwAoYnaHR0cDovL2FpYS5sYWIyMDE2LnBraS9wa2ktbGFiLXJvb3QuY3J0MCgGCCsGAQUFBzABhhxodHRwOi8vb2NzcC5sYWIyMDE2LnBraS9vY3NwMA0GCSqGSIb3DQEBCwUAA4IBAQCkhbfpxOAaxk0ToTe3BkUFVaOa1PJSE2gK1nbMBLDTfzMq3QumCUwJRXs9x8YTifgEAra7etrM45jMC4egqiRB5OAid00CBePzhc8Zf7fh+Dat82YL9lSIY2J+j+IosoflZZ5pL3HmNxwz3rCse8wi0r1+1TQ+Jme6HhlgCtNJTpUDWHpkXQmgubr3eu4VIw8iJoWtb5GtWUrEnSSfGDQGQ3VKuZ/d11HrjDUa8hXoZ8JJ8T1nncIKL5oAXDzz2ok7fQG+OHIOcLPF2HS2e+HeFWly7Oln5ON9C1p1AtH/B4yE4M47pgDxdWo2ZEbvo3P+phrCjQVa4RJ2FfR9wVFM";
const root = "MIIDZTCCAk2gAwIBAgIQM6RVcIAOpZ5E1nRf4Rek8TANBgkqhkiG9w0BAQsFADBFMRMwEQYKCZImiZPyLGQBGRYDcGtpMRcwFQYKCZImiZPyLGQBGRYHbGFiMjAxNjEVMBMGA1UEAxMMUEtJLUxhYi1Sb290MB4XDTIyMDMxMDEyMDIyMVoXDTMyMDMxMDEyMTIyMVowRTETMBEGCgmSJomT8ixkARkWA3BraTEXMBUGCgmSJomT8ixkARkWB2xhYjIwMTYxFTATBgNVBAMTDFBLSS1MYWItUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAO7+CAx7lbXcYshcyOqYrxIGTtqvqS3n8/DSw3yKzMttq9ADGHJEl5PFk99mMUr+h1QJ5hj1flIScoH+gQpnRY74z/zaGDRECzhLV1toFMFQ0jAqsMkdDmzY6Vux0EWjcRLe+MAyPXLNl3JTOQxiMQj+5Jlnt2BMCexKDgQ33RYdfbS/Sc7fXIBAFg9EH2o4sGS9bQH+7UXKBqK9685LQoLhjr6V7vvgGuhll8TT+TXn7vaQUyL/Hty9YKCj/LRYO7rzlP14iJYavmNzNMpHKyH1YrWxZG/WuJVMYPI3nzgvzVzqS+ayKIyQjevekXflvwUn/ARHgYvlYW2DXVJXNu0CAwEAAaNRME8wCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFMFuFbBqKF6TM5o9CJIM3Be4YwmNMBAGCSsGAQQBgjcVAQQDAgEAMA0GCSqGSIb3DQEBCwUAA4IBAQARRRaRqzioXurGr39zw7MNwMOIP/5dVAAApl4jFYJ4Ro4vZh+VdeCyuXrWe3Q1Yv05FiK5HCSoWYqEyATyekRVKXCJprCbb8GQwdrl+j+FYx69l3KYMkZP2BfwtZMFsmeP7hzC1aPARXfT2SVM2rpDGjGuD68h8IkCiCWB/REgvBNGgECkkVnKh1FgcsJQ7FW4UbSd0TAx9f8O6VpYuu+3hXQP0g8SaEalnwCW9TT+JJiPjkmIKh9JRhjhE5CMAtBIFQPKicvTtF1JVjbktO142tnXAomvnDqoHlJ69cN1V2+rwYAwIVVT/pCM8VTYkZVd+wenuolta+hzrwrH/p9D";
//const mycert = "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";
var prTrim = prPem.replace("-----BEGIN PRIVATE KEY-----","").replace("-----END PRIVATE KEY-----","").replace(/(\r\n|\r|\n)/g,"");
const prk64 = "MIIEpAIBAAKCAQEAnOnsGQoS+MqK5C5wkWVrfCsZ5L4fBU0Qn9IRzpVgRaUenZjjZcHsiTh/nsO2fGTHf4qqIEgr4apEw+WH7EXSH7F+VNqpInLdHVGmsw+JTn/83xgAP/+7UaEsM1Rb9RjVFU4beeLuTIhs/gcAzNhnSMmR3H1JZCusNH7jsF2GBBDOjL7OMKV8O9QdPq1DMOlSwc5QWTsfKyxglKkNa1q4Lgh8iyA/2UxHo7N87aRc6DCtvLNQH+breYUcLgq3mj4rA0Q1qrWHB+NYkpR0yhbcPB1OGKc6vwUdUlyZFdxb6FgYp29kF4EnLy6fuo99CIArU8BgIEwdUeguGBrPobUCKQIDAQABAoIBAGN95teRjan2Ms6vq2xlVBus8IQbEGw6CvprJiNIj3xZT+o5UKXqqeHv0uuFyKVi+SOjdm91k21ImsVjOiXTt4Gk9ycyZd+T2SOH7BzJExSVDm8eNrpdmhYODYqWSKBFmIYjukQ0YUhhkEoZgqZf6E08kaGuRuSe1FeMxS3Efv7/7OBdt5HPY2diapHb2Y4joUXM+kZogXThTte6XxnUDE9zC2xklyCQRsSsmpQh8MhcDTrqBxf/Jw7z9yczWijfP315i73Idrmr0yL5i5aDErcBlTVTaanv0WTjxrUSXzhPNbncqL5dNhyLCumlgS8iZXTBu+jaTcU3ZPlP9qZ0tekCgYEA+TCMZuZc32x/C35cS8E48BMtbM82ov5mZPFRaSdk4vTdGR406g7k7LwtvN7C3YqpE06KHBxxs/oWMXhUl07JPF6Q8npMeMFqEY/VA8vI7uRqscODSI2aIqNtXvhcX7EiakW2vuLXKcH7PYs2PSDI9A8DWjARn2UTPc+s6spMZ88CgYEAoTPEWZEv2f4nh7Bud6bn5Ym8pfYCUT0n8GtVoNB0A8Bv1xn42sR7GRP7TNlqW2jvISVI8V4K7TZAK0p8+9v2/mkCaDgC6K6fWGQkxLdkIoiAJ0+6P2osTgheIjgO3IViw8Cqvj+nqIWaJYwpnDy18XLmJcw2Qwg9UtlfGKM+fIcCgYBVDo8+KG+XC8+puq4CZafruoAM3gYGSNPmrMBfJkU3euFlS3xAUGkvrWPnThoxyLzBjFN0GPlut3SP2kT1iL0D0DulqL0lks+DwxawvwSNFoacuuG7CCqOnD4e5qORPkNDBxzDt2Y+KKp7bWNMJj6xn9ZDGJlLURLqTFL3qam+3QKBgQCM0Y36uCvXAIBDtkop1/HHwHS9fZQ0p3nWOc1JeA+An4CTpSqQ4Qavt5bVYS/Zvmb2y31W7FIbOkMADkf0NAkl4VGq/RL9dF3ad1DvT0z4JcndjXYjo3okiIbC2bmRxiuq2QnOvAiX3G310uUeiKJf04FdD3FvSSlY0G6UNTaGzQKBgQDZtMBgEbpJzvs8MP/0MamcbQXfIDzq1whnKkNZNuSd9z2A7y4qpmkyq49NLOcd5HSC9eHLwA0Ohyz/AsKRzTS72keJx+/Lqa06gwwdK0MAqrEYr1/Py98gt8R+3CgEHTEpkRHBhUJAD5eAwy/JpY9V/SRRDvMkJeSZeNIVxE5igA==";
const pkcs8Raw = pvutils.stringToArrayBuffer(pvutils.fromBase64(myprkey));
const pkcs8Simpl = pkijs.PrivateKeyInfo.fromBER(pkcs8Raw);
//console.log(prTrim);

async function passwordBasedIntegrity$1(password, hash = "SHA-256") {
    //#region Create simplified structires for certificate and private key
    const certRaw = pvutils.stringToArrayBuffer(pvutils.fromBase64(mycert));
    const certSimpl = pkijs.Certificate.fromBER(certRaw);    
    const icaRaw = pvutils.stringToArrayBuffer(pvutils.fromBase64(ica));
    const icaSimpl = pkijs.Certificate.fromBER(icaRaw);
    const rootRaw = pvutils.stringToArrayBuffer(pvutils.fromBase64(root));
    const rootSimpl = pkijs.Certificate.fromBER(rootRaw);    
    const pkcs8Raw = pvutils.stringToArrayBuffer(pvutils.fromBase64(myprkey));
    const pkcs8Simpl = pkijs.PrivateKeyInfo.fromBER(pkcs8Raw);
    //#endregion
    //#region Put initial values for PKCS#12 structures
    const pkcs12 = new pkijs.PFX({
        parsedValue: {
            integrityMode: 0,
            authenticatedSafe: new pkijs.AuthenticatedSafe({
                parsedValue: {
                    safeContents: [
                        {
                            privacyMode: 0,
                            value: new pkijs.SafeContents({
                                safeBags: [
                                    new pkijs.SafeBag({
                                        bagId: "1.2.840.113549.1.12.10.1.1",
                                        bagValue: pkcs8Simpl
                                    }),
                                    new pkijs.SafeBag({
                                        bagId: "1.2.840.113549.1.12.10.1.3",
                                        bagValue: new pkijs.CertBag({
                                            parsedValue: certSimpl
                                        })
                                    }),
                                    new pkijs.SafeBag({
                                        bagId: "1.2.840.113549.1.12.10.1.3",
                                        bagValue: new pkijs.CertBag({
                                            parsedValue: icaSimpl
                                        })
                                    }),
                                    new pkijs.SafeBag({
                                        bagId: "1.2.840.113549.1.12.10.1.3",
                                        bagValue: new pkijs.CertBag({
                                            parsedValue: rootSimpl
                                        })
                                    })
                                ]
                            })
                        }
                    ]
                }
            })
        }
    });
    //#endregion
    //#region Encode internal values for all "SafeContents" firts (create all "Privacy Protection" envelopes)
    if (!(pkcs12.parsedValue && pkcs12.parsedValue.authenticatedSafe)) {
        throw new Error("pkcs12.parsedValue.authenticatedSafe is empty");
    }
    await pkcs12.parsedValue.authenticatedSafe.makeInternalValues({
        safeContents: [
            {
            // Empty parameters since we have "No Privacy" protection level for SafeContents
            }
        ]
    });
    //#endregion
    //#region Encode internal values for "Integrity Protection" envelope
    await pkcs12.makeInternalValues({
        password: pvutils.stringToArrayBuffer(password),
        iterations: 100000,
        pbkdf2HashAlgorithm: hash,
        hmacHashAlgorithm: hash
    });
    //#endregion
    //#region Encode output buffer
    return pkcs12.toSchema().toBER();
    //#endregion
}

const pfx = await passwordBasedIntegrity$1("pass");
console.log(pfx);

var buf = Buffer.from(pfx, 'binary');

fs.writeFile('myFullpfx.pfx', buf, function(err) {
    if (err) throw err;
});