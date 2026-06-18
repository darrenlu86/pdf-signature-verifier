/**
 * Taiwan Time Stamp Authority (TSA) Root Certificates
 *
 * TSAs sign timestamp tokens (RFC 3161) that prove "this signature existed
 * at this time." The TSA trust domain is conceptually independent from the
 * signing-CA trust domain — but for several Taiwan PKIs, the SAME physical
 * root CA acts as the trust anchor for both:
 *
 *   - TWCA Global Root CA → TWCA Timestamping Certification Authority →
 *     TSA leaf (e.g. "70759028-01-TSA"). Same root as TWCA's
 *     document-signing chain.
 *   - TWCA CYBER Root CA → newer TSA chain (when TWCA migrates).
 *   - GRCA G2 → Government TSA chain.
 *
 * Listing those roots here makes the verification accept legitimate
 * timestamps without weakening the audit's "separate trust domain"
 * principle — the maintainer makes an explicit decision about each anchor.
 *
 * To verify any entry yourself: decode the PEM to DER and SHA-256 the
 * result. The trust manager rejects an entry whose computed fingerprint
 * doesn't match `expectedFingerprint`.
 */

import type { TrustAnchorEntry } from './taiwan-roots'

export const TAIWAN_TSA_ROOT_CERTIFICATES: TrustAnchorEntry[] = [
  {
    name: 'TWCA Global Root CA (TSA anchor)',
    pem: `-----BEGIN CERTIFICATE-----
MIIFQTCCAymgAwIBAgICDL4wDQYJKoZIhvcNAQELBQAwUTELMAkGA1UEBhMCVFcx
EjAQBgNVBAoTCVRBSVdBTi1DQTEQMA4GA1UECxMHUm9vdCBDQTEcMBoGA1UEAxMT
VFdDQSBHbG9iYWwgUm9vdCBDQTAeFw0xMjA2MjcwNjI4MzNaFw0zMDEyMzExNTU5
NTlaMFExCzAJBgNVBAYTAlRXMRIwEAYDVQQKEwlUQUlXQU4tQ0ExEDAOBgNVBAsT
B1Jvb3QgQ0ExHDAaBgNVBAMTE1RXQ0EgR2xvYmFsIFJvb3QgQ0EwggIiMA0GCSqG
SIb3DQEBAQUAA4ICDwAwggIKAoICAQCwBdvI64zEbooh745NnHEKH1Jw7W2CnJfF
10xORUnLQEK1EjRsGcJ0pDFfhQKX7EMzClPSnIyOt7h52yvVavKOZsTuKwEHktSz
0ALfUPZVr2YOy+BHYC8rMjk1Ujoog/h7FsYYuGLWRyWRzvAZEk2tY/XTP3VfKfCh
MBwqoJimFb3u/Rk28OKRQ4/6ytYQJ0lM793B8YVwm8rqqFpD/G2Gb3PpN0Wp8DbH
zIh1HrtsBv+baz4X7GGqcXzGHaL3SekVtTzWoWH1EfcFbx39Eb7QMAfCKbAJTibc
46KokWofwpFFiFzlmLhxpRUZyXx1EcxwdE8tmx2RRP1WKKD+u4ZqyPpcC1jcxkt2
yKsi2XMPpfRaAok/T54igu6idFMqPVMnaR1sjjIsZAAmY2E2TqNGtz99sy2sbZCi
laLOz9qC5wc0GZbpuCGqKX6mOL6OKUohZnkfs8O1CWfe1tQHRvMq2uYiN2DLgbYP
oA/pyJV/v1WRBXrPPRXAb94JlAGD1zQbzECl8LibZ9WYkTunhHiVJqRaCPgrdLQA
BDzfuBSO6N+pjWxnkjMdwLfS7JLIvgm/LCkFbwJrnu+8vyq8W8BQj0FwcYeyTbcE
qYSjMq+u7msXi7Kx/mzhkIyIqJdIzshNy/MGz19qCkKxHh53L46g5pIOBvwFItIm
4TFRfTLcDwIDAQABoyMwITAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB
/zANBgkqhkiG9w0BAQsFAAOCAgEAXzSBdu+WHdXltdkCY4QWwa6gcFGn90xHNcgL
1yg9iXHZqjNB6hQbbCEAwGxCGX6faVsgQt+i0trEfJdLjbDorMjupWkEmQqSpqsn
LhpNgb+E1HAerUf+/UqdM+DyucRFCCEK2mlpc3INvjT+lIutwx4116KD7+U4x6WF
H6vPNOw/KP4M8VeGTslV9xzU2KV9Bnpv1d8Q34FOIWWxtuEXeZVFBs5fzNxGiWNo
RI2T9GRwoD2dKAXDOXC4Ynsg/eTb6QihuJ49CcdP+yz4k3ZB3lLg4VfSnQO8d57+
nile98FRYB/e2guyLXW3Q0iT5/Z5xoRdgFlglPx4mI88k1HtQJAH32RjJMtOcQWh
15QaiDLxInQirqWm2BJpTGCjAu4r7NRjkgtevi92a6O2JryPA9gK8kxkRr05YuWW
6zRjESjMlfGt7+/cgFhI6Uu46mWs6fyAtbXIRfmswZ/ZuepiiI7E8UuDEq3mi4TW
nsLrgxifarsbJGAzcMzs9zLzXNl5fe+epP7JI8Mk7hWSsT2RTyaGvWZzJBPqpK5j
wa19hAM8EHiGG3njxPPyBJUgriOCxLM6AGK/5jYk4Ve6xx6QddVfP5VhK8E7zeWz
aGHQRiapIVJpLesux+t3zqY6tQMzT3bR51xUAV3LePTJDL/PEo4XLSNolOer/qmy
KwbQBM0=
-----END CERTIFICATE-----`,
    expectedFingerprint: '59:76:90:07:f7:68:5d:0f:cd:50:87:2f:9f:95:d5:75:5a:5b:2b:45:7d:81:f3:69:2b:61:0a:98:67:2f:0e:1b',
    source: 'Same cert as taiwan-roots.ts. Verified to be the TSA anchor by inspecting real TWCA TSP tokens (chain terminates at this root for "TWCA Timestamping Certification Authority" → leaf TSA).',
    notes: 'TWCA reuses Global Root CA as the trust anchor for both document-signing and timestamping sub-CAs.',
  },
  {
    name: 'TWCA CYBER Root CA (TSA anchor)',
    pem: `-----BEGIN CERTIFICATE-----
MIIFjTCCA3WgAwIBAgIQQAE0jMIAAAAAAAAAATzyxjANBgkqhkiG9w0BAQwFADBQ
MQswCQYDVQQGEwJUVzESMBAGA1UEChMJVEFJV0FOLUNBMRAwDgYDVQQLEwdSb290
IENBMRswGQYDVQQDExJUV0NBIENZQkVSIFJvb3QgQ0EwHhcNMjIxMTIyMDY1NDI5
WhcNNDcxMTIyMTU1OTU5WjBQMQswCQYDVQQGEwJUVzESMBAGA1UEChMJVEFJV0FO
LUNBMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJUV0NBIENZQkVSIFJvb3Qg
Q0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDG+Moe2Qkgfh1sTs6P
40czRJzHyWmqOlt47nDSkvgEs1JSHWdyKKHfi12VCv7qze33Kc7wb3+szT3vsxxF
avcokPFhV8UMxKNQXd7UtcsZyoC5dc4pztKFIuwCY8xEMCDa6pFbVuYdHNWdZsc/
34bKS1PE2Y2yHer43CdTo0fhYcx9tbD47nORxc5zb87uEB8aBs/pJ2DFTxnk684i
JkXXYJndzk834H/nY62wuFm40AZoNWDTNq5xQwTxaWV4fPMf88oon1oglWa0zbfu
j3ikRRjpJi+NmykosaS3Om251Bw4ckVYsV7r8Cibt4LK/c/WMw+f+5eesRycnupf
Xtuq3VTpMCEobY5583WSjCb+3MX2w7DfRFlDo7YDKPYIMKoNM+HvnKkHIuNZW0CP
2oi3aQiotyMuRAlZN1vH4xfyIutuOVLF3lSnmMlLIJXcRolftBL5hSmO68gnFSDA
S9TMfAxsNAwmmyYxpjyn9tnQS6Jk/zuZQXLB4HCX8SS7K8R0IrGsayIyJNN4KsDA
oS/xUgXJP+92ZuJF2A09rZXIx4kmyA+upwMu+8Ff+iDhcK2wZSA3M2Cw1a/XDBzC
kHDXShi8fgGwsOsVHkQGzaRP6AzRwyAQ4VRlnrZR0Bp2a0JaWHY06rc3Ga4udfmW
5cFZ95RXKSWNOkyrTZpB0F8mAwIDAQABo2MwYTAOBgNVHQ8BAf8EBAMCAQYwDwYD
VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBSdhWEUfMFib5do5E83QOGt4A1WNzAd
BgNVHQ4EFgQUnYVhFHzBYm+XaORPN0DhreANVjcwDQYJKoZIhvcNAQEMBQADggIB
AGSPesRiDrWIzLjHhg6hShbNcAu3p4ULs3a2D6f/CIsLJc+o1IN1KriWiLb73y0t
tGlTITVX1olNc79pj3CjYcya2x6a4CD4bLubIp1dhDGaLIrdaqHXKGnK/nZVekZn
68xDiBaiA9a5F/gZbG0jAn/xX9AKKSM70aoK7akXJlQKTcKlTfjF/biBzysseKNn
TKkHmvPfXvt89YnNdJdhEGoHK4Fa0o635yDRIG4kqIQnoVesqlVYL9zZyvpoBJ7t
RCT5dEA7IzOrg1oYJkK2bVS1FmAwbLGg+LhBoF1JSdJlBTrq/p1hvIbZv97Tujqx
f36SNI7JAG7cmL3c7IAFrQI932XtCwP39xaEBDG6k5TY8hL4iuO/Qq+n1M0RFxbI
Qh0UqEL20kCGoE8jypZFVmAGzbdVAaYBlGX+bgUJurSkquLvWL69J1bY73NxW0Qz
8ppy6rBePm6pUlvscG21h483XjyMnM7k8M4MZ0HMzvaAq07MTFb1wWFZk7Q+ptq4
NxKfKjLji7gh7MMrZQzvIt6IKTtM1/r+t+FHvpw+PoP7UV31aPcuIYXcv/Fa4nzX
xeSDwWrruoBa3lwtcHb4yOWHh8qgnaHlIhInD0Q9HWzq1MKLL295q39QpsQZp6F6
t5b5wR9iWqJDB0BeJsas7a5wFsWqynKKTbDPAYsDP27X
-----END CERTIFICATE-----`,
    expectedFingerprint: '3f:63:bb:28:14:be:17:4e:c8:b6:43:9c:f0:8d:6d:56:f0:b7:c4:05:88:3a:56:48:a3:34:42:4d:6b:3e:c5:58',
    source: 'Same cert as taiwan-roots.ts. TWCA may issue new TSA chains under CYBER going forward.',
    notes: 'Newer TWCA root that will likely anchor future TSA chains.',
  },
  {
    name: 'Government Root Certification Authority (GRCA G2) (TSA anchor)',
    pem: `-----BEGIN CERTIFICATE-----
MIIFSzCCAzOgAwIBAgIRALZLiAfiI+7IXBKtpg4GofIwDQYJKoZIhvcNAQELBQAw
PzELMAkGA1UEBhMCVFcxMDAuBgNVBAoMJ0dvdmVybm1lbnQgUm9vdCBDZXJ0aWZp
Y2F0aW9uIEF1dGhvcml0eTAeFw0xMjA5MjgwODU4NTFaFw0zNzEyMzExNTU5NTla
MD8xCzAJBgNVBAYTAlRXMTAwLgYDVQQKDCdHb3Zlcm5tZW50IFJvb3QgQ2VydGlm
aWNhdGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
AQC2/5c8gb4BWCQnr44BK9ZykjAyG1+bfNTUf+ihYHMwVxAA+lCWJP5Q5ow6ldFX
eYTVZ1MMKoI+GFy4MCYa1l7GLbIEUQ7v3wxjR+vEEghRK5lxXtVpe+FdyXcdIOxW
juVhYC386RyA3/pqg7sFtR4jEpyCygrzFB0g5AaPQySZn7YKk1pzGxY5vgW28Yyl
ZJKPBeRcdvc5w88tvQ7Yy6gOMZvJRg9nU0MEj8iyyIOAX7ryD6uBNaIgIZfOD4k0
eA/PH07p+4woPN405+2f0mb1xcoxeNLOUNFggmOd4Ez3B66DNJ1JSUPUfr0t4urH
cWWACOQ2nnlwCjyHKenkkpTqBpIpJ3jmrdc96QoLXvTg1oadLXLLi2RW5vSueKWg
OTNYPNyoj420ai39iHPplVBzBN8RiD5C1gJ0+yzEb7xs1uCAb9GGpTJXA9ZN9E4K
mSJ2fkpAgvjJ5E7LUy3Hsbbi08J1J265DnGyNPy/HE7CPfg26QrMWJqhGIZO4uGq
s3NZbl6dtMIIr69c/aQCb/+4DbvVq9dunxpPkUDwH0ZVbaCSw4nNt7H/HLPLo5wK
4/7NqrwB7N1UypHdTxOHpPaY7/1J1lcqPKZc9mA3v9g+fk5oKiMyOr5u5CI9ByTP
isubXVGzMNJxbc5Gim18SjNE2hIvNkvy6fFRCW3bapcOFwIDAQABo0IwQDAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBTVZx3gnHosnMvFmOcdByYqhux0zTAOBgNV
HQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQELBQADggIBAJA75cJTQijq9TFOjj2Rnk0J
89ixUuZPrAwxIbvx6pnMg/y2KOTshAcOD06Xu29oRo8OURWV+Do7H1+CDgxxDryR
T64zLiNB9CZrTxOH+nj2LsIPkQWXqmrBap+8hJ4IKifd2ocXhuGzyl3tOKkpboTe
Rmv8JxlQpRJ6jH1i/NrnzLyfSa8GuCcn8on3Fj0Y5r3e9YwSkZ/jBI3+BxQaWqw5
ghvxOBnhY+OvbLamURfr+kvriyL2l/4QOl+UoEtTcT9a4RD4co+WgN2NApgAYT2N
vC2xR8zaXeEgp4wxXPHj2rkKhkfIoT0Hozymc26Uke1uJDr5yTDRB6iBfSZ9fYTf
hsmL5a4NHr6JSFEVg5iWL0rrczTXdM3Jb9DCuiv2mv6Z3WAUjhv5nDk8f0OJU+jl
wqu+Iq0nOJt3KLejY2OngeepaUXrjnhWzAWEx/uttjB8YwWfLYwkf0uLkvw4Hp+g
pVezbp3YZLhwmmBScMip0P/GnO0QYV7Ngw5u6E0CQUridgR51lQ/ipgyFKDdLZzn
uoJxo4ZVKZnSKdt1OvfbQ/+2W/u3fjWAjg1srnm3Ni2XUqGwB5wH5Ss2zQOXlL0t
DjQG/MAWifw3VOTWzz0TBPKR2ck2Lj7FWtClTILD/y58Jnb38/1FoqVuVa4uzM8s
iTTa9g3nkagQ6hed8vbs
-----END CERTIFICATE-----`,
    expectedFingerprint: '70:b9:22:bf:da:0e:3f:4a:34:2e:4e:e2:2d:57:9a:e5:98:d0:71:cc:5e:c9:c3:0f:12:36:80:34:03:88:ae:a5',
    source: 'Same cert as taiwan-roots.ts. Anchors the Government PKI TSA chain when TWES / GCA timestamps are involved.',
    notes: 'Government TSA chains terminate here.',
  },
]

export function getPopulatedTsaEntries(): TrustAnchorEntry[] {
  return TAIWAN_TSA_ROOT_CERTIFICATES.filter((entry) => entry.pem.trim().length > 0)
}

export function hasAnyEmbeddedTsaPem(): boolean {
  return TAIWAN_TSA_ROOT_CERTIFICATES.some((entry) => entry.pem.trim().length > 0)
}
