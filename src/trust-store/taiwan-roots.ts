/**
 * Taiwan PKI Root Certificates (Signing CAs)
 *
 * Hardcoded set of root anchors trusted for end-entity (document signing)
 * certificates. Each PEM body was obtained from a public, signed bundle and
 * its SHA-256 fingerprint was recomputed locally to populate
 * `expectedFingerprint`. The fingerprints are also verifiable against the
 * Mozilla CCADB report and curl.se's `cacert.pem` for the TWCA entries.
 *
 * Sources used to populate this file:
 *   - TWCA Root Certification Authority, TWCA Global Root CA,
 *     TWCA CYBER Root CA — extracted from https://curl.se/ca/cacert.pem
 *     (which mirrors Mozilla CCADB's IncludedRootsPEMTxtReport).
 *   - Government Root Certification Authority G1 — downloaded from
 *     https://grca.nat.gov.tw/repository/Certs/GRCA.cer
 *   - Government Root Certification Authority G2 — downloaded from
 *     https://grca.nat.gov.tw/repository/Certs/GRCA2.cer
 *   - MOICA G2 — downloaded from
 *     https://moica.nat.gov.tw/repository/Certs/MOICA2.cer.
 *     NOTE: MOICA G2 is NOT a self-signed root; it is an intermediate
 *     issued by GRCA G2. We pin it as a trust anchor anyway because most
 *     citizen-digital-certificate signers terminate at MOICA in the PDF's
 *     embedded chain, and operationally we want MOICA-issued signatures
 *     to validate without forcing users to install GRCA as well. The
 *     audit's request "include MOICA as a root" reflects this practice.
 *
 * To verify any entry yourself: decode the PEM to DER and SHA-256 the
 * result. The trust manager rejects an entry whose computed fingerprint
 * doesn't match `expectedFingerprint`.
 */

export interface TrustAnchorEntry {
  /** Human-readable name (used in UI and report) */
  name: string
  /** PEM-encoded X.509 certificate. Empty string = not yet populated. */
  pem: string
  /** SHA-256 fingerprint as published by the CA. Lowercase hex, colon-separated. */
  expectedFingerprint?: string
  /** Where the PEM was obtained from. */
  source: string
  /** Free-form notes (algorithm, validity, retirement plan, etc.). */
  notes?: string
}

export const TAIWAN_ROOT_CERTIFICATES: TrustAnchorEntry[] = [
  {
    name: 'TWCA Global Root CA',
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
    source: 'https://curl.se/ca/cacert.pem (Mozilla CCADB)',
    notes: 'SHA-256 signature, RSA-4096, validity 2012-06-27 → 2030-12-31. Self-signed.',
  },
  {
    name: 'TWCA Root Certification Authority',
    pem: `-----BEGIN CERTIFICATE-----
MIIDezCCAmOgAwIBAgIBATANBgkqhkiG9w0BAQUFADBfMQswCQYDVQQGEwJUVzES
MBAGA1UECgwJVEFJV0FOLUNBMRAwDgYDVQQLDAdSb290IENBMSowKAYDVQQDDCFU
V0NBIFJvb3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMDgwODI4MDcyNDMz
WhcNMzAxMjMxMTU1OTU5WjBfMQswCQYDVQQGEwJUVzESMBAGA1UECgwJVEFJV0FO
LUNBMRAwDgYDVQQLDAdSb290IENBMSowKAYDVQQDDCFUV0NBIFJvb3QgQ2VydGlm
aWNhdGlvbiBBdXRob3JpdHkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQCwfnK4pAOU5qfeCTiRShFAh6d8WWQUe7UREN3+v9XAu1bihSX0NXIP+FPQQeFE
AcK0HMMxQhZHhTMidrIKbw/lJVBPhYa+v5guEGcevhEFhgWQxFnQfHgQsIBct+HH
K3XLfJ+utdGdIzdjp9xCoi2SBBtQwXu4PhvJVgSLL1KbralW6cH/ralYhzC2gfeX
RfwZVzsrb+RH9JlF/h3x+JejiB03HFyP4HYlmlD4oFT/RJB2I9IyxsOrBr/8+7/z
rX2SYgJbKdM1o5OaQ2RgXbL6Mv87BK9NQGr5x+PvI/1ry+UPizgN7gr8/g+YnzAx
3WxSZfmLgb4i4RxYA7qRG4kHAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBRqOFsmjd6LWvJPelSDGRjjCDWmujANBgkq
hkiG9w0BAQUFAAOCAQEAPNV3PdrfibqHDAhUaiBQkr6wQT25JmSDCi/oQMCXKCeC
MErJk/9q56YAf4lCmtYR5VPOL8zy2gXE/uJQxDqGfczafhAJO5I1KlOy/usrBdls
XebQ79NqZp4VKIV66IIArB6nCWlWQtNoURi+VJq/REG6Sb4gumlc7rh3zc5sH62D
lhh9DrUUOYTxKOkto557HnpyWoOzeW/vtPzQCqVYT0bf+215WfKEIlKuD8z7fDvn
aspHYcN6+NOSBB+4IIThNlQWx0DeO4pz3N/GCUzf7Nr/1FNCocnyYh0igzyXxfkZ
YiesZSLX0zzG5Y6yU8xJzrww/nsOM5D77dIUkR8Hrw==
-----END CERTIFICATE-----`,
    expectedFingerprint: 'bf:d8:8f:e1:10:1c:41:ae:3e:80:1b:f8:be:56:35:0e:e9:ba:d1:a6:b9:bd:51:5e:dc:5c:6d:5b:87:11:ac:44',
    source: 'https://curl.se/ca/cacert.pem (Mozilla CCADB)',
    notes: 'SHA-1 signature (legacy), RSA-2048, validity 2008-08-28 → 2030-12-31. Self-signed.',
  },
  {
    name: 'TWCA CYBER Root CA',
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
    source: 'https://curl.se/ca/cacert.pem (Mozilla CCADB)',
    notes: 'SHA-384 signature, RSA-4096, validity 2022-11-22 → 2047-11-22. Self-signed. Newer TWCA root.',
  },
  {
    name: 'Government Root Certification Authority (GRCA G1)',
    pem: `-----BEGIN CERTIFICATE-----
MIIFcjCCA1qgAwIBAgIQH51ZWtcvwgZEpYAIaeNe9jANBgkqhkiG9w0BAQUFADA/
MQswCQYDVQQGEwJUVzEwMC4GA1UECgwnR292ZXJubWVudCBSb290IENlcnRpZmlj
YXRpb24gQXV0aG9yaXR5MB4XDTAyMTIwNTEzMjMzM1oXDTMyMTIwNTEzMjMzM1ow
PzELMAkGA1UEBhMCVFcxMDAuBgNVBAoMJ0dvdmVybm1lbnQgUm9vdCBDZXJ0aWZp
Y2F0aW9uIEF1dGhvcml0eTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AJoluOzMonWoe/fOW1mKydGGEghU7Jzy50b2iPN86aXfTEc2pBsBHH8eV4qNw8XR
IePaJD9IK/ufLqGU5ywck9G/GwGHU5nOp/UKIXZ3/6m3xnOUT0b3EEk3+qhZSV1q
gQdW8or5BtD3cCJNtLdBuTK4sfCxw5w/cP1T3YGq2GN49thTbqGsaoQkclSGxtKy
yhwOeYHWtXBiCAEuTk8O1RGvqa/lmr/czIdtJuTJV6L7lvnM4T9TjGxMfptTCAts
F/tnyMKtsc2AtJfcdgEWFelq16TheEfOhtX7MfP6Mb40qij7cEwdScevLJ1tZqa2
jWR+tSBqnTuBto9AAGdLiYa4zGX+FVPpBMHWXx1E1wovJ5pGfaENda1UhhXcSTvx
ls4Pm6Dso3pdvtUqdULle96ltqqvKKyskKw4t9VoNSZ63Pc78/1Fm9G7Q3hub/FC
VGqY8A2tl+lSXunVanLeavcbYBT0peS2cWeqH+riTcFCQP5nRhc4L0c/cZyu5SHK
YS1tB6iEfC3uUSXxY5Ce/eFXiGvviiNtsea9P63RPZYLhY3Naye7twWb7LuRqQoH
EgKXTiCQ8P8NHuJBO9NAOueNXdpm5AKwB1KYXA6OM5zCppX7VRluTI6uSw+9wThN
Xo+EHWbNxWCWtFJaBYmOlXqYwZE8lSOyDvR5tMl8wUohAgMBAAGjajBoMB0GA1Ud
DgQWBBTMzO/MKWCkO7GStjz6MmKPrCUVOzAMBgNVHRMEBTADAQH/MDkGBGcqBwAE
MTAvMC0CAQAwCQYFKw4DAhoFADAHBgVnKgMAAAQUA5vwIhP/lSg209yewDL7MTqK
UWUwDQYJKoZIhvcNAQEFBQADggIBAECASvomyc5eMN1PhnR2WPWus4MzeKR6dBcZ
TulStbngCnRiqmjKeKBMmo4sIy7VahIkv9Ro04rQ2JyftB8M3jh+Vzj8jeJPXgyf
qzvS/3WXy6TjZwj/5cAWtUgBfen5Cv8b5Wppv3ghqMKnI6mGq3ZW6A4M9hPdKmaK
ZEk9GhiHkASfQlK3T8v+R0F2Ne//AHY2RTKbxkaFXeIksB7jSJaYV0eUVXoPQbFE
JPPB/hprv4j9wabak2BegUqZIJxIZhm1AHlUD7gsL0u8qV1bYH+Mh6XgUmMqvtg7
hUAV/h62ZT/FS9p+tXo1KaMuephgIqP0fSdOLeq0dDzpD6QzDxARvBMB1uUO07+1
EqLhRSPAzAhuYbeJq4PjJB7mXQfnHyA+z2fI56wwbSdLaG5LKlwCCDTb+HbkZ6Mm
nD+iMsJKxYEYMRBWqoTvLQr/uB930r+lWKBi5NdLkXWNiYCYfm3LU05er/ayl4WX
udpVBrkk7tfGOB5jGxI7leFYrPLfhNVfmS8NVVvmONsuP3LpSIXLuykTjx44Vbnz
ssQwmSNOXfJIoRIM3BKQCZBUkQM8R+XVyWXgt0t97EfTsws+rZ7QdAAO671RrcDe
LMDDav7v3Aun+kbfYNucpllQdSNpc5Oy+fwC00fmcc4QAu4njIT/rEUNE1yDMuAl
pYYsfPQS
-----END CERTIFICATE-----`,
    expectedFingerprint: '76:00:29:5e:ef:e8:5b:9e:1f:d6:24:db:76:06:2a:aa:ae:59:81:8a:54:d2:77:4c:d4:c0:b2:c0:11:31:e1:b3',
    source: 'https://grca.nat.gov.tw/repository/Certs/GRCA.cer',
    notes: 'SHA-1 signature (legacy), RSA-4096, validity 2002-12-05 → 2032-12-05. Self-signed top of GPKI.',
  },
  {
    name: 'Government Root Certification Authority (GRCA G2)',
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
    source: 'https://grca.nat.gov.tw/repository/Certs/GRCA2.cer',
    notes: 'SHA-256 signature, RSA-4096, validity 2012-09-28 → 2037-12-31. Self-signed. Newer GPKI root.',
  },
  {
    name: 'MOICA G2 (citizen digital certificate, subordinate to GRCA G2)',
    pem: `-----BEGIN CERTIFICATE-----
MIIFKDCCAxCgAwIBAgIQUcO1wamhWIYJIiIx1hrArTANBgkqhkiG9w0BAQsFADA/
MQswCQYDVQQGEwJUVzEwMC4GA1UECgwnR292ZXJubWVudCBSb290IENlcnRpZmlj
YXRpb24gQXV0aG9yaXR5MB4XDTE0MDEwMjA2MzEwNFoXDTM0MDEwMjA2MzEwNFow
RzELMAkGA1UEBhMCVFcxEjAQBgNVBAoMCeihjOaUv+mZojEkMCIGA1UECwwb5YWn
5pS/6YOo5oaR6K2J566h55CG5Lit5b+DMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAn9gInAVVnWPVqzS8XfaF+10vRLo3ulZAI4sAYxrOcFCTNQnQ+bZz
b/6iqWgg4fvAxbIbMZfhbQ01eihjledeZEAvN66P/87iSBwiplWESeE1LrKEQkot
4ic2F/YKXU9/u2Vk8ek6pQzoxNMNg5BACTYqAWC13VPoGPiPNErxLphj5VJopMgb
oiCUETh1UYy/TVAZUIHWMKpALi+eqThHJc+oJ1Qju0C715zdnRI3HQYkuFoF9vYi
OSLJgVUeqJ538E3z4iuTUZ+jcohxfSFGt4e3hwPVqn/xhn+cYI8gbpxqOfAMLyv/
+REKhb8Vwl2uILOKf29aEgJtCKHLxoEpHQIDAQABo4IBFjCCARIwHwYDVR0jBBgw
FoAU1Wcd4Jx6LJzLxZjnHQcmKobsdM0wHQYDVR0OBBYEFPqbNGcJCpgi92JIi4Im
pkXFwyKkMA4GA1UdDwEB/wQEAwIBBjAUBgNVHSAEDTALMAkGB2CGdmUAAwMwEgYD
VR0TAQH/BAgwBgEB/wIBADA+BgNVHR8ENzA1MDOgMaAvhi1odHRwOi8vZ3JjYS5u
YXQuZ292LnR3L3JlcG9zaXRvcnkvQ1JMMi9DQS5jcmwwVgYIKwYBBQUHAQEESjBI
MEYGCCsGAQUFBzAChjpodHRwOi8vZ3JjYS5uYXQuZ292LnR3L3JlcG9zaXRvcnkv
Q2VydHMvSXNzdWVkVG9UaGlzQ0EucDdiMA0GCSqGSIb3DQEBCwUAA4ICAQAYjLOx
0ErTqE8Yul0WIRw7yl7UPy23z1xNn2lhs022lpTSWA8ebx3fATUnSPx6oBiGoxG8
U/x+NV5DgUy7qenxXHscgOVZVpf7avGcrq8FYrZ0nRGmMCRC30lELnrrH7C9H8YT
VZymh2Ovg2jtJHupvmvb43AV9T68T/739lmSkaw7/tu+Ea3Wtxlunzw++5ameC/U
Z/1LN0qt/ImKlxBIhXmJbhrHGl20bQp3ZfvGtQ8n03rJtX6dbN2U+JQO4LMcY/3T
6Q1sPy2KLA0f2sW4oUM13g8UCIQvhV029DKL3rkDL9xzUHfKBjD9LGDHgdzZ7Fsz
BpFwWEEhsGZx5ZQgFexauozom2lfxSLyZRprWySpMCRlqhU/Vgmx4DwXwWimqH/g
tD6cK9+88lcMqhC2d+Jy6D2OrhSbMMW5chfDW6BETxUBXQRBQ6pG8FfWH+f1WN2j
ytWvymqmvR31e8XsxUa3oOQUTO+NcKBkI3iH7DMR9N5PWwA5OVTrunAl8eC3cb9Z
dIG6j27xMjNck46fYAIIp3uqyK1MTC6Z6e8yygL1pSW7/whNWL/4gp0EFyMkx7M1
V8QmqYNaeVbRVFjDGZ30qh2Osr4mtEPImvHZFX8Sv0keMYemH9oLqyxYzhsb40XC
WNzYC0RS73kTcXATtetNSsXzrxLfbno09jQHsg==
-----END CERTIFICATE-----`,
    expectedFingerprint: 'c4:c4:62:de:46:3f:85:68:04:dc:89:83:38:d2:ce:cb:55:fb:a7:41:55:85:15:99:d8:fb:7d:70:21:8f:d1:be',
    source: 'https://moica.nat.gov.tw/repository/Certs/MOICA2.cer',
    notes: 'NOT self-signed — intermediate under GRCA G2 (issuer: Government Root Certification Authority). Pinned as anchor for operational reasons (citizen-digital-cert chains commonly terminate here in the PDF\'s embedded chain).',
  },
]

/**
 * Whether the build has at least one PEM populated.
 * Used to decide whether to emit a startup warning.
 */
export function hasAnyEmbeddedPem(): boolean {
  return TAIWAN_ROOT_CERTIFICATES.some((entry) => entry.pem.trim().length > 0)
}

/**
 * Return only entries that have a PEM body (filtering out unpopulated slots).
 */
export function getPopulatedEntries(): TrustAnchorEntry[] {
  return TAIWAN_ROOT_CERTIFICATES.filter((entry) => entry.pem.trim().length > 0)
}

/**
 * Get all root certificate PEM strings (populated only)
 */
export function getAllRootCertificates(): string[] {
  return getPopulatedEntries().map((cert) => cert.pem)
}

/**
 * Get root certificate names
 */
export function getRootCertificateNames(): string[] {
  return TAIWAN_ROOT_CERTIFICATES.map((cert) => cert.name)
}
