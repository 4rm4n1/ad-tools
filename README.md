# AD Tools

Utilidades para auditoría de entornos Active Directory / Windows.

## Scripts

### decode_sid.py
Convierte un `objectSid` de Active Directory en formato Base64 (LDAP) 
al formato legible S-1-5-...

```bash
python decode_sid.py
```

### rc4_hmac.py
Genera el NT hash (RC4-HMAC, etype 23) de una contraseña en texto plano.
Útil para auditorías Kerberos.

```bash
python rc4_hmac.py MiPassword
python rc4_hmac.py -w wordlist.txt
```

## Uso
Herramientas orientadas a pentesting y administración de sistemas Windows/AD.
