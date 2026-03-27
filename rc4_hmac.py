#!/usr/bin/env python3

import argparse

def _rotl(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def _md4(msg: bytes) -> bytes:
    # RFC 1320 – MD4 (pure Python)
    A, B, C, D = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    orig_bits = (len(msg) * 8) & 0xffffffffffffffff
    msg += b"\x80"
    while (len(msg) % 64) != 56: msg += b"\x00"
    msg += orig_bits.to_bytes(8, "little")

    def F(x,y,z): return (x & y) | (~x & z)
    def G(x,y,z): return (x & y) | (x & z) | (y & z)
    def H(x,y,z): return x ^ y ^ z

    for i in range(0, len(msg), 64):
        X = [int.from_bytes(msg[i+j:i+j+4], "little") for j in range(0, 64, 4)]
        AA, BB, CC, DD = A, B, C, D

        # Round 1
        s = (3,7,11,19)
        for k in range(16):
            if k%4==0: A = _rotl((A + F(B,C,D) + X[k]) & 0xFFFFFFFF, s[0])
            elif k%4==1: D = _rotl((D + F(A,B,C) + X[k]) & 0xFFFFFFFF, s[1])
            elif k%4==2: C = _rotl((C + F(D,A,B) + X[k]) & 0xFFFFFFFF, s[2])
            else:        B = _rotl((B + F(C,D,A) + X[k]) & 0xFFFFFFFF, s[3])

        # Round 2
        s = (3,5,9,13); order = (0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15)
        for k in range(16):
            iX = order[k]
            if k%4==0: A = _rotl((A + G(B,C,D) + X[iX] + 0x5a827999) & 0xFFFFFFFF, s[0])
            elif k%4==1: D = _rotl((D + G(A,B,C) + X[iX] + 0x5a827999) & 0xFFFFFFFF, s[1])
            elif k%4==2: C = _rotl((C + G(D,A,B) + X[iX] + 0x5a827999) & 0xFFFFFFFF, s[2])
            else:        B = _rotl((B + G(C,D,A) + X[iX] + 0x5a827999) & 0xFFFFFFFF, s[3])

        # Round 3
        s = (3,9,11,15); order = (0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15)
        for k in range(16):
            iX = order[k]
            if k%4==0: A = _rotl((A + H(B,C,D) + X[iX] + 0x6ed9eba1) & 0xFFFFFFFF, s[0])
            elif k%4==1: D = _rotl((D + H(A,B,C) + X[iX] + 0x6ed9eba1) & 0xFFFFFFFF, s[1])
            elif k%4==2: C = _rotl((C + H(D,A,B) + X[iX] + 0x6ed9eba1) & 0xFFFFFFFF, s[2])
            else:        B = _rotl((B + H(C,D,A) + X[iX] + 0x6ed9eba1) & 0xFFFFFFFF, s[3])

        A = (A + AA) & 0xFFFFFFFF
        B = (B + BB) & 0xFFFFFFFF
        C = (C + CC) & 0xFFFFFFFF
        D = (D + DD) & 0xFFFFFFFF

    return (A.to_bytes(4,'little') + B.to_bytes(4,'little') +
            C.to_bytes(4,'little') + D.to_bytes(4,'little'))

def rc4_hmac_from_password(pw: str) -> str:
    # Kerberos RC4-HMAC key == NT hash
    return _md4(pw.encode("utf-16le")).hex().upper()

def main():
    ap = argparse.ArgumentParser(description="Plaintext -> rc4_hmac (NT hash)")
    ap.add_argument("password", nargs="?", help="plaintext password")
    ap.add_argument("-w","--wordlist", help="file with one password per line")
    args = ap.parse_args()

    if args.wordlist:
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                pw = line.rstrip("\n")
                if pw:
                    print(f"{pw}:{rc4_hmac_from_password(pw)}")
    else:
        pw = args.password if args.password is not None else input("Password: ")
        print(rc4_hmac_from_password(pw))

if __name__ == "__main__":
    main()

