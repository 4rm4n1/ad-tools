#!/usr/bin/env python3

import base64
import struct

def decode_objectsid(base64_sid):
    # Limpiar posibles prefijos como "objectSid:: "
    sid_b64 = base64_sid.strip().split()[-1]
    
    # Decodificar base64 a binario
    sid_bin = base64.b64decode(sid_b64)
    
    # Leer encabezado del SID
    revision = sid_bin[0]
    sub_authority_count = sid_bin[1]
    identifier_authority = int.from_bytes(sid_bin[2:8], byteorder='big')
    
    # Leer SubAuthorities
    sub_authorities = [
        struct.unpack("<I", sid_bin[8 + i*4:12 + i*4])[0]
        for i in range(sub_authority_count)
    ]
    
    # Construir SID legible
    sid_string = f"S-{revision}-{identifier_authority}-" + "-".join(str(s) for s in sub_authorities)
    return sid_string

input_line = input('Introduza el SID: ')
print(decode_objectsid(input_line))
