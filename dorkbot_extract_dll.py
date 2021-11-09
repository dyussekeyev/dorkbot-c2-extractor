import pefile
import base64
from Crypto.Cipher import ARC4

datas = list()

def get_offset(resource_dir):
    if hasattr(resource_dir, 'entries'):
        for entry in resource_dir.entries:
            if hasattr(entry, 'directory'):
                get_offset(entry.directory)
            if hasattr(entry, 'data'):
                data_rva = entry.data.struct.OffsetToData
                data_size = entry.data.struct.Size

                datas.append(pe.get_memory_mapped_image()[data_rva:data_rva+data_size])

def isBase64(sb):
    try:
        if isinstance(sb, str):
            sb_bytes = bytes(sb, 'ascii')
        elif isinstance(sb, bytes):
            sb_bytes = sb
        else:
            raise ValueError("Argument must be string or bytes")
        return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
    except Exception:
        return False

pe = pefile.PE("5C55FC257423ACD1AE6382D88B1EE306.bin")
get_offset(pe.DIRECTORY_ENTRY_RESOURCE)

count = 0
for x in datas:
    if not isBase64(x):
        exit(1)

    decoded = base64.b64decode(x)
    size_dll = int.from_bytes(decoded[0:4], byteorder='little')
    size_bytes = len(decoded) - 32
    
    crypto = ARC4.new(decoded[8:13])
    decrypted = crypto.decrypt(decoded[32:32 + size_bytes])
    decrypted_dll = decrypted[size_bytes - size_dll:size_bytes]

    f = open('decrypted' + str(count) + '.bin', 'wb')
    f.write(decrypted_dll)
    f.close()

    count = count + 1
