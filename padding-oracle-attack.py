import base64
import requests

def decode(data):
    return base64.b64decode(data.replace('~', '=').replace('!', '/').replace('-', '+'))

def encode(data):
    return base64.b64encode(data).decode('utf-8').replace('=', '~').replace('/', '!').replace('+', '-')

def bxor(b1, b2): # use xor for bytes
    result = b""
    for b1, b2 in zip(b1, b2):
        result += bytes([b1 ^ b2])
    return result

def test(url, data):
    r = requests.get(url+'?post={}'.format(data))
    if 'PaddingException' in r.text:
        return False
    else:
        return True

def generate_iv_list(tail):
    iv = b'\x00' * (16 - len(tail) -1)
    return [iv+bytes([change])+tail for change in range(0x00, 0xff+1)]

def padding_oracle(real_iv, url, data):
    index = 15
    plains = bytes()
    tail = bytes()
    while index >= 0:
        for iv in generate_iv_list(tail):
            if test(url, encode(iv+data)):
                plains = bytes([(16-index) ^ iv[index]]) + plains
                index -= 1
                tail = bytes([plain ^ (16-index) for plain in plains])
                break
    return bxor(real_iv, plains)

if __name__ == '__main__':
    post = 'MKRAo1lbXFPnve5SMutjRl7Hf3YnnX-tLy9mdSwRGynFGPFPrAuVMx2k1K2SIB!gW6ea76GBUrFZanEAz8cyAEk69Ze9-9sB8fBu9lJj-YqXFM6QaONckyYpxQh2RMb60pEJjK5ZM0TrWnepJAeJs4SJv9rKGZVqPpDuj7LrHvMfl8kzQ9OmoqHJp5ejwo3d685XL8YNSkhFhGzs4BpNGw~~'
    url = 'http://35.190.155.168/56848a7821/'

    i = 1
    plains = bytes()
    data = decode(post)
    length = len(data)
    while True:
        if i*16 < length:
            iv = data[(i-1)*16: i*16]
            plains += padding_oracle(iv, url, data[i*16: (i+1)*16])
        else:
            break
        i += 1
    print(plains)
