from .SphinxCrypto import crypto
from .SphinxParams import SphinxParams

from binascii import hexlify
from hashlib import sha256

def test_init():
    C = crypto()
    x1 = C.aes_ctr_c(b"\x00"*16, b"\x00"*16, b"\x00"*16)

    p = SphinxParams()
    x2 = p.aes_ctr(b"\x00"*16, b"\x00"*16, b"\x00"*16)

    assert x1 == x2

    h1 = C.hash(b"hello")
    h2 = sha256(b"hello").digest()

    assert h1 == h2


def test_timing():
    C = crypto()
    p = SphinxParams()

    k = 16
    key = b"\x00" * 16
    m = b"\x01" * 1024

    c1 = p.lioness_enc(key, m)
    c2 = C.lioness_enc(k, key, m)
    assert c1 == c2

    import time
    t0 = time.time()
    for _ in range(10000):
        c1 = p.lioness_enc(key, m)
    t1 = time.time()
    print()
    print("Python lioness_enc: %.2fms" % ((t1-t0)*1000.0/10000))

    t0 = time.time()
    for _ in range(10000):
        c2 = C.lioness_enc(k, key, m)
    t1 = time.time()
    print("Native lioness_enc: %.2fms" % ((t1-t0)*1000.0/10000))