from .SphinxCrypto import hello, aes_ctr_c
from .SphinxParams import SphinxParams

from binascii import hexlify

def test_init():
	assert hello() == "Hello"
	x1 = aes_ctr_c(b"\x00"*16, b"\x00"*16, b"\x00"*16)

	p = SphinxParams()
	x2 = p.aes_ctr(b"\x00"*16, b"\x00"*16, b"\x00"*16)

	assert x1 == x2