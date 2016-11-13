#!/usr/bin/env python

# Copyright 2011 Ian Goldberg
# Copyright 2016 George Danezis (UCL InfoSec Group)
#
# This file is part of Sphinx.
# 
# Sphinx is free software: you can redistribute it and/or modify
# it under the terms of version 3 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
# 
# Sphinx is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with Sphinx.  If not, see
# <http://www.gnu.org/licenses/>.
#
# The LIONESS implementation and the xcounter CTR mode class are adapted
# from "Experimental implementation of the sphinx cryptographic mix
# packet format by George Danezis".


from os import urandom
from hashlib import sha256
import hmac

from petlib.ec import EcGroup, EcPt, POINT_CONVERSION_UNCOMPRESSED
from petlib.bn import Bn
from petlib.cipher import Cipher
import numpy

# Python 2/3 compatibility
from builtins import bytes

from SphinxNymserver import Nymserver

class Group_ECC:
    "Group operations in ECC"

    def __init__(self, gid=713):
        self.G = EcGroup(gid)
        self.g = self.G.generator() # .export()

    def gensecret(self):
        return self.G.order().random() # .binary()

    def expon(self, base, exp):
        # x = Bn.from_binary(exp)
        # b = EcPt.from_binary(base, self.G)
        
        x = exp
        b = base
        return (x * b) # .export()

    def multiexpon(self, base, exps):
        # base = EcPt.from_binary(base, self.G)
        expon = 1
        for e in exps:
            # expon = Bn.from_binary(e).mod_mul( expon, self.G.order())
            expon = e.mod_mul( expon, self.G.order())
        return (expon * base) # .export()

    def makeexp(self, data):
        return (Bn.from_binary(data) % self.G.order()) # .binary()
        #return data % self.G.order()

    def in_group(self, alpha):
        # All strings of length 32 are in the group, says DJB
        b = alpha # EcPt.from_binary(alpha, self.G)
        return self.G.check_point(b)

    def printable(self, alpha):
        return alpha.export(POINT_CONVERSION_UNCOMPRESSED) # .encode("hex")

def test_group():
    G = Group_ECC()
    sec1 = G.gensecret();
    sec2 = G.gensecret();
    gen = G.g

    assert G.expon(G.expon(gen, sec1), sec2) == G.expon(G.expon(gen, sec2), sec1)
    assert G.expon(G.expon(gen, sec1), sec2) == G.multiexpon(gen, [sec2, sec1])
    assert G.in_group(G.expon(gen, sec1))

def test_params():
    # Test Init
    params = SphinxParams()
    
    # Test XOR
    assert params.xor(b"AAA", b"AAA") == b"\x00\x00\x00"
    x = urandom(20)
    assert params.xor(x, x)[-1:] == b"\x00"

    # Test Lioness
    k = b"A" * 16
    m = b"ARG"* 16

    c = params.lioness_enc(k,m)
    m2 = params.lioness_dec(k, c)
    assert m == m2

    k = urandom(16)
    c = params.aes_ctr(k, b"Hello World!")
    assert params.aes_ctr(k, c) == b"Hello World!"

class SphinxParams:
    k = 16 # in bytes, == 128 bits
    m = 1024 # size of message body, in bytes
    pki = {} # mapping of node id to node
    clients = {} # mapping of destinations to clients


    def __init__(self, r=5, group=None):
        self.r = r
        self.aes = Cipher("AES-128-CTR")

        self.group = group
        if not group:
            self.group = Group_ECC()

        self.nymserver = Nymserver(self)

    def xor(self, data, key):
        data = bytes(data)
        key = bytes(key)
        assert len(data) == len(key)
        assert type(data) is bytes and type(key) is bytes
        # Select the type size in bytes       
        dt = numpy.dtype('B');
        return bytes(numpy.bitwise_xor(numpy.fromstring(key, dtype=dt), numpy.fromstring(data, dtype=dt)).tostring())

    # The LIONESS PRP

    def aes_ctr(self, k, m):
        k = bytes(k)
        m = bytes(m)
        assert type(k) is bytes and type(m) is bytes
        iv = b"\x00" * 16
        c = self.aes.enc(k, iv).update(m)
        return c

    def lioness_enc(self, key, message):
        assert len(key) == self.k
        assert len(message) >= self.k * 2
        # Round 1
        r1 = self.xor(self.hash(message[self.k:]+key+b'1')[:self.k],
                message[:self.k]) + message[self.k:]

        # Round 2
        k2 = self.xor(r1[:self.k], key)
        c = self.aes_ctr(k2, r1[self.k:])
        r2 = r1[:self.k] + c

        # Round 3
        r3 = self.xor(self.hash(r2[self.k:]+key+b'3')[:self.k], r2[:self.k]) + r2[self.k:]

        # Round 4
        k4 = self.xor(r3[:self.k], key)
        c = self.aes_ctr(k4, r3[self.k:])
        r4 = r3[:self.k] + c

        return r4

    def lioness_dec(self, key, message):
        assert len(key) == self.k
        assert len(message) >= self.k * 2

        r4 = message

        # Round 4
        k4 = self.xor(r4[:self.k], key)
        c = self.aes_ctr(k4, r4[self.k:])
        r3 = r4[:self.k] + c # c.encrypt(r4[self.k:])

        # Round 3
        r2 = self.xor(self.hash(r3[self.k:]+key+b'3')[:self.k], r3[:self.k]) + r3[self.k:]

        # Round 2
        k2 = self.xor(r2[:self.k], key)
        c = self.aes_ctr(k2, r2[self.k:])
        r1 = r2[:self.k] + c # c.encrypt(r2[self.k:])

        # Round 1
        r0 = self.xor(self.hash(r1[self.k:]+key+b'1')[:self.k], r1[:self.k]) + r1[self.k:]

        return r0

    # The PRG; key is of length k, output is of length (2r+3)k
    def rho(self, key):
        assert len(key) == self.k
        p = b"\x00" * ( (2 * self.r + 3) * self.k )
        return self.aes_ctr(key, p)

    # The HMAC; key is of length k, output is of length k
    def mu(self, key, data):
        mac = hmac.new(key, data, digestmod=sha256).digest()[:self.k]
        return mac

    # The PRP; key is of length k, data is of length m
    def pi(self, key, data):
        assert len(key) == self.k
        assert len(data) == self.m

        return self.lioness_enc(key, data)

    # The inverse PRP; key is of length k, data is of length m
    def pii(self, key, data):
        assert len(key) == self.k
        assert len(data) == self.m

        return self.lioness_dec(key, data)

    # The various hashes

    def hash(self, data):
        return sha256(data).digest()

    def hb(self, alpha, s):
        "Compute a hash of alpha and s to use as a blinding factor"
        group = self.group
        return group.makeexp(self.hash(b"hb:" + group.printable(alpha)
            + b" , " + group.printable(s)))

    def hrho(self, s):
        "Compute a hash of s to use as a key for the PRG rho"
        group = self.group
        return (self.hash(b"hrho:" + group.printable(s)))[:self.k]

    def hmu(self, s):
        "Compute a hash of s to use as a key for the HMAC mu"
        group = self.group
        return (self.hash(b"hmu:" + group.printable(s)))[:self.k]

    def hpi(self, s):
        "Compute a hash of s to use as a key for the PRP pi"
        group = self.group
        return (self.hash(b"hpi:" + group.printable(s)))[:self.k]

    def htau(self, s):
        "Compute a hash of s to use to see if we've seen s before"
        group = self.group
        return (self.hash(b"htau:" + group.printable(s)))

if __name__ == '__main__':
    p = SphinxParams(5, True)
    print(p.hb(p.group.g, p.group.g).encode("hex"))
    print(p.rho("1234" * 4).encode("hex"))
