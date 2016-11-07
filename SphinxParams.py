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

import os
from SphinxNymserver import Nymserver

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256, HMAC
    from Crypto.Util import number
except:
    print "\n\n*** You need to install the Python Cryptography Toolkit. ***\n\n"
    raise

try:
    from curvedh import *
except:
    pass

from hashlib import sha256

from petlib.ec import EcGroup, EcPt
from petlib.bn import Bn
from petlib.cipher import Cipher


import numpy

class Group_ECC:
    "Group operations in ECC"

    def __init__(self, gid=713):
        self.G = EcGroup(gid)
        self.g = self.G.generator().export()

    def gensecret(self):
        return self.G.order().random().binary()

    def expon(self, base, exp):
        x = Bn.from_binary(exp)
        b = EcPt.from_binary(base, self.G)
        return (x * b).export()

    def multiexpon(self, base, exps):
        baseandexps = [base]
        baseandexps.extend(exps)
        return reduce(self.expon, baseandexps)

    def makeexp(self, data):
        return (Bn.from_binary(data) % self.G.order()).binary()

    def in_group(self, alpha):
        # All strings of length 32 are in the group, says DJB
        b = EcPt.from_binary(alpha, self.G)
        return self.G.check_point(b)

    def printable(self, alpha):
        return alpha.encode("hex")

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
    assert params.xor("AAA", "AAA") == "\x00\x00\x00"
    x = os.urandom(20)
    assert params.xor(x, x)[-1] == "\x00"

    # Test Lioness
    k = "A" * 16
    m = "ARG"* 16

    c = params.lioness_enc(k,m)
    m2 = params.lioness_dec(k, c)
    assert m == m2

class SphinxParams:
    k = 16 # in bytes, == 128 bits
    m = 1024 # size of message body, in bytes
    pki = {} # mapping of node id to node
    clients = {} # mapping of destinations to clients

    def __init__(self, r=5, group=None):
        self.r = r
        if group:
            self.group = group
        else:
            self.group = Group_ECC()

        self.nymserver = Nymserver(self)

    def xor(self, data, key):
        assert len(data) == len(key)
        # Select the type size in bytes       
        dt = numpy.dtype('B');
        return numpy.bitwise_xor(numpy.fromstring(key, dtype=dt), numpy.fromstring(data, dtype=dt)).tostring()

    class xcounter:
        # Implements a string counter to do AES-CTR mode
        i = 0
        def __init__(self, size):
            self.size = size
    
        def __call__(self):
            ii = number.long_to_bytes(self.i)
            ii = '\x00' * (self.size-len(ii)) + ii
            self.i += 1
            return ii

    # The LIONESS PRP

    def lioness_enc(self, key, message):
        assert len(key) == self.k
        assert len(message) >= self.k * 2
        # Round 1
        r1 = self.xor(self.hash(message[self.k:]+key+'1')[:self.k],
                message[:self.k]) + message[self.k:]

        # Round 2
        k2 = self.xor(r1[:self.k], key)
        c = AES.new(k2, AES.MODE_CTR, counter=self.xcounter(self.k))
        r2 = r1[:self.k] + c.encrypt(r1[self.k:])

        # Round 3
        r3 = self.xor(self.hash(r2[self.k:]+key+'3')[:self.k], r2[:self.k]) + r2[self.k:]

        # Round 4
        k4 = self.xor(r3[:self.k], key)
        c = AES.new(k4, AES.MODE_CTR, counter=self.xcounter(self.k))
        r4 = r3[:self.k] + c.encrypt(r3[self.k:])

        return r4

    def lioness_dec(self, key, message):
        assert len(key) == self.k
        assert len(message) >= self.k * 2

        r4 = message

        # Round 4
        k4 = self.xor(r4[:self.k], key)
        c = AES.new(k4, AES.MODE_CTR, counter=self.xcounter(self.k))
        r3 = r4[:self.k] + c.encrypt(r4[self.k:])

        # Round 3
        r2 = self.xor(self.hash(r3[self.k:]+key+'3')[:self.k], r3[:self.k]) + r3[self.k:]

        # Round 2
        k2 = self.xor(r2[:self.k], key)
        c = AES.new(k2, AES.MODE_CTR, counter=self.xcounter(self.k))
        r1 = r2[:self.k] + c.encrypt(r2[self.k:])

        # Round 1
        r0 = self.xor(self.hash(r1[self.k:]+key+'1')[:self.k], r1[:self.k]) + r1[self.k:]

        return r0

    # The PRG; key is of length k, output is of length (2r+3)k
    def rho(self, key):
        assert len(key) == self.k
        c = AES.new(key, AES.MODE_CTR, counter=self.xcounter(self.k))
        return c.encrypt("\x00" * ( (2 * self.r + 3) * self.k ))

    # The HMAC; key is of length k, output is of length k
    def mu(self, key, data):
        m = HMAC.new(key, msg=data, digestmod=SHA256)
        return m.digest()[:self.k]

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
        return group.makeexp(self.hash("hb:" + group.printable(alpha)
            + " , " + group.printable(s)))

    def hrho(self, s):
        "Compute a hash of s to use as a key for the PRG rho"
        group = self.group
        return (self.hash("hrho:" + group.printable(s)))[:self.k]

    def hmu(self, s):
        "Compute a hash of s to use as a key for the HMAC mu"
        group = self.group
        return (self.hash("hmu:" + group.printable(s)))[:self.k]

    def hpi(self, s):
        "Compute a hash of s to use as a key for the PRP pi"
        group = self.group
        return (self.hash("hpi:" + group.printable(s)))[:self.k]

    def htau(self, s):
        "Compute a hash of s to use to see if we've seen s before"
        group = self.group
        return (self.hash("htau:" + group.printable(s)))

if __name__ == '__main__':
    p = SphinxParams(5, True)
    print p.hb(p.group.g, p.group.g).encode("hex")
    print p.rho("1234" * 4).encode("hex")
