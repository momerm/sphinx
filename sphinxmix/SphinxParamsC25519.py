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

# Python 2/3 compatibility
from builtins import bytes

from nacl.bindings import crypto_scalarmult_base, crypto_scalarmult

class Group_C25519:
    "Group operations in ECC"

    def __init__(self, gid=713):
        # self.G = EcGroup(gid)
        # self.g = self.G.generator()
        pass

    def gensecret(self):
        return urandom(32)

    def expon(self, base, exp):        
        for f in exp:
            base = crypto_scalarmult(f, base)
        return base

    def expon_base(self, exp):
        base = crypto_scalarmult_base(exp[0])        
        for f in exp[1:]:
            base = crypto_scalarmult(f, base)
        return base


    def makeexp(self, data):
        return data[:32]

    def in_group(self, alpha):
        # All strings of length 32 are in the group, says DJB
        return len(alpha) == 32

    def printable(self, alpha):
        return alpha