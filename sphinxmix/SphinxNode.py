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

from os import urandom
from struct import unpack
from binascii import hexlify

# Python 2/3 compatibility
from builtins import bytes

class SphinxException(Exception):
    pass

# Core Process function -- devoid of any chrome
def sphinx_process(params, secret, header, delta):
    """ The heart of a Sphinx server, that processes incoming messages.
    It takes a set of parameters, the secret of the server, the dictionary of seen messages,
    and an incoming message header and body.
    It may return 3 structures:
        - ("Node", (nextmix, header, delta)): The message needs to be forwarded to the next mix.
        - ("Process", ((type, receiver), body)): The message should be sent to the final receiver.
        - ("Client", ((receiver, surbid), delta)): The SURB reply needs to be send to the receiver with a surbid index.
     """
    p = params
    group = p.group
    alpha, beta, gamma = header

    # Check that alpha is in the group
    if not group.in_group(alpha):
        raise SphinxException("Alpha not in Group.")

    # Compute the shared secret
    s = group.expon(alpha, secret)
    
    assert len(beta) == p.max_len - 32
    # print("B: \n%s" % hexlify(beta))
    if gamma != p.mu(p.hmu(s), beta):
        raise SphinxException("MAC mismatch.")

    beta_pad = beta + (b"\x00" * (2 * p.max_len)) 
    B = p.xor(beta_pad, p.rho(p.hrho(s), len(beta_pad)))

    length = B[0]
    rest = B[1+length:]

    tag = p.htau(s)
    b = p.hb(alpha, s)
    alpha = group.expon(alpha, b)
    gamma = rest[:p.k]
    beta = rest[p.k:p.k+(p.max_len - 32)]
    delta = p.pii(p.hpi(s), delta)

    ret = (tag, B, ((alpha, beta, gamma), delta))
    return ret

