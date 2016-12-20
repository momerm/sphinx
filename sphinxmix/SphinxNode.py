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

# Padding/unpadding of message bodies: a 0 bit, followed by as many 1
# bits as it takes to fill it up

def pad_body(msgtotalsize, body):
    """ Unpad the Sphinx message body."""
    body = body + b"\x7f"
    body = body + (b"\xff" * (msgtotalsize - len(body)))
    return body

def unpad_body(body):
    """ Pad a Sphinx message body. """
    body = bytes(body)
    l = len(body) - 1
    x_marker = bytes(b"\x7f")[0]
    f_marker = bytes(b"\xff")[0]
    while body[l] == f_marker and l > 0:
        l -= 1
    
    if body[l] == x_marker:
        ret = body[:l]
    else:
        ret = b''
    
    return ret

# Prefix-free encoding/decoding of node names and destinations

# The special destination
Dspec = b"\x00"

# Any other destination.  Must be between 1 and 127 bytes in length
def Denc(dest):
    dest = bytes(dest)
    assert type(dest) is bytes
    assert len(dest) >= 1 and len(dest) <= 127
    return bytes([ len(dest) ]) + dest

def test_Denc():
    assert Denc(bytes(b'dest')) == b'\x04dest'

# Sphinx nodes
def Nenc(param, idnum):
    """ The encoding of mix names. """
    id = b"\xff" + idnum + (b"\x00" * (param.k - len(idnum) - 1))
    assert len(id) == param.k
    return id

# Decode the prefix-free encoding.  Return the type, value, and the
# remainder of the input string
def PFdecode(param, s):
    """ Decoder of prefix free encoder for commands."""
    assert type(s) is bytes
    if s == b"": return None, None, None
    if s[:1] == b'\x00': return 'Dspec', None, s[1:]
    if s[:1] == b'\xff': return 'node', s[:param.k], s[param.k:]
    l = s[0]
    if l < 128: return 'dest', s[1:l+1], s[l+1:]
    
    print(s)
    assert False
    return None, None, None


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
    
    if gamma != p.mu(p.hmu(s), beta):
        raise SphinxException("MAC mismatch.")

    B = p.xor(beta + (b"\x00" * (2 * p.k)), p.rho(p.hrho(s)))

    typex, valx, rest = PFdecode(params, B)

    # Have we seen it already?
    tag = p.htau(s)
    b = p.hb(alpha, s)
    alpha = group.expon(alpha, b)
    gamma = rest[:p.k]
    beta = rest[p.k:]
    delta = p.pii(p.hpi(s), delta)

    ret = (tag, (typex, valx, rest), ((alpha, beta, gamma), delta))
    return ret


# class SphinxTestNode:
#     """ A Sphinx Test Node class."""

#     def __init__(self, params, pki, secret=None):
#         self.p = params
#         group = self.p.group

#         # Load the user provided secret for the Node
#         if secret == None:
#             self._x = group.gensecret()
#         else:
#             self._x = secret

#         # Generate public key
#         self.y = group.expon(group.g, self._x)
#         idnum = urandom(4)
        

#         self.id = Nenc(self.p, idnum)
#         self.name = b"Node " + idnum # .encode("hex")
        
#         # The list of seen packets
#         self.seen = {}

#         # A local mapping between IDs and Nodes
#         self.pki = pki

#     def process(self, header, delta):

#         RET = sphinx_process(self.p, self._x, header, delta)
#         (tag, (typex, valx, rest), (header, delta)) = RET
        
#         print("Processing at", self.name)

#         p = self.p
#         pki = self.pki

#         if typex == "node":
#             return pki[valx].process(header, delta)

#         if typex == "Dspec":
#             if delta[:p.k] == (b"\x00" * p.k):
#                   type2, val, rest = PFdecode(self.p, delta[self.p.k:])
#                   if type2 == "dest":
#                       body = unpad_body(rest)

#             print("Deliver [%s] to [%s]" % (body, val))
#             return (val, body)

#         if typex == "dest":
#             idc = rest[:self.p.k]
#             if valx in pki:
#                 return pki[valx].process(idc, delta)
#             else:
#                 print("No such client [%s]" % val)
#                 return
