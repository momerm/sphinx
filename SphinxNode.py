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
import re

# Padding/unpadding of message bodies: a 0 bit, followed by as many 1
# bits as it takes to fill it up

re_compiled = re.compile("\x7f\xff*$")

def pad_body(msgtotalsize, body):
    body = body + "\x7f"
    body = body + ("\xff" * (msgtotalsize - len(body)))
    return body

def unpad_body(body):
    return re_compiled.sub('', body)

# Prefix-free encoding/decoding of node names and destinations

# The special destination
Dspec = "\x00"

# Any other destination.  Must be between 1 and 127 bytes in length
def Denc(dest):
    assert len(dest) >= 1 and len(dest) <= 127
    return chr(len(dest)) + dest

class SphinxException(Exception):
    pass

# Core Process function -- devoid of any chrome
def sphinx_process(params, secret, seen, header, delta):
    # print "Processing at", self.name
    p = params
    group = p.group

    alpha, beta, gamma = header

    # Check that alpha is in the group
    if not group.in_group(alpha):
        raise SphinxException("Alpha not in Group.")

    # Compute the shared secret
    s = group.expon(alpha, secret)

    # Have we seen it already?
    tag = p.htau(s)

    if tag in seen:
        raise SphinxException("Message already processed.")

    if gamma != p.mu(p.hmu(s), beta):
        raise SphinxException("MAC mismatch.")

    seen[tag] = 1

    B = p.xor(beta + ("\x00" * (2 * p.k)), p.rho(p.hrho(s)))

    type, val, rest = PFdecode(params, B)

    if type == "node":
        b = p.hb(alpha, s)
        alpha = group.expon(alpha, b)
        gamma = B[p.k:p.k*2]
        beta = B[p.k*2:]
        delta = p.pii(p.hpi(s), delta)
        return ("Node", (val, (alpha, beta, gamma), delta))

    if type == "Dspec":
        delta = p.pii(p.hpi(s), delta)
        if delta[:p.k] == ("\x00" * p.k):
            type2, val, rest = PFdecode(params, delta[p.k:])
            if type2 == "dest":
                body = unpad_body(rest)
                return ("Process", ((type2, val), body) )

    if type == "dest":
        id = rest[:p.k]
        delta = p.pii(p.hpi(s), delta)
        return ("Client", ((val,id), delta))


# Sphinx nodes

def Nenc(param, idnum):
    id = "\xff" + idnum + ("\x00" * (param.k - len(idnum) - 1))
    assert len(id) == param.k
    return id

# Decode the prefix-free encoding.  Return the type, value, and the
# remainder of the input string
def PFdecode(param, s):
    if s == "": return None, None, None
    if s[0] == '\x00': return 'Dspec', None, s[1:]
    if s[0] == '\xff': return 'node', s[:param.k], s[param.k:]
    l = ord(s[0])
    if l < 128: return 'dest', s[1:l+1], s[l+1:]
    return None, None, None


class SphinxTestNode:

    def __init__(self, params, secret=None):
        self.p = params
        group = self.p.group

        # Load the user provided secret for the Node
        if secret == None:
            self._x = group.gensecret()
        else:
            self._x = secret

        # Generate public key
        self.y = group.expon(group.g, self._x)
        idnum = urandom(4)
        

        self.id = Nenc(self.p, idnum)
        self.name = "Node " + idnum.encode("hex")
        
        # The list of seen packets
        self.seen = {}

        # A local mapping between IDs and Nodes
        params.pki[self.id] = self

    def process(self, header, delta):

        RET = sphinx_process(self.p, self._x, {}, header, delta)

        print "Processing at", self.name

        p = self.p
        pki = p.pki
        

        type_code = RET[0]
        if type_code == "Node":
            (_, (val, (alpha, beta, gamma), delta)) = RET
            return pki[val].process((alpha, beta, gamma), delta)

        if type_code == "Process":
            (_, ((type2, val), body) ) = RET
            print "Deliver [%s] to [%s]" % (body, val)
            return 

        if type_code == "Client":
            (_, ((val,idc), delta)) = RET            
            if val in p.clients:
                return p.clients[val].process(idc, delta)
            else:
                print "No such client [%s]" % val
                return
