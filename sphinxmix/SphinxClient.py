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

# Python 2/3 compatibility
from builtins import bytes

from .SphinxParams import SphinxParams
from .SphinxNode import SphinxTestNode, Denc, Dspec, pad_body, unpad_body
from .SphinxNymserver import Nymserver

def rand_subset(lst, nu):
    """Return a list of nu random elements of the given list (without
    replacement)."""

    # Randomize the order of the list by sorting on a random key
    nodeids = [(urandom(8),x) for x in lst]
    nodeids.sort(key=lambda x:x[0])

    # Return the first nu elements of the randomized list
    return list(map(lambda x:x[1], nodeids[:nu]))


from collections import namedtuple
header_record = namedtuple("header_record", ["alpha", "s", "b"])
pki_entry = namedtuple("pki_entry", ["id", "x", "y"])

def create_header(params, nodelist, pki, dest, id):
    p = params
    nu = len(nodelist)
    assert nu <= p.r
    assert len(id) == p.k
    assert len(dest) <= 2 * (p.r - nu + 1) * p.k
    group = p.group
    x = group.gensecret()

    # Compute the (alpha, s, b) tuples
    blind_factor = x
    asbtuples = []
    
    for node in nodelist:
        alpha = group.expon(group.g, blind_factor)
        s = group.expon(pki[node].y, blind_factor)
        b = p.hb(alpha, s)
        blind_factor = blind_factor.mod_mul(b, p.group.G.order())
        hr = header_record(alpha, s, b)
        asbtuples.append(hr)

    # Compute the filler strings
    phi = b''
    for i in range(1,nu):
        min = (2*(p.r-i)+3)*p.k
        phi = p.xor(phi + (b"\x00" * (2*p.k)),
            p.rho(p.hrho(asbtuples[i-1].s))[min:])
    
    # Compute the (beta, gamma) tuples
    # The os.urandom used to be a string of 0x00 bytes, but that's wrong
    beta = dest + id + urandom(((2 * (p.r - nu) + 2)*p.k - len(dest)))
    beta = p.xor(beta,
        p.rho(p.hrho(asbtuples[nu-1].s))[:(2*(p.r-nu)+3)*p.k]) + phi
    gamma = p.mu(p.hmu(asbtuples[nu-1].s), beta)
    
    for i in range(nu-2, -1, -1):
        id = nodelist[i+1]
        assert len(id) == p.k
        beta = p.xor(id + gamma + beta[:(2*p.r-1)*p.k],
            p.rho(p.hrho(asbtuples[i].s))[:(2*p.r+1)*p.k])
        gamma = p.mu(p.hmu(asbtuples[i].s), beta)
    
    return (asbtuples[0].alpha, beta, gamma), \
        [x.s for x in asbtuples]


def create_forward_message(params, nodelist, pki, dest, msg):
    p = params
    # pki = p.pki
    nu = len(nodelist)
    assert len(dest) < 128 and len(dest) > 0
    assert p.k + 1 + len(dest) + len(msg) < p.m

    # Compute the header and the secrets
    header, secrets = create_header(params, nodelist, pki, Dspec, b"\x00" * p.k)

    body = pad_body(p.m, (b"\x00" * p.k) + Denc(dest) + msg)

    # Compute the delta values
    delta = p.pi(p.hpi(secrets[nu-1]), body)
    for i in range(nu-2, -1, -1):
        delta = p.pi(p.hpi(secrets[i]), delta)

    return header, delta

def create_surb(params, nodelist, pki, dest):
    p = params
    # pki = p.pki
    nu = len(nodelist)
    id = urandom(p.k)

    # Compute the header and the secrets
    header, secrets = create_header(params, nodelist, pki, Denc(dest), id)

    ktilde = urandom(p.k)
    keytuple = [ktilde]
    keytuple.extend(map(p.hpi, secrets))
    return id, keytuple, (nodelist[0], header, ktilde)


class SphinxClient:
    def __init__(self, params, pki, nymserver):
        self.id = b"Client " + urandom(4) # .encode("hex")
        self.params = params
        # params.clients[self.id] = self
        self.keytable = {}
        self.pki = pki
        self.nymserver = nymserver

    def create_nym(self, nym, nllength):
        """Create a SURB for the given nym (passing through nllength
        nodes), and send it to the nymserver."""

        # Pick the list of nodes to use
        pki = self.pki
        mixnodes = [x for x in pki.keys() if isinstance(pki[x], SphinxTestNode)]
        nodelist = rand_subset(mixnodes, nllength)
        id, keytuple, nymtuple = create_surb(self.params, nodelist, self.pki, self.id)

        self.keytable[id] = keytuple
        self.nymserver.add_surb(nym, nymtuple)

    def process(self, id, delta):
        "Process a (still-encrypted) reply message"
        p = self.params
        keytuple = self.keytable.pop(id, None)
        if keytuple == None:
            print("Unreadable reply message received by [%s]" % self.id)
            return

        ktilde = keytuple.pop(0)
        nu = len(keytuple)
        for i in range(nu-1, -1, -1):
            delta = p.pi(keytuple[i], delta)
        delta = p.pii(ktilde, delta)

        if delta[:p.k] == (b"\x00" * p.k):
            msg = unpad_body(delta[p.k:])
            print("[%s] received by [%s]" % (msg, self.id))
        else:
            print("Corrupted message received by [%s]" % self.id)

def test_FullClient():
    r = 5
    params = SphinxParams(r)
    pki = {}
    nymserver = Nymserver(params, pki)
    
    # Create some nodes
    for i in range(2*r):
        node = SphinxTestNode(params, pki)
        pki[node.id] = node

    # Create a client
    client = SphinxClient(params, pki, nymserver)
    pki[client.id] = client

    # Pick a list of nodes to use
    mixnodes = [x for x in pki.keys() if isinstance(pki[x], SphinxTestNode)]
    use_nodes = rand_subset(mixnodes, r)

    header, delta = create_forward_message(params, use_nodes, pki, b"dest", b"this is a test")

    # Send it to the first node for processing
    pki[use_nodes[0]].process(header, delta)

    # Create a reply block for the client
    client.create_nym(b"cypherpunk", r)

    # Send a message to it
    nymserver.send_to_nym(b"cypherpunk", b"this is a reply")

def test_timing():
    r = 5
    params = SphinxParams(r)
    pki = {}
    nymserver = Nymserver(params, pki)

    # Create some nodes
    for i in range(2*r):
        node = SphinxTestNode(params, pki)
        pki[node.id] = node

    # Create a client
    client = SphinxClient(params, pki, nymserver)
    pki[client.id] = client

    # Pick a list of nodes to use
    mixnodes = [x for x in pki.keys() if isinstance(pki[x], SphinxTestNode)]
    use_nodes = rand_subset(mixnodes, r)

    print()
    
    import time
    t0 = time.time()
    for _ in range(100):
        header, delta = create_forward_message(params, use_nodes, pki, b"dest", b"this is a test")
    t1 = time.time()
    print("Time per mix encoding: %.2fms" % ((t1-t0)*1000.0/100))

    from .SphinxNode import sphinx_process
    import time
    t0 = time.time()
    for _ in range(100):
        x = pki[use_nodes[0]]._x
        sphinx_process(params, x, {}, header, delta)
        # header, delta = create_forward_message(params, use_nodes, "dest", "this is a test")
    t1 = time.time()
    print("Time per mix processing: %.2fms" % ((t1-t0)*1000.0/100))


def test_minimal():
    
    
    from SphinxParams import SphinxParams
    r = 5
    params = SphinxParams(r)

    # The minimal PKI involves names of nodes and keys
    from SphinxNode import Nenc
    
    pki = {}
    for i in range(2*r):
        nid = Nenc(params, bytes([i]))
        x = params.group.gensecret()
        y = params.group.expon(params.group.g, x)
        pki[nid] = pki_entry(nid, x, y)

    # The simplest path selection algorithm and message packaging
    use_nodes = rand_subset(pki.keys(), r)
    dest = b"bob"
    message = b"this is a test"
    header, delta = create_forward_message(params, use_nodes, pki, dest, message)

    # Process message by the sequence of mixes
    from .SphinxNode import sphinx_process
    x = pki[use_nodes[0]].x

    while True:
        seen = {}
        ret = sphinx_process(params, x, seen, header, delta)
        if ret[0] == "Node":
            _, (addr, header, delta) = ret
            x = pki[addr].x 
        elif ret[0] == "Process":
            print(ret[1])
            break
        else:
            print("Error")
            assert False
            break
    

if __name__ == "__main__":
    test_timing() 