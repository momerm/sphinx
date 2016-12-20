# -*- coding: utf-8 -*-
"""The ``sphinxmix`` package implements the Sphinx mix packet format core cryptographic functions.

The paper describing sphinx may be found here:

    * George Danezis and Ian Goldberg. Sphinx: A Compact and Provably Secure Mix Format. IEEE Symposium on Security and Privacy 2009. [`link <http://www.cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf>`_]


All the ``sphinxmix`` cryptography is encapsulated and within a ``SphinxParams`` object that 
is used by all subsequent functions. To make ``sphinxmix`` use different cryptographic 
primitives simply extend this class, or re-implement it. The default cryptographic primitives 
are ``NIST/SEGS-p224`` curves, ``AES`` and ``SHA256``.

To package or process sphinx messages create a new ``SphinxParams`` object:

    >>> # Instantiate a the crypto parameters for Sphinx.
    >>> from sphinxmix.SphinxParams import SphinxParams
    >>> params = SphinxParams(r = 5)

The ``sphinxmix`` package requires some rudimentary Public Key Information: mix nodes need
an identifier created by ``Nenc`` and the PKI consists of a dictionary mapping node names
to ``pki_entry`` records. Those include secret keys (derived using ``gensecret``) and public 
keys (derived using ``expon``).

    >>> # The minimal PKI involves names of nodes and keys
    >>> from sphinxmix.SphinxClient import pki_entry, Nenc
    >>> pkiPriv = {}
    >>> pkiPub = {}
    >>> for i in range(10):
    ...     nid = Nenc(params, bytes([i]))
    ...     x = params.group.gensecret()
    ...     y = params.group.expon(params.group.g, x)
    ...     pkiPriv[nid] = pki_entry(nid, x, y)
    ...     pkiPub[nid] = pki_entry(nid, None, y)

A client may package a message using the Sphinx format to relay over a number of mix servers. 
The function ``rand_subset`` may be used to select a random number of node identifiers; the function
``create_forward_message`` can then be used to package the message, ready to be sent to the 
first mix. Note both destination and message need to be ``bytes``.

    >>> # The simplest path selection algorithm and message packaging
    >>> from sphinxmix.SphinxClient import rand_subset, \\
    ...                                    create_forward_message
    >>> use_nodes = rand_subset(pkiPub.keys(), 5)
    >>> keys_nodes = [pkiPub[n].y for n in use_nodes]
    >>> dest = b"bob"
    >>> message = b"this is a test"
    >>> header, delta = create_forward_message(params, use_nodes, \\
    ...     keys_nodes, dest, message)

The heart of a Sphinx mix server is the ``sphinx_process`` function, that takes the server
secret and decodes incoming messages. In this example the message encode above, is decoded
by the sequence of mixes.

    >>> # Process message by the sequence of mixes
    >>> from sphinxmix.SphinxClient import PFdecode
    >>> from sphinxmix.SphinxNode import sphinx_process
    >>> x = pkiPriv[use_nodes[0]].x
    >>> while True:
    ...     seen = {}
    ...     ret = sphinx_process(params, x, header, delta)
    ...     (tag, B, (header, delta)) = ret
    ...     typex, valx, rest = PFdecode(params, B)
    ...     if typex == "node":
    ...         addr = valx
    ...         x = pkiPriv[addr].x 
    ...     elif typex == "Dspec":
    ...         break
    
"""

VERSION = "0.0.2"