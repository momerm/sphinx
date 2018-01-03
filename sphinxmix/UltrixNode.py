#!/usr/bin/env python

# Copyright 2011 Ian Goldberg
# Copyright 2017 George Danezis (UCL InfoSec Group)
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


from . import SphinxException

# Core Process function -- devoid of any chrome
def ultrix_process(params, secret, header, delta, assoc=b''):
    """ The heart of a Ultrix server, that processes incoming messages.
    It takes a set of parameters, the secret of the server,
    and an incoming message header and body. Optinally some Associated
    data may also be passed in to check their integrity.
        
    """
    p = params
    group = p.group
    alpha, beta, gamma, dest_key = header
    original_beta = beta

    if params.assoc_len != len(assoc):
        raise SphinxException("Associated data length mismatch: expected %s and got %s." % (params.assoc_len, len(assoc)))

    # Check that alpha is in the group
    if not group.in_group(alpha):
        raise SphinxException("Alpha not in Group.")

    # Compute the shared secret
    s = group.expon(alpha, [ secret ])
    aes_s, (header_enc_key, round_mac_key, tag) = p.get_aes_key_all(s)
    assert len(beta) == p.max_len - 32
    
    beta_pad = beta + p.zero_pad
    B = p.xor_rho(header_enc_key, beta_pad)

    length = B[0]
    routing = B[1:1+length]
    rest = B[1+length:]

    b = p.hb(alpha, aes_s)
    alpha = group.expon(alpha, [ b ])
    beta = rest[:(p.max_len - 32)]

    gamma = p.mu(round_mac_key, gamma + original_beta)
    root_K, body_K = p.derive_user_keys(round_mac_key, gamma)

    dest_key = p.small_perm(root_K, dest_key)
    delta = p.xor_rho(body_K, delta)

    ret = (tag, routing, ((alpha, beta, gamma, dest_key), delta), body_K)
    return ret

