# Make a test case.
# The test case is a json file containing private keys of nodes and a
# sphinx packet routed through those nodes.

from sphinxmix.SphinxParams import SphinxParams
from sphinxmix.SphinxClient import *
import json

r = 5
params = SphinxParams()

nodes_routing = []
node_priv_keys = []
node_pub_keys = []

for i in range(r):
    nid = b"node" + bytes(str(i))
    x = params.group.gensecret()
    y = params.group.expon(params.group.g, [ x ])

    nodes_routing.append(Nenc(nid))
    node_priv_keys.append(x)
    node_pub_keys.append(y)
    
header, delta = create_forward_message(params, nodes_routing, node_pub_keys, b"bob", b"this is a test")
bin_message = pack_message(params, (header, delta))

# Save private keys and binary message to file
testcase = {}
testcase['keys'] = map(lambda x: list(bytearray(x.binary())), node_priv_keys)
testcase['packet'] = list(bytearray(bin_message))

with open('test case.json', 'w') as outfile:
    json.dump(testcase, outfile)
    

    
