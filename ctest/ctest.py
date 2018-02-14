# See if the test case in the "test case.json" file can be processed correctly.

from petlib.bn import Bn
from petlib.ec import POINT_CONVERSION_UNCOMPRESSED 
from sphinxmix.SphinxParams import SphinxParams
from sphinxmix.SphinxClient import *
from sphinxmix.SphinxNode import sphinx_process
import json
from builtins import bytes

with open('test case.json', 'r') as f:
    test_case = json.load(f)

privKeys = test_case['keys']
packet = test_case['packet']
packet = bytes(bytearray(packet))

params = SphinxParams()
pki = {}
use_nodes = []

for i, k in enumerate(privKeys):
    nid = "node" + str(i)
    use_nodes.append(nid)
    print(nid)
    
    x = Bn.from_binary(bytes(bytearray(k)))
    y = params.group.expon_base([x])
    print("Public key: " + y.export(POINT_CONVERSION_UNCOMPRESSED).encode("hex") + "\n")
    
    pki[nid] = pki_entry(nid, x, y)

param_dict = { (params.max_len, params.m):params }
px, (header, delta) = unpack_message(param_dict, packet)
assert px == params

print("Processing message by the sequence of mixes.")
x = pki[use_nodes[0]].x
i = 0
while True:
    ret = sphinx_process(params, x, header, delta)
    (tag, B, (header, delta), mac_key) = ret
    routing = PFdecode(params, B)

    print("round %d" % i)
    i += 1
    
    if routing[0] == Relay_flag:
        addr = routing[1]
        x = pki[addr].x 
    elif routing[0] == Dest_flag:
        assert len(routing) == 1
        dec_dest, dec_msg = receive_forward(params, mac_key, delta)
        print("\nMessage has reached its destination.")
        print("To: " + dec_dest)
        print("Message: " + dec_msg)
        break
    else:
        print("Error")
        assert False
        break







    

    
        
        
