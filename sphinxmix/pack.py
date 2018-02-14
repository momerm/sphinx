# Set custom encoder to encode EC points in uncompressed format

from petlib.ec import EcGroup, EcPt, POINT_CONVERSION_UNCOMPRESSED
import msgpack

def default(obj):
    if isinstance(obj, EcPt):
        data = obj.export(POINT_CONVERSION_UNCOMPRESSED)
        return msgpack.ExtType(2, data)
    
    raise TypeError("Unknown type: %r" % (obj,))

def ext_hook(code, data):
    if code == 2:
        return EcPt.from_binary(data, EcGroup(415))
    
    return ExtType(code, data)
        
def encode(structure):
    return msgpack.packb(structure, default=default, use_bin_type=True)

def decode(packed_data):
    return msgpack.unpackb(packed_data, ext_hook=ext_hook, encoding='utf-8')

def test_ecpt():
    G = EcGroup(415)
    test_data = G.generator()
    packed = encode(test_data)
    x = decode(packed)
    assert x == test_data
