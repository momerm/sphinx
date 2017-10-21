# Run as: python -OO -m cProfile -s tottime timings.py > prof.txt 

if __name__ == "__main__":
    from sphinxmix.UltrixClient import test_ultrix_c25519
    test_ultrix_c25519(rep=1000, payload_size=1024 * 10) 