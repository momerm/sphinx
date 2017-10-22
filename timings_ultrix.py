# Run as: python -OO -m cProfile -s tottime timings.py > prof.txt 

if __name__ == "__main__":
    from sphinxmix.UltrixClient import profile_ultrix_c25519
    profile_ultrix_c25519(rep=10000, payload_size=1024) 