# Run as: python -OO -m cProfile -s tottime timings_ultrix.py > prof.txt 

if __name__ == "__main__":
    from sphinxmix.UltrixClient import profile_ultrix_c25519

    # profile = LineProfiler(profile_ultrix_c25519)
    
    deb = False
    if deb:
        import cProfile, pstats
        pr = cProfile.Profile()
        pr.enable()
    
    profile_ultrix_c25519(rep=1000, payload_size=1024) 

    if deb:
        pr.disable()
        ps = pstats.Stats(pr).strip_dirs().sort_stats('time')
        ps.print_callers()
