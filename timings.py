# Run as: python -OO -m cProfile -s tottime timings.py > prof.txt 

if __name__ == "__main__":
	from sphinxmix.SphinxClient import test_timing
	test_timing()