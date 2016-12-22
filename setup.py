from setuptools import setup, find_packages
from setuptools.extension import Extension
from Cython.Build import cythonize, build_ext

import sphinxmix

ext = Extension("sphinxmix.SphinxCrypto", 
                        ["sphinxmix/SphinxCrypto.pyx"],
                          libraries=["crypto"])
                

if __name__ == "__main__":
      
      setup(name='sphinxmix',
            # packages = find_packages(),
            # ext_modules = cythonize("sphinxmix/SphinxCrypto.pyx", libraries = ['crypto']),
            #ext_modules = cythonize([
            #    ),
            extensions = ext,
            version=sphinxmix.VERSION,
            description='A Python implementation of the Sphinx mix packet format.',
            author='George Danezis',
            author_email='g.danezis@ucl.ac.uk',
            url=r'http://sphinxmix.readthedocs.io/en/latest/',
            packages=['sphinxmix'],
            license="2-clause BSD",
            long_description="""A Python implementation of the Sphinx mix packet format.

            For full documentation see: http://sphinxmix.readthedocs.io/en/latest/
            """,

            package_data = {
                  'sphinxmix': ['*.pyx'],
            },

            setup_requires=[
                  'pytest-runner >=2.0,<3dev', 
                  "pytest >= 2.0.0", 
                  "cython > 0.x"
                  ],
            tests_require=[
                  "cython > 0.x",
                  "pytest >= 2.0.0",
                  "future >= 0.14.3",
                  "pytest >= 3.0.0",
                  "msgpack-python >= 0.4.6",
                  "petlib >= 0.0.38",
            ],
            install_requires=[
                  "Cython",
                  "future >= 0.14.3",
                  "pytest >= 3.0.0",
                  "msgpack-python >= 0.4.6",
                  "petlib >= 0.0.38",
            ]
      )