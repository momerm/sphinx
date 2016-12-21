from setuptools import setup

import sphinxmix

setup(name='sphinxmix',
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

      setup_requires=["pytest >= 2.6.4"],
      install_requires=[
            "future >= 0.14.3",
            "pytest >= 2.5.0",
            "msgpack-python >= 0.4.6",
            "petlib >= 0.0.38",
      ]
)