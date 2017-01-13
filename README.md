The Sphinxmix python package
============================
[![PyPI](https://img.shields.io/pypi/v/sphinxmix.svg)]()
[![Documentation Status](https://readthedocs.org/projects/sphinxmix/badge/?version=latest)](http://sphinxmix.readthedocs.io/en/latest/?badge=latest)
[![Build Status](https://travis-ci.org/UCL-InfoSec/sphinx.svg?branch=master)](https://travis-ci.org/UCL-InfoSec/sphinx)
[![Coverage Status](https://coveralls.io/repos/github/UCL-InfoSec/sphinx/badge.svg?branch=master)](https://coveralls.io/github/UCL-InfoSec/sphinx?branch=master)

The ``sphinxmix`` package implements the Sphinx mix packet format core cryptographic functions.

The paper describing sphinx may be found here:

George Danezis and Ian Goldberg. Sphinx: A Compact and Provably Secure Mix Format. IEEE Symposium on Security and Privacy 2009. 
http://www.cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf

Beyond the original proposal it allows for clients to communicate additional information to mix servers to implement arbitrary mixing strategies.

More information
----------------

The sphinxmix python package may be installed from pypi using pip: https://pypi.python.org/pypi/sphinxmix/

The documentation for sphinxmix may be found on Read the Docs: http://sphinxmix.readthedocs.io/en/latest/

The Git repository for sphinxmix may be found at the UCL Information Security repository at: https://github.com/UCL-InfoSec/sphinx


Licence
-------

Sphinx v0.8-UCL README
2016-11-12
George Danezis <g.danezis@ucl.ac.uk>

```
# Copyright 2011 Ian Goldberg
# Copyright 2016 George Danezis (UCL InfoSec Group)
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
```

This is a UCL branch and port of the original Sphinx software to using modern python libraries, including petlib for cryptography and msgpack for binary formats. It also decouples the message processing from other concerns to allow sphix to be embedded into other applications. It is based on the original software by Ian Goldberg (U. Waterloo) and retains both his copyright and the original LGPL licence.
