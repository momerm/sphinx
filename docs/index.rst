.. sphinxmix documentation master file, created by
   sphinx-quickstart on Sun Nov 13 20:36:25 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

The sphinxmix package documentation
===================================

Introduction
------------

.. automodule:: sphinxmix
   :members:

Development
-----------

The ``pytest`` unit tests and doctests of ``sphinxmix`` may be ran using ``tox`` simply through the command::

	$ tox

To upload a new distribution of ``sphinxmix`` the maintainer simply uses::

	$ python setup.py sdist upload


Core classes and functions
--------------------------

.. autoclass:: sphinxmix.SphinxParams.SphinxParams

.. autoclass:: sphinxmix.SphinxParams.Group_ECC

.. autofunction:: sphinxmix.SphinxClient.pki_entry

.. autofunction:: sphinxmix.SphinxNode.Nenc

.. autofunction:: sphinxmix.SphinxClient.rand_subset
    
.. autofunction:: sphinxmix.SphinxClient.create_forward_message

.. autofunction:: sphinxmix.SphinxNode.sphinx_process

SURB functions
--------------

.. autofunction:: sphinxmix.SphinxClient.create_surb

.. autofunction:: sphinxmix.SphinxClient.package_surb

.. autofunction:: sphinxmix.SphinxClient.receive_surb


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

