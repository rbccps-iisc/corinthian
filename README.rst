==========
Corinthian
==========

|travis| |codacy| |license|

.. |travis| image:: https://travis-ci.org/rbccps-iisc/corinthian.svg?branch=master
    :target: https://travis-ci.org/rbccps-iisc/corinthian
    
.. |codacy| image:: https://api.codacy.com/project/badge/Grade/d69aaf669bb9416580118d55566dc648
    :target: https://app.codacy.com/project/pct960/corinthian/dashboard

.. |license| image:: https://img.shields.io/badge/license-ISC-blue.svg
    :target: https://en.wikipedia.org/wiki/ISC_license#OpenBSD_license
    
An IUDX compliant IoT middleware for smart cities

Documentation: https://iudx.readthedocs.io

Quickstart
==========

#. Clone the repository::

    git clone https://github.com/rbccps-iisc/corinthian
    cd corinthian
    git submodule init
    git submodule update
    
#. Install the required dependencies (Host OS must be Ubuntu)::

    ./test-suite/require.sh

#. If the host OS is not Ubuntu then install the following dependencies manually

	- docker
	- docker-compose
	
   Also install the following dependencies if the tests need to be run
   
	- requests
	- urllib3
	- pika
    
#. Start the installation::

    ./docker/install

#. Test the middleware using::

    ./test-suite/test fxnl --random

Use-case diagrams
=================

.. image:: https://raw.githubusercontent.com/rbccps-iisc/corinthian/master/DOCS/usecase-diagrams/uc.svg?sanitize=true

Sequence diagrams
=================

- Registration 

.. image:: https://raw.githubusercontent.com/rbccps-iisc/corinthian/master/DOCS/sequence-diagrams/register.svg?sanitize=true

- Share/Follow 

.. image:: https://raw.githubusercontent.com/rbccps-iisc/corinthian/master/DOCS/sequence-diagrams/follow-share-publish-subscribe.svg?sanitize=true

API
===
- /admin/register-owner

.. image:: https://raw.githubusercontent.com/rbccps-iisc/corinthian/master/DOCS/api/register-owner.svg?sanitize=true

- /owner/register-entity

.. image:: https://raw.githubusercontent.com/rbccps-iisc/corinthian/master/DOCS/api/register-entity.svg?sanitize=true

- /entity/publish 

.. image:: https://raw.githubusercontent.com/rbccps-iisc/corinthian/master/DOCS/api/publish.svg?sanitize=true

- /entity/subscribe

.. image:: https://raw.githubusercontent.com/rbccps-iisc/corinthian/master/DOCS/api/subscribe.svg?sanitize=true

- /owner/follow

.. image:: https://raw.githubusercontent.com/rbccps-iisc/corinthian/master/DOCS/api/follow.svg?sanitize=true

- /owner/follow-status

.. image:: https://raw.githubusercontent.com/rbccps-iisc/corinthian/master/DOCS/api/follow-status.svg?sanitize=true
