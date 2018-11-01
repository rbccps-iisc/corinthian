==========
Corinthian
==========

.. image:: https://travis-ci.org/rbccps-iisc/corinthian.svg?branch=master
    :target: https://travis-ci.org/rbccps-iisc/corinthian
    
An IoT middleware developed using https://kore.io

Developers: Arun Babu and Poorna Chandra Tejasvi

Quickstart
==========

#. Clone the repository::

    git clone https://github.com/rbccps-iisc/corinthian && cd corinthian
    
#. Install required dependencies (If you are running Ubuntu)::

    ./tests/require-docker.sh

#. If the host machine is not Ubuntu then install the following dependencies manually
	#. docker
	#. docker-compose
	#. python
	#. python-pip
	
   If you want to run the test script then also install the following python libraries
	#. requests
	#. urllib3
    
#. Start the installation::

    cd docker
    ./install

#. Test the middleware using::

    ./tests/test fxnl --random
