==========
Corinthian
==========

.. image:: https://travis-ci.org/rbccps-iisc/corinthian.svg?branch=master
    :target: https://travis-ci.org/rbccps-iisc/corinthian
    
An experimental IoT middleware developed using https://kore.io

Developers: Arun Babu and Poorna Chandra Tejasvi

Quickstart
==========

#. Clone the repository::

    git clone https://github.com/rbccps-iisc/corinthian && cd corinthian
    
#. Install required dependencies (docker and docker-compose)::

    ./tests/require-docker.sh
    
#. Start the installation::

    ./install.docker

#. Test the middleware using::

    ./tests/test --random
