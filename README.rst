yappcap 
=======

yappcap is a Pythonic wrapper for the libpcap library. It aims to support as
much of the libpcap API as is practical to implement in Python with complete
documentation and active support.

Installation
------------

    make && sudo make install

or

    sudo python setup.py install

Getting started
---------------
Starting a capture on an interface and saving all packets on port 5060 to a 
save file::

    >>> import yappcap
    >>> p = PcapLive("eth0", timeout=1000)
    >>> p.activate()
    >>> p.filter = "port 5060"
    >>> while True:
    ...     pkt = p.next()

Full documentation at http://otherwiseguy.github.com/yappcap/
