.. _live:

Live captures
*************
.. automodule:: yappcap
.. autoclass:: PcapLive
    :inherited-members:
    :members:
    :undoc-members:

Capturing traffic
=================
Some libpcap capture properties must be set before a capture is activated, while
others can only be set after activation.

Properties that require an un-activated PcapLive:
    * snaplen
    * promisc
    * timeout
    * autosave
    * rfmon
    * buffer_size

Properties that require an activated PcapLive:
    * blocking
    * datalink
    * fileno
    * filter

Starting a live capture
-----------------------
An example of creating, initializing, and starting a capture::

    >>> from yappcap import PcapLive
    >>> p = PcapLive('eth0')
    >>> p.timeout = 1000
    >>> p.autosave = "/tmp/output.pcap"
    >>> p.activate()

Setting up a filter
-------------------
To filter the packets that are returned, set the filter on an activated
PcapLive object::

    >>> p.filter = "udp port 5060"

Retrieving captured packets
---------------------------
There are several ways to retrieve captured packets. Using iterators::

    >>> for pkt in p:
    ...     print pkt

or manually retrieving the next captured packet::

    >>> pkt = p.next()

.. warning::
    Note that if timeout = 0, the above methods may block for a very long time
    even if packets are being received, as some systems will wait for the
    receive buffer to fill before returning any packets. It is almost always
    advisable to set a timeout or to use non-blocking I/O when using these
    methods.

or using the dispatch() method to execute a callback for each packet::

    >>> def callback(pkt, *args, **kwargs):
    ...     print args, kwargs, pkt
    ...
    >>> p.dispatch(1, callback, 'beautiful', 'plumage', pining='fjords')
    ('beautiful', 'plumage') {'pining': 'fjords'} <Packet recived at 1324264650.400614 with length 1514/1514>
    1

dispatch() returns the number of packets processed.
