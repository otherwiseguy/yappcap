.. _offline:

Offline captures
****************
.. automodule:: yappcap
.. autoclass:: PcapOffline
    :inherited-members:
    :members:
    :undoc-members:

Processing an offline capture
=============================
Processing saved capture files is very similar to processing live captures. The
properties listed above return information about the capture file, and
processing the packets is done with iterators, next(), and dispatch() as in
live captures.

As an example, the following will open a capture file and write only packets
that match port 5060 to the autosave file::

    >>> from yappcap import PcapOffline
    >>> p = PcapOffline('/tmp/input.pcap', autosave='/tmp/output.pcap')
    >>> p.filter = 'port 5060'
    >>> for pkt in p:
    ...     pass
