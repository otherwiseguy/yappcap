.. _interfaces:

Dealing with network interfaces
*******************************
.. automodule:: yappcap

Interfaces
==========
.. autoclass:: PcapInterface
   :members:

Listing available interfaces
----------------------------
.. autofunction:: findalldevs

To create a list of available interface names::

    >>> from yappcap import findalldevs
    >>> interfaces = findalldevs()
    >>> [i.name for i in interfaces]
    ['en0', 'fw0', 'en1', 'p2p0', 'lo0']

To retrieve the first available loopback device::

    >>> try:
    ...     lo = [i.name for i in interfaces if i.loopback][0]
    >>> except IndexError:
    ...     print "No looback interfaces on this system!"

Interface addresses
===================
.. autoclass:: PcapAddress
   :members:

To retrieve a list of the string representations of the IPv4 addresses from
the looback address returned above::

    >>> import socket
    >>> [str(x) for x in lo.addresses if x.address and x.address.get('family') == socket.AF_INET]
    ... ['IPv4: 127.0.0.1/255.0.0.0']

