include "definitions.pxi"
from pcap cimport *
from cpython cimport bool

class PcapError(Exception):
    pass

class PcapErrorBreak(Exception):
    pass

class PcapErrorNotActivated(Exception):
    pass

class PcapErrorActivated(Exception):
    pass

class PcapErrorNoSuchDevice(Exception):
    pass

class PcapErrorRfmonNotSup(Exception):
    pass

class PcapErrorNotRfmon(Exception):
    pass

class PcapErrorPermDenied(Exception):
    pass

class PcapErrorIfaceNotUp(Exception):
    pass

class PcapWarning(Exception):
    pass

class PcapWarningPromiscNotSup(Exception):
    pass

class PcapTimeout(Exception):
    pass

cdef void __pcap_callback_fn(unsigned char *user, const_pcap_pkthdr_ptr pkthdr, const_uchar_ptr pktdata):
    cdef pcap_callback_ctx *ctx = <pcap_callback_ctx *>user
    cdef PcapPacket pkt = PcapPacket_factory(pkthdr, pktdata)
    cdef Pcap pcap = <object>ctx.pcap
    (<object>ctx.callback)(pkt, <object>ctx.args)
    if pcap.__dumper:
        pcap.__dumper.dump(pkt)

# Things that work with all pcap_t
cdef class Pcap(object):
    cdef pcap_t *__pcap
    cdef PcapDumper __dumper
    cdef __autosave
    def __init__(self):
        raise TypeError("Instantiate a PcapLive of PcapOffline class")

    def __iter__(self):
        return self

    def __next__(self):
        cdef PcapPacket pkt
        cdef pcap_pkthdr *hdr
        cdef const_uchar_ptr data

        if self.__pcap is NULL:
            raise PcapErrorNotActivated()

        res = pcap_next_ex(self.__pcap, &hdr, &data)
        if res == 0:
            raise PcapTimeout()
        if res == -1:
            raise PcapError(pcap_geterr(self.__pcap))
        if res == -2:
            raise StopIteration
        IF not PCAP_V0:
            if res == PCAP_ERROR_NOT_ACTIVATED:
                raise PcapErrorNotActivated() # This is undocumented, but happens
        if res == 1:
            pkt = PcapPacket_factory(hdr, data)
            if self.__dumper:
                self.__dumper.dump(pkt)
            return pkt
        else:
            raise PcapError("Unknown error")

    def dispatch(self, cnt, callback, *args, **kwargs):
        cdef pcap_callback_ctx ctx

        if self.__pcap is NULL:
            raise PcapErrorNotActivated()

        ctx.callback = <void *>callback
        ctx.args = <void *>args
        ctx.kwargs = <void *>kwargs
        ctx.pcap = <void *>self
        res = pcap_dispatch(self.__pcap, cnt, __pcap_callback_fn, <unsigned char *>&ctx)
        if res >= 0:
            return res
        if res == -1:
            raise PcapError(pcap_geterr(self.__pcap))
        if res == -2:
            # XXX breakloop called, do something
            return
        IF not PCAP_V0:
            if res == PCAP_ERROR_NOT_ACTIVATED:
                raise PcapErrorNotActivated()
        raise PcapError("Unknown error")

    # It sucks that this requires an activated pcap since it means
    # that we will capture non-matching packets between activation
    # and calling setfilter()
    def setfilter(self, filterstring):
        if self.__pcap is NULL:
            raise PcapErrorNotActivated()
        bpf = BpfProgram(self, filterstring)
        res = pcap_setfilter(self.__pcap, &bpf.__bpf)
        if res == -1:
            raise PcapError(pcap_geterr(self.__pcap))
        IF not PCAP_V0:
            if res == PCAP_ERROR_NOT_ACTIVATED:
                raise PcapErrorNotActivated()

    property datalink:
        def __get__(self):
            if self.__pcap is NULL:
                raise PcapErrorNotActivated()
            # libpcap currently returns no error if the pcap isn't
            # isn't yet active.
            return pcap_datalink_val_to_name(pcap_datalink(self.__pcap))

    def __dealloc__(self):
        if self.__pcap:
            pcap_close(self.__pcap)


# Things that work with pcap_open_live/pcap_create
cdef class PcapLive(Pcap):
    cdef __snaplen
    cdef __promisc
    cdef __rfmon
    cdef __timeout
    cdef __buffer_size
    cdef __interface
    def __init__(self, interface, snaplen=65535, promisc=False, rfmon=False,
            timeout=0, buffer_size=0, autosave=None):
        cdef char errbuf[PCAP_ERRBUF_SIZE]
        self.__interface = interface # For now, eventually we'll look it up and do PcapInterface
        if not PCAP_V0:
            self.__pcap = pcap_create(self.__interface, errbuf)
            if self.__pcap is NULL:
                raise PcapError(errbuf)

        # Set default values via properties
        self.snaplen = snaplen
        self.promisc = promisc
        self.timeout = timeout
        self.__autosave = autosave

        IF not PCAP_V0:
            self.rfmon = rfmon
            self.buffer_size = buffer_size

    property interface:
        def __get__(self):
            return self.__interface

    property snaplen:
        def __get__(self):
            return self.__snaplen
        def __set__(self, snaplen):
            IF PCAP_V0:
                if self.__pcap:
                    raise PcapErrorActivated()
            ELSE:
                if pcap_set_snaplen(self.__pcap, snaplen) == PCAP_ERROR_ACTIVATED:
                    raise PcapErrorActivated()
            self.__snaplen = snaplen

    property promisc:
        def __get__(self):
            return self.__promisc
        def __set__(self, promisc):
            IF PCAP_V0:
                if self.__pcap:
                    raise PcapErrorActivated()
            ELSE:
                if pcap_set_promisc(self.__pcap, promisc) == PCAP_ERROR_ACTIVATED:
                    raise PcapErrorActivated()
            self.__promisc = promisc

    property timeout:
        def __get__(self):
            return self.__timeout
        def __set__(self, timeout):
            IF PCAP_V0:
                if self.__pcap:
                    raise PcapErrorActivated()
            ELSE:
                if pcap_set_timeout(self.__pcap, timeout) == PCAP_ERROR_ACTIVATED:
                    raise PcapErrorActivated()
            self.__timeout = timeout 

    property rfmon:
        def __get__(self):
            IF PCAP_V0:
                raise PcapError("%s is too old for this call" % (lib_version(),))
            ELSE:
                return self.__rfmon
        def __set__(self, rfmon):
            IF PCAP_V0:
                raise PcapError("%s is too old for this call" % (lib_version(),))
            ELSE:
                res = pcap_can_set_rfmon(self.__pcap)
                if res == 0:
                    # Could not set rfmon for some non-error reason
                    return
                elif res == PCAP_ERROR_NO_SUCH_DEVICE:
                    raise PcapErrorNoSuchDevice()
                elif res == PCAP_ERROR_ACTIVATED:
                    raise PcapErrorActivated()
                elif res == PCAP_ERROR:
                    raise PcapError(pcap_geterr(self.__pcap))
                elif res == 1:
                    if pcap_set_rfmon(self.__pcap, rfmon) == PCAP_ERROR_ACTIVATED:
                        raise PCAP_ERROR_ACTIVATED
                    self.__rfmon = rfmon 

    property buffer_size:
        def __get__(self):
            IF PCAP_V0:
                raise PcapError("%s is too old for this call" % (lib_version(),))
            ELSE:
                return self.__buffer_size
        def __set__(self, timeout):
            IF PCAP_V0:
                raise PcapError("%s is too old for this call" % (lib_version(),))
            ELSE:
                if pcap_set_buffer_size(self.__pcap, timeout) == PCAP_ERROR_ACTIVATED:
                    raise PcapErrorActivated()

    property fileno:
        def __get__(self):
            res = pcap_fileno(self.__pcap)
            if res == -1:
                # With a live file capture, this should only happen when not activated
                raise PcapErrorNotActivated()
            return res

    # Reverse the logic from checking the negative: nonblock
    property blocking:
        def __get__(self):
            cdef char errbuf[PCAP_ERRBUF_SIZE]

            if self.__pcap is NULL:
                raise PcapErrorNotActivated()

            res = pcap_getnonblock(self.__pcap, errbuf)
            if res == -1:
                raise PcapError(errbuf)
            elif res == 0:
                return True 
            elif res == 1:
                return False
            else:
                return PcapError("Unknown error")

        def __set__(self, blocking):
            cdef char errbuf[PCAP_ERRBUF_SIZE]

            if self.__pcap is NULL:
                raise PcapErrorNotActivated()

            res = pcap_setnonblock(self.__pcap, not blocking, errbuf)
            if res == -1:
                raise PcapError(errbuf)
            IF not PCAP_V0:
                if res == PCAP_ERROR_NOT_ACTIVATED:
                    raise PcapErrorNotActivated() # Not documented, but happens
            if res != 0:
                raise PcapError("Unknown error %d" % (res,))

    def activate(self):
        cdef res
        IF PCAP_V0:
            cdef char errbuf[PCAP_ERRBUF_SIZE]

            if self.__pcap is not NULL:
                raise PcapErrorActivated()

            self.__pcap = self.__pcap = pcap_open_live(self.__interface, self.__snaplen, self.__promisc, self.__timeout, errbuf)
            if self.__pcap is NULL:
                raise PcapError(errbuf)
        ELSE:
            res = pcap_activate(self.__pcap)
            if res == 0:
                # Success
                pass
            elif res == PCAP_WARNING_PROMISC_NOTSUP:
                raise PcapWarningPromiscNotSup(pcap_geterr(self.__pcap))
            elif res == PCAP_WARNING:
                raise PcapWarning(pcap_geterr(self.__pcap))
            elif res == PCAP_ERROR_ACTIVATED:
                raise PcapErrorActivated()
            elif res == PCAP_ERROR_NO_SUCH_DEVICE:
                raise PcapErrorNoSuchDevice(pcap_geterr(self.__pcap))
            elif res == PCAP_ERROR_PERM_DENIED:
                raise PcapErrorPermDenied(pcap_geterr(self.__pcap))
            elif res == PCAP_ERROR_RFMON_NOTSUP:
                raise PcapErrorRfmonNotSup()
            elif res == PCAP_ERROR_IFACE_NOT_UP:
                raise PcapErrorIfaceNotUp()
            elif res == PCAP_ERROR:
                raise PcapError(pcap_geterr(self.__pcap))

        if self.__autosave:
            self.__dumper = PcapDumper(self, self.__autosave)


# Things that work with pcap_open_offline
cdef class PcapOffline(Pcap):
    cdef __filename
    def __init__(self, filename, autosave=None):
        cdef char errbuf[PCAP_ERRBUF_SIZE]
        self.__filename = filename
        self.__autosave = autosave
        self.__pcap = pcap_open_offline(self.__filename, errbuf)
        if self.__pcap == NULL:
            raise PcapError(errbuf)
        if self.__autosave:
            self.__dumper = PcapDumper(self, self.__autosave)

    property filename:
        def __get__(self):
            return self.__filename
    property snaplen:
        def __get__(self):
            return pcap_snapshot(self.__pcap)
    property swapped:
        def __get__(self):
            return pcap_is_swapped(self.__pcap)
    property major_version:
        def __get__(self):
            return pcap_major_version(self.__pcap)
    property minor_version:
        def __get__(self):
            return pcap_minor_version(self.__pcap)

cdef class PcapPacket:
    cdef pcap_pkthdr __pkthdr
    cdef bytes __data
    def __init__(self):
        raise TypeError("This class cannot be instantiated from Python")

    property timestamp:
        def __get__(self):
            return self.__pkthdr.ts.tv_sec + (<double>self.__pkthdr.ts.tv_usec / 1000000)
    property caplen:
        def __get__(self):
            return self.__pkthdr.caplen
    property wirelen:
        def __get__(self):
            return self.__pkthdr.len
    property data:
        def __get__(self):
            return self.__data


cdef PcapPacket PcapPacket_factory(const_pcap_pkthdr_ptr pkt_header, const_uchar_ptr data):
    cdef PcapPacket instance = PcapPacket.__new__(PcapPacket)
    cdef char *cast_data = <char *>data
    instance.__pkthdr = pkt_header[0]
    instance.__data = cast_data[:pkt_header.caplen]
    return instance


cdef class PcapDumper:
    cdef pcap_dumper_t *__dumper

    def __init__(self, Pcap pcap, filename):
        self.__dumper = pcap_dump_open(pcap.__pcap, filename)
        if self.__dumper is NULL:
            raise PcapError(pcap_geterr(pcap.__pcap))

    def dump(self, PcapPacket pkt):
        pcap_dump(<unsigned char *>self.__dumper, <pcap_pkthdr *>&pkt.__pkthdr, <unsigned char *>pkt.data)

    def __dealloc__(self):
        pcap_dump_close(self.__dumper)

# Read only cdef factory-created
cdef class PcapInterface:
    cdef list __addresses
    cdef str __name
    cdef str __description
    cdef bool __loopback
    def __init__(self):
        raise TypeError("Instances of this class cannot be created from Python")
    property name:
        def __get__(self):
            return self.__name
    property description:
        def __get__(self):
            return self.__description
    property loopback:
        def __get__(self):
            return self.__loopback
    property addresses:
        def __get__(self):
            return self.__addresses
    def __str__(self):
        return self.name

cdef PcapInterface PcapInterface_factory(pcap_if_t *interface):
    cdef PcapInterface instance = PcapInterface.__new__(PcapInterface)
    cdef pcap_addr_t *it = interface.addresses
    instance.__addresses = list()
    if interface.name:
        instance.__name = interface.name
    if interface.description:
        instance.__description = interface.description
    if interface.flags & PCAP_IF_LOOPBACK:
        instance.__loopback = True
    else:
        instance.__loopback = False

    while it:
        addr = PcapAddress_factory(it)
        instance.__addresses.append(addr)
        it = it.next
    return instance

cdef str type2str(int t):
    if t == AF_INET:
        return "IPv4"
    elif t == AF_INET6:
        return "IPv6"
    else:
        return str(t)

# Read only cdef factory-created
cdef class PcapAddress:
    cdef dict __addr, __netmask, __broadaddr, __dstaddr
    def __init__(self):
        raise TypeError("Instances of this class cannot be created from Python")
    property address:
        def __get__(self):
            return self.__addr
    property netmask:
        def __get__(self):
            return self.__netmask
    property broadcast:
        def __get__(self):
            return self.__broadaddr
    property dstaddr:
        def __get__(self):
            return self.__dstaddr

    def __str__(self):
        addr = family = nm = None
        if not self.address:
            addr = family = 'Unknown'
        if not self.netmask:
            nm = 'Unknown'

        return "%s: %s/%s" % (family or type2str(self.address['family']), addr or self.address.get('address', 'Unknown'), nm or self.netmask.get('address', 'Unknown'))


cdef get_sock_len(sockaddr *addr):
    if addr.sa_family == AF_INET:
        return sizeof(sockaddr_in)
    elif addr.sa_family == AF_INET6:
        return sizeof(sockaddr_in6)
    else:
        return -1

cdef parse_addr(sockaddr *addr):
    cdef int socklen
    cdef char buf[NI_MAXHOST]

    if not addr:
        return

    socklen = get_sock_len(addr)
    if socklen < 0:
        return {'family': addr.sa_family}
    res = getnameinfo(addr, socklen, buf, sizeof(buf), NULL, 0, NI_NUMERICHOST)
    if res:
        return {'family': addr.sa_family}

    return {'family': addr.sa_family, 'address': buf}

cdef PcapAddress PcapAddress_factory(pcap_addr_t *address):
    cdef PcapAddress instance = PcapAddress.__new__(PcapAddress)
    instance.__addr = parse_addr(address.addr)
    instance.__netmask = parse_addr(address.netmask)
    instance.__broadaddr = parse_addr(address.broadaddr)
    instance.__dstaddr = parse_addr(address.dstaddr)
    return instance

cdef class BpfProgram:
    cdef bpf_program __bpf
    def __init__(self, Pcap pcap, filterstring):
        if pcap.__pcap is NULL:
            raise PcapErrorNotActivated()
        res = pcap_compile(pcap.__pcap, &self.__bpf, filterstring, 1, PCAP_NETMASK_UNKNOWN)
        if res == -1:
            raise PcapError(pcap_geterr(pcap.__pcap))
        IF not PCAP_V0:
            # It should return this, but might not
            if res == PCAP_ERROR_NOT_ACTIVATED:
                raise PcapErrorNotActivated()


def lib_version():
    """Return the version string from pcap_lib_version()"""
    return pcap_lib_version()

def findalldevs():
    """Return a list of available PcapInterfaces"""
    cdef pcap_if_t *interfaces, *it
    cdef char errbuf[PCAP_ERRBUF_SIZE]
    cdef int res = pcap_findalldevs(&interfaces, errbuf)
    cdef list result = list()
    if res < 0:
        raise PcapError(errbuf)
    it = interfaces
    while it:
        i = PcapInterface_factory(it)
        result.append(i)
        it = it.next
    pcap_freealldevs(interfaces)

    return result

#def lookupdev():
#    """Return a single available PcapInterface"""
#    pass
#
#def lookupnet(ifname):
#    """Return the IPv4 address and netmask of an interface"""
#    pass
