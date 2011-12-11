from pcap cimport *

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
    (<object>ctx.callback)(pkt, <object>ctx.args)

# Things that work with all pcap_t
cdef class Pcap(object):
    cdef pcap_t *__pcap
    def __init__(self):
        raise TypeError("Instantiate a PcapLive of PcapOffline class")

    def __iter__(self):
        return self

    def __next__(self):
        cdef PcapPacket pkt
        cdef pcap_pkthdr *hdr
        cdef const_uchar_ptr data

        res = pcap_next_ex(self.__pcap, &hdr, &data)
        if res == 0:
            raise PcapTimeout()
        if res == -1:
            raise PcapError(pcap_geterr(self.__pcap))
        elif res == -2:
            raise StopIteration
        elif res == PCAP_ERROR_NOT_ACTIVATED:
            raise PcapErrorNotActivated() # This is undocumented, but happens
        elif res == 1:
            pkt = PcapPacket_factory(hdr, data)
            return pkt
        else:
            raise PcapError("Unknown error")

    def dispatch(self, cnt, callback, *args, **kwargs):
        cdef pcap_callback_ctx ctx
        ctx.callback = <void *>callback
        ctx.args = <void *>args
        ctx.kwargs = <void *>kwargs
        res = pcap_dispatch(self.__pcap, cnt, __pcap_callback_fn, <unsigned char *>&ctx)
        if res >= 0:
            return res
        if res == -1:
            raise PcapError(pcap_geterr(self.__pcap))
        elif res == -2:
            # XXX breakloop called, do something
            return
        elif res == PCAP_ERROR_NOT_ACTIVATED:
            raise PcapErrorNotActivated()
        else:
            raise PcapError("Unknown error")


    def __dealloc__(self):
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
            timeout=0, buffer_size=0):
        cdef char errbuf[PCAP_ERRBUF_SIZE]
        self.__interface = interface # For now, eventually we'll look it up and do PcapInterface
        self.__pcap = pcap_create(self.__interface, errbuf)
        if self.__pcap is NULL:
            raise PcapError(errbuf)

        # Set default values via properties
        self.snaplen = snaplen
        self.promisc = promisc
        self.rfmon = rfmon
        self.timeout = timeout
        self.buffer_size = buffer_size

    property interface:
        def __get__(self):
            return self.__interface

    property snaplen:
        def __get__(self):
            return self.__snaplen
        def __set__(self, snaplen):
            if pcap_set_snaplen(self.__pcap, snaplen) == PCAP_ERROR_ACTIVATED:
                raise PcapErrorActivated()
            self.__snaplen = snaplen

    property promisc:
        def __get__(self):
            return self.__promisc
        def __set__(self, promisc):
            if pcap_set_promisc(self.__pcap, promisc) == PCAP_ERROR_ACTIVATED:
                raise PcapErrorActivated()
            self.__promisc = promisc

    property rfmon:
        def __get__(self):
            return self.__rfmon
        def __set__(self, rfmon):
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

    property timeout:
        def __get__(self):
            return self.__timeout
        def __set__(self, timeout):
            if pcap_set_timeout(self.__pcap, timeout) == PCAP_ERROR_ACTIVATED:
                raise PcapErrorActivated()
            self.__timeout = timeout 

    property buffer_size:
        def __get__(self):
            return self.__buffer_size
        def __set__(self, timeout):
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
            res = pcap_setnonblock(self.__pcap, not blocking, errbuf)
            if res == -1:
                raise PcapError(errbuf)
            elif res == -3:
                raise PcapErrorNotActivated() # Not documented, but happens
            elif res != 0:
                raise PcapError("Unknown error %d" % (res,))

    def activate(self):
        cdef res = pcap_activate(self.__pcap)
        if res == 0:
            # Success
            return
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


# Things that work with pcap_open_offline
cdef class PcapOffline(Pcap):
    cdef __filename
    def __init__(self, filename):
        cdef char errbuf[PCAP_ERRBUF_SIZE]
        self.__filename = filename
        self.__pcap = pcap_open_offline(self.__filename, errbuf)
        if self.__pcap == NULL:
            raise PcapError(errbuf)

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


#cdef PcapPacket PcapPacket_factory(pcap_pkthdr *pkt_header, const_uchar_ptr data):
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
    pass

# Read only cdef factory-created
cdef class PcapAddress:
    pass

cdef class BpfProgram:
    pass

def lib_version():
    """Return the version string from pcap_lib_version()"""
    return pcap_lib_version()

def findalldevs():
    """Return a list of available PcapInterfaces"""
    pass

def lookupdev():
    """Return a single available PcapInterface"""
    pass

def lookupnet(ifname):
    """Return the IPv4 address and netmask of an interface"""
    pass
