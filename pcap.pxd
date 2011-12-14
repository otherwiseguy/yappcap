include "definitions.pxi"

cdef extern from "sys/time.h":
    cdef struct timeval:
        long tv_sec
        long tv_usec

cdef extern from "sys/socket.h":
    cdef struct sockaddr:
        unsigned int sa_family
    cdef struct sockaddr_in:
        pass
    cdef struct sockaddr_in6:
        pass
    cdef enum:
        AF_INET
        AF_INET6
        #AF_LINK

cdef extern from "netdb.h":
    cdef enum:
        NI_NUMERICHOST
        NI_MAXHOST

    int getnameinfo(sockaddr *, unsigned int, char *, unsigned int, char *, unsigned int, int)
    char *gai_strerror(int)

cdef extern from *:
    ctypedef unsigned char* const_uchar_ptr "const unsigned char *"

cdef extern from "pcap.h":
    ctypedef struct pcap_t:
        pass
    cdef struct pcap_pkthdr:
        timeval ts
        unsigned int caplen
        unsigned int len
    ctypedef pcap_pkthdr * const_pcap_pkthdr_ptr "const struct pcap_pkthdr *"
    ctypedef struct pcap_dumper_t:
        pass
    ctypedef void (*pcap_handler)(unsigned char *, const_pcap_pkthdr_ptr, const_uchar_ptr)
    ctypedef enum:
        PCAP_ERROR
        PCAP_ERROR_BREAK
        PCAP_ERROR_NOT_ACTIVATED
        PCAP_ERROR_ACTIVATED
        PCAP_ERROR_NO_SUCH_DEVICE
        PCAP_ERROR_RFMON_NOTSUP
        PCAP_ERROR_NOT_RFMON
        PCAP_ERROR_PERM_DENIED
        PCAP_ERROR_IFACE_NOT_UP

        PCAP_WARNING
        PCAP_WARNING_PROMISC_NOTSUP

        PCAP_ERRBUF_SIZE
        PCAP_NETMASK_UNKNOWN
        PCAP_IF_LOOPBACK
    cdef struct bpf_program:
        pass
    ctypedef struct pcap_addr_t:
        pcap_addr_t *next
        sockaddr *addr
        sockaddr *netmask
        sockaddr *broadaddr
        sockaddr *dstaddr
    ctypedef struct pcap_if_t:
        pcap_if_t *next
        char *name
        char *description
        pcap_addr_t *addresses
        int flags

    # Live-capture-only functions
    IF PCAP_V0:
        pcap_t *pcap_open_live(char *, int, int, int, char *)
    ELSE:
        pcap_t *pcap_create(char *, char *)
        int	pcap_activate(pcap_t *)
        int	pcap_set_snaplen(pcap_t *, int)
        int	pcap_set_promisc(pcap_t *, int)
        int	pcap_can_set_rfmon(pcap_t *)
        int	pcap_set_rfmon(pcap_t *, int)
        int	pcap_set_timeout(pcap_t *, int)
        int	pcap_set_buffer_size(pcap_t *, int)
    int pcap_fileno(pcap_t *)
    int pcap_setnonblock(pcap_t *, int, char *)
    int pcap_getnonblock(pcap_t *, char *)

    # Offline-capture-only functions
    pcap_t *pcap_open_offline(char *, char *)
    bint pcap_is_swapped(pcap_t *)
    int pcap_major_version(pcap_t *)
    int pcap_minor_version(pcap_t *)

    # Live and Offline functions
    int pcap_snapshot(pcap_t *)
    int pcap_next_ex(pcap_t *, pcap_pkthdr **, const_uchar_ptr *)
    int pcap_dispatch(pcap_t *, int, pcap_handler, const_uchar_ptr)
    int pcap_compile(pcap_t *, bpf_program *, char *, int, unsigned int)
    int pcap_setfilter(pcap_t *, bpf_program *)
    void pcap_close(pcap_t *)
    char *pcap_geterr(pcap_t *)
    int pcap_datalink(pcap_t *)
    char *pcap_datalink_val_to_name(int)

    # Pcap dump functions
    pcap_dumper_t *pcap_dump_open(pcap_t *, char *)
    void pcap_dump_close(pcap_dumper_t *)
    void pcap_dump(const_uchar_ptr, pcap_pkthdr *, const_uchar_ptr)

    # Top-level library functions
    char *pcap_lib_version()
    int pcap_findalldevs(pcap_if_t **, char *)
    void pcap_freealldevs(pcap_if_t *)

cdef struct pcap_callback_ctx:
    void *callback
    void *args
    void *pcap
    void *kwargs
