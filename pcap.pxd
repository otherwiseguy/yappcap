cdef extern from "sys/time.h":
    cdef struct timeval:
        long tv_sec
        long tv_usec

cdef extern from *:
    ctypedef unsigned char* const_uchar_ptr "const unsigned char *"

cdef extern from "pcap/pcap.h":
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
        PCAP_ERROR                = -1
        PCAP_ERROR_BREAK          = -2
        PCAP_ERROR_NOT_ACTIVATED  = -3
        PCAP_ERROR_ACTIVATED      = -4
        PCAP_ERROR_NO_SUCH_DEVICE = -5
        PCAP_ERROR_RFMON_NOTSUP   = -6
        PCAP_ERROR_NOT_RFMON      = -7
        PCAP_ERROR_PERM_DENIED    = -8
        PCAP_ERROR_IFACE_NOT_UP   = -9

        PCAP_WARNING                = 1
        PCAP_WARNING_PROMISC_NOTSUP = 2

        PCAP_ERRBUF_SIZE = 256

    pcap_t *pcap_create(char *, char *)
    int	pcap_activate(pcap_t *)
    int	pcap_set_snaplen(pcap_t *, int)
    int	pcap_set_promisc(pcap_t *, int)
    int	pcap_can_set_rfmon(pcap_t *)
    int	pcap_set_rfmon(pcap_t *, int)
    int	pcap_set_timeout(pcap_t *, int)
    int	pcap_set_buffer_size(pcap_t *, int)

    void pcap_close(pcap_t *)
    int pcap_fileno(pcap_t *)
    int pcap_setnonblock(pcap_t *, int, char *)
    int pcap_getnonblock(pcap_t *, char *)

    pcap_t *pcap_open_offline(char *, char *)
    bint pcap_is_swapped(pcap_t *)
    int pcap_major_version(pcap_t *)
    int pcap_minor_version(pcap_t *)

    int pcap_snapshot(pcap_t *)
    int pcap_next_ex(pcap_t *, pcap_pkthdr **, const_uchar_ptr *)
    int pcap_dispatch(pcap_t *, int, pcap_handler, const_uchar_ptr)

    pcap_dumper_t *pcap_dump_open(pcap_t *, char *)
    void pcap_dump_close(pcap_dumper_t *)
    void pcap_dump(const_uchar_ptr, pcap_pkthdr *, const_uchar_ptr)
    char *pcap_geterr(pcap_t *)
    char *pcap_lib_version()

cdef struct pcap_callback_ctx:
    void *callback
    void *args
    void *kwargs
