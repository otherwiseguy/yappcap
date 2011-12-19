#include <string.h>
#include <stdio.h>
#include <pcap.h>
#include <sys/socket.h>
#if defined(__APPLE__) || (defined(__unix__) && !defined(__linux__))
#include <net/if_dl.h>
#endif

int main(int argc, char *argv[])
{
	const char *version = pcap_lib_version();
	char *ver_ptr;
	/* It looks like all pcap versions for both win32 and others have
	 * the actual libpcap version after the last space */
	if ((ver_ptr = strrchr(version, ' '))) {
		ver_ptr++;
	} else {
		return -1;
	}
	printf("DEF PCAP_V0 = %d\n", ver_ptr[0] != '0' ? 0 : 1);
#if defined(AF_LINK)
	printf("DEF HAVE_AF_LINK = 1\n");
#else
	printf("DEF HAVE_AF_LINK = 0\n");
#endif
#if defined(AF_PACKET)
	printf("DEF HAVE_AF_PACKET = 1\n");
#else
	printf("DEF HAVE_AF_PACKET = 0\n");
#endif

	return 0;
}

	
