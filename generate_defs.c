#include <string.h>
#include <stdio.h>
#include <pcap.h>

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

	return 0;
}

	
