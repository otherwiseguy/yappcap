#!/usr/bin/env python

import sys
from yappcap import PcapOffline

if len(sys.argv) < 3:
    print "Usage:", sys.argv[0], "input.pcap output.pcap [ filter ]"
    print "Example:", sys.argv[0], "input.pcap output.pcap src 192.168.1.1 and port 5060"
    sys.exit(1)

p = PcapOffline(sys.argv[1], autosave=sys.argv[2])
p.filter = ' '.join(sys.argv[3:])
p.loop(-1, None)
