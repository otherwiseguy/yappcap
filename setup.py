from distutils.core import setup
from distutils.extension import Extension

setup(
    ext_modules = [
        Extension("yappcap", ["yappcap.c"], libraries=["pcap"])
    ]
)
