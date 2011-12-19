from distutils.core import setup
from distutils.extension import Extension
import os

if not os.path.exists('definitions.pxi'):
    os.system('make definitions.pxi')

setup(
    ext_modules = [
        Extension('yappcap', ['yappcap.c'], libraries=['pcap'])
    ]
)

