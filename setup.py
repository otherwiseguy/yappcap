from Cython.Build import cythonize
from distutils.core import setup
import os

if not os.path.exists('definitions.pxi'):
    os.system('make definitions.pxi')

setup(
    ext_modules=cythonize('yappcap.pyx')
)
