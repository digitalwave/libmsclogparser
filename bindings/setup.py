from setuptools import setup, Extension
import os

module = Extension(
    'mscpylogparser',
    sources=['pybinding.c'],
    libraries=['msclogparser'],
    include_dirs=['../src', '/usr/include', '/usr/local/include'],
    library_dirs=['../src/.libs', '/usr/lib', '/usr/local/lib'],
)

setup(
    ext_modules=[module],
)

