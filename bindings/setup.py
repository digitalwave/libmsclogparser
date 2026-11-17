import os
import re
from setuptools import setup, Extension

def version():
    # the version is in src/msclogparser.h only
    header = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "msclogparser.h")
    with open(header) as f:
        parts = dict(re.findall(r'#define MSCLOGPARSER_(MAJOR|MINOR|PATCH) "(\d+)"', f.read()))
    return "%s.%s.%s" % (parts["MAJOR"], parts["MINOR"], parts["PATCH"])

def main():
    setup(name="mscpylogparser",
          version=version(),
          description="Python interface for parsing ModSecurity generated error.log lines",
          author="Ervin Hegedus",
          author_email="airween@digitalwave.hu",
          ext_modules=[
            Extension("mscpylogparser",
                sources = ["pybinding.c"],
                library_dirs = ["../src/.libs",],
                libraries = ['msclogparser'],
                extra_compile_args = ["-Wall", "-I../src"],
            )
          ],
        )

if __name__ == "__main__":
    main()
