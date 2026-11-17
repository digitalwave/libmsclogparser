import os
import re
from setuptools import setup, Extension

def version():
    # the version is in src/msclogparser.h only
    here = os.path.dirname(os.path.abspath(__file__))
    header = os.path.join(here, "..", "src", "msclogparser.h")
    if os.path.exists(header):
        with open(header) as f:
            parts = dict(re.findall(r'#define MSCLOGPARSER_(MAJOR|MINOR|PATCH) "(\d+)"', f.read()))
        return "%s.%s.%s" % (parts["MAJOR"], parts["MINOR"], parts["PATCH"])
    # an sdist doesn't contain the header, but its PKG-INFO has the version
    with open(os.path.join(here, "PKG-INFO")) as f:
        return re.search(r"^Version: (\S+)$", f.read(), re.M).group(1)

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
