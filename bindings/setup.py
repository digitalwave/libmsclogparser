from distutils.core import setup, Extension

def main():
    setup(name="mscpylogparser",
          version="0.0.1",
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
