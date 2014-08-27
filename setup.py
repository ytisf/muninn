import os
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "Muninn",
    version = "0.0.3",
    author = "Yuval tisf Nativ",
    author_email = "yuval [at ] morirt *dot* com",
    description = ("A tool that uses Volatility to get basic analysis of a "
                                   "memory image and provide a simple report."),
    license = "GPLv3",
    keywords = "volatility memory analyzer forensics",
    url = "http://ytisf.github.io/Muninn",
    packages=['optparse', 'prettytable'],
    long_description=read('README.md'),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        "License :: GNU :: GPLv3",
    ],
)