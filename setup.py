from os import path
from setuptools import setup

long_description = open(
    path.join(path.dirname(__file__), 'README.md')
).read().strip() if path.exists('README.md') else ''

_locals = {}
with open("msrc.py") as f:
    for line in f.readlines():
        if line.startswith('__version_'):
            exec(line, None, _locals)

version = _locals['__version__']

install_requires = [
    "requests"
]

setup(
    name="msrc",
    description="MSRC Search tool",
    license="MIT License",
    url="https://github.com/haginara/msrc-python",
    long_description=long_description,
    long_description_content_type='text/markdown',
    version=version,
    author='Jonghak Choi',
    author_email='haginara@gmail.com',
    install_requires=install_requires,
    entry_points={
        'console_scripts': [
            'msrc=msrc:main',
        ]
    },
    py_modules=['msrc'],
    package_data={
        '': ['README.md', ]
    },
    include_package_data=True,
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ]
)
