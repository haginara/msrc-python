from os import path
from pathlib import Path
from setuptools import setup

long_description = (Path(__file__).parent / "README.md").read_text().strip()
install_requires = [
    "requests"
]

setup(
    name="msrc",
    description="MSRC Search tool",
    version="0.2.0",
    license="MIT License",
    url="https://github.com/haginara/msrc-python",
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Jonghak Choi',
    author_email='haginara@gmail.com',
    install_requires=install_requires,
    entry_points={
        'console_scripts': [
            'msrc=msrc.cli:main',
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
