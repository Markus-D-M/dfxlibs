from setuptools import setup, find_packages

setup(
    name='dfxlibs',
    version='0.1.0',
    packages=find_packages(),
    url='https://github.com',
    license='Apache 2.0',
    author='Markus D',
    author_email='mar.d@gmx.net',
    description='DFIR libs',
    python_requires=">=3.8",
    entry_points={
        'console_scripts': [
            'dfxlibs = dfxlibs.cli:main'
        ]
    },
    install_requires=[
        'libewf-python',
        'libqcow-python',
        'libvmdk-python',
        'libvhdi-python',
        'pytsk3',
        'python-registry',
        'python-evtx',
        'lxml',
        "XlsxWriter",
        "py-tlsh",
        "python-magic",
        "python-magic-bin;platform_system=='Windows'",
        "libvshadow-python",
        "libscca-python",
        "libbde-python",
        "libevtx-python",
        "pycryptodome",
        "signify",
        "xmltodict",
        "lnkparse3"
    ]
)
