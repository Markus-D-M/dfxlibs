from setuptools import setup

setup(
    name='dfxlibs',
    version='0.0.1',
    packages=['dfxlibs'],
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
        'pytsk3',
        'python-registry',
        'python-evtx',
        'lxml',
        "XlsxWriter",
        "py-tlsh",
        "python-magic",
        "python-magic-bin;platform_system=='Windows'"
    ]
)
