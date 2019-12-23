import io
import os
from setuptools import setup

def read(name):
    file_path = os.path.join(os.path.dirname(__file__), name)
    return io.open(file_path, encoding='utf8').read()

setup(
    name='aiodxf',
    version='7.5.3',
    description="Package for accessing a Docker v2 registry",
    long_description=read('README.rst'),
    keywords='docker registry',
    author='FiveAI Ltd.',
    author_email='dave@davedoesdev.com',
    url='https://github.com/fiveai/aiodxf',
    license='MIT',
    packages=['aiodxf'],
    entry_points={'console_scripts': ['aiodxf=aiodxf.main:main']},
    install_requires=['www-authenticate>=0.9.2',
                      'aiohttp==3.6.2',
                      'jwcrypto>=0.4.2',
                      'tqdm>=4.19.4']
)
