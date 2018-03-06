#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
from setuptools import setup, find_packages

setup(
    name='fridump',
    version='0.1.2',
    packages=find_packages(),
    url='https://github.com/Nightbringer21/fridump',
    # license='GPL',
    author='Nightbringer21',
    # author_email='entert@email.here',
    description='Fridump is using the Frida framework to dump accessible memory addresses from any platform supported.',
    entry_points='''
        [console_scripts]
        fridump=fridump:main
    ''',
    keywords=['frida', 'memory', 'dump']
)
