from setuptools import setup, find_packages

VERSION = '0.2.0'

setup(name='fridump',
      version=VERSION,
      description='A universal memory dumper using Frida',
      url='https://github.com/Nightbringer21/fridump',
      license='',
      author='',
      author_email='',
      packages=find_packages(),
      install_requires=['frida'],
      include_package_data=True,
      entry_points={
          'console_scripts': [
              'fridump = fridump.__init__'
          ]
      },
      zip_safe=False
)
