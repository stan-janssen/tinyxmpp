from setuptools import setup

with open('README.md') as file:
    long_description = file.read()

setup(name='tinyxmpp',
      version='0.1.1',
      description='A friendly and easy to use XMPP client for Python',
      long_description=long_description,
      long_description_content_type='text/markdown',
      author='Stan Janssen',
      url='https://github.com/stan-janssen/tinyxmpp',
      packages=['tinyxmpp'],
      install_requires=['lxml', 'tinysasl'])
