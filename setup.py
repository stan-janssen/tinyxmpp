from setuptools import setup

setup(name='tinyxmpp',
      version='0.1.0',
      description='A friendly and easy to use XMPP client for Python',
      author='Stan Janssen',
      url='https://github.com/stan-janssen/tinyxmpp',
      packages=['tinyxmpp'],
      install_requires=['lxml', 'tinysasl'])

