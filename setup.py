"""
Flask-htpasswd
---------

Flask extension for providing basic digest authentication and token
authentication via apache htpasswd files.

Links
`````

* `documentation
   <https://github.com/carsongee/flask-htpasswd/blob/master/README.rst>`_
* `development version
  <https://github.com/carsongee/flask-htpasswd/archive/master.tar.gz#egg=flask-htpasswd-dev>`_
"""
from __future__ import absolute_import, unicode_literals
import codecs
from setuptools import setup
from setuptools.command.test import test as TestCommand

with codecs.open('README.rst', encoding='utf-8') as readme:
    README = readme.read()


class Tox(TestCommand):
    """
    Boiler plate test command for running tox with ``python setup.py test``.
    Borrowed from: https://testrun.org/tox/latest/example/basic.html
    """
    # pylint: disable=attribute-defined-outside-init
    user_options = [(
        str('tox-args='),
        str('a'),
        str('Arguments to pass to tox')
    )]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.tox_args = []

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # Import here, cause outside the eggs aren't loaded
        # pylint: disable=import-outside-toplevel
        import tox  # pylint: disable=import-error
        import shlex
        args = self.tox_args
        if args:
            args = shlex.split(self.tox_args)
        tox.cmdline(args=args)


setup(
    name='flask-htpasswd',
    version='0.4.0',
    url='http://github.com/carsongee/flask-htpasswd',
    license='BSD New',
    author='Carson Gee',
    author_email='x@carsongee.com',
    description=('Basic authentication support via '
                 'htpasswd files in flask applications'),
    long_description=README,
    py_modules=['flask_htpasswd'],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    python_requires=">=3.5",
    install_requires=[
        'Flask',
        'passlib>=1.6',
        'itsdangerous',
        'tox',
    ],
    tests_require=['tox'],
    cmdclass={'test': Tox},
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Framework :: Flask',
    ]
)
