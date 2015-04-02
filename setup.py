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

from setuptools import setup

with open('README.rst') as readme:
    README = readme.read()

with open('test_requirements.txt') as test_reqs:
    TESTS_REQUIRE = test_reqs.readlines(),

setup(
    name='flask-htpasswd',
    version='0.1.1',
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
    install_requires=[
        'Flask',
        'passlib',
        'itsdangerous',
    ],
    tests_require=TESTS_REQUIRE,
    test_suite="nose.collector",
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
