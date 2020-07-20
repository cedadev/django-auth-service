""" A setuptools based setup module. """

__author__ = "William Tucker"
__date__ = "2020-02-05"
__copyright__ = "Copyright 2020 United Kingdom Research and Innovation"
__license__ = "BSD - see LICENSE file in top-level directory"


from setuptools import setup, find_packages


with open("README.md") as readme_file:
    LONG_DESCRIPTION = readme_file.read()


setup(
    name="django-auth-service",
    version="0.1.0",
    description="Django application which authenticates and authorizes users.",
    author="William Tucker",
    author_email="william.tucker@stfc.ac.uk",
    url="https://github.com/glamod/django-auth-service",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    include_package_data=True,
    packages=find_packages(),
    install_requires=[
        "Authlib",
        "django",
        "ndg-saml",
        "ndg-httpsclient",
        "pyopenssl",
        "pyyaml",
        "ua-parser",
        "user-agents",
        "requests",
        "crypto-cookie",
    ],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
    zip_safe=False,
)
