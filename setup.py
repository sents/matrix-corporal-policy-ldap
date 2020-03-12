#!/usr/bin/env python3

# -*- coding: utf-8 -*-

from distutils.core import setup

setup(
    name="matrix-corporal-policy-ldap",
    version="0.1",
    description="""A script to generate a matrix-corporal policy from an ldap database""",
    long_description="""This script can generate a policy for matrix-corporal, a matrix
    server reconciliator. The idea is that user informations in a ldap
    database are used to generate a policy document which can be read by matrix-corporal
    to assign users to their ldap groups.
    """,
    classifiers=[
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
    license="GNU AGPLv3",
    install_requires=["ldap3"],
    author="Finn Krein",
    author_email="finn@krein.moe",
    url='https://github.com/sents/matrix-corporal-policy-ldap',
    packages=["matrix_corporal_policy_ldap"],
    entry_points={
        "console_scripts": [
            "corporal-policy-ldap.py = matrix_corporal_policy_ldap.generate_policy:main"
        ]
    },
)
