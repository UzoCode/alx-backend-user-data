#!/usr/bin/env python3
"""
For Encrypting passwords
"""


import bcrypt


def hash_password(password: str) -> bytes:
    """
    The Salted pass generation
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ is it valid?
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
