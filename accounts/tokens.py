import six
from django.contrib.auth.tokens import PasswordResetTokenGenerator
import base64
import pyotp


class TokenGen(object):
    @staticmethod
    def generate_token(email, phone, timestamp):
        return f"{email}{phone}{timestamp}"
