from django.db.models import fields
from accounts.models import User, Administrator, Owner
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.settings import api_settings
from django.contrib.auth.models import update_last_login
from django.core.exceptions import ObjectDoesNotExist

from django.contrib.auth.tokens import PasswordResetTokenGenerator

from django.utils.encoding import (
    DjangoUnicodeDecodeError,
    force_str,
    smart_bytes,
    smart_str,
)
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework.exceptions import AuthenticationFailed


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            "id",
            "phone",
            "email",
            "full_name",
            "role",
            "timestamp",
        )
        read_only_fields = ("email", "role")
        extra_kwargs = {
            "phone": {"validators": []},
        }


class LoginSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = self.get_token(self.user)
        data["user"] = UserSerializer(self.user).data
        data["refresh"] = str(refresh)
        data["access"] = str(refresh.access_token)
        if api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)
        return data


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=128,
        min_length=4,
        write_only=True,
        style={"input_type": "password"},
        required=True,
    )
    password_confirmation = serializers.CharField(
        max_length=128,
        min_length=4,
        write_only=True,
        style={"input_type": "password confirmation"},
        required=True,
    )
    full_name = serializers.CharField(max_length=255, required=True)
    phone = serializers.CharField(max_length=25, required=True)

    class Meta:
        model = User
        fields = (
            "phone",
            "email",
            "full_name",
            "password",
            "password_confirmation",
        )

    def create(self, validated_data):
        try:
            user = User.objects.get(
                phone=validated_data["phone"],
            )
            raise serializers.ValidationError(
                "User with this phone number already exists."
            )

        except ObjectDoesNotExist:
            password1 = validated_data["password"]
            password2 = validated_data["password_confirmation"]
            if password1 and password2 and password1 == password2:
                user = User.objects.create(
                    phone=validated_data["phone"],
                    email=validated_data["email"],
                    full_name=validated_data["full_name"],
                    role="Owner",
                    is_active=False,
                )
                user.set_password(
                    password1,
                )
                user.save()
            return user


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=155, min_length=2)

    class Meta:
        fields = [
            "email",
        ]

    def validate(self, attrs):
        return attrs


# Activation Token
class TokenRequestSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=20)
    phone = serializers.CharField(max_length=20)

    class Meta:
        fields = ("token", "phone")


# Request Password Reset Phone where otp will be sent
class RequestPasswordResetPhoneSerializer(serializers.Serializer):
    phone = serializers.CharField(max_length=20)

    class Meta:
        fields = ("phone",)


# Password Reset Token

# Set new Password
class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=20, write_only=True)
    password_confirm = serializers.CharField(max_length=20, write_only=True)
    phone = serializers.CharField(max_length=20)
    token = serializers.CharField(max_length=20, write_only=True)

    class Meta:
        fields = (
            "password",
            "password_confirm",
            "phone",
            "token",
        )


class GoogleSocialLoginSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=255, required=True)

    class Meta:
        fields = ("token",)


class OwnersProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = Owner
        fields = (
            "id",
            "user",
            "bio",
            "profile_picture",
        )
        read_only_fields = ("id",)


class AdministratorProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    url = serializers.HyperlinkedRelatedField(
        read_only=True, view_name="api:admin-profile"
    )

    class Meta:
        model = Administrator
        fields = (
            "id",
            "url",
            "user",
            "bio",
            "profile_picture",
        )
        read_only_fields = ("id",)
