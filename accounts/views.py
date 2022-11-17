import base64
import json

import pyotp
import requests
from accounts.tokens import TokenGen
import jwt
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.core.files.base import File
from django.core.mail import BadHeaderError, EmailMessage, send_mail
from django.db.models import Q, query
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django.utils.encoding import (
    DjangoUnicodeDecodeError,
    force_bytes,
    force_str,
    smart_bytes,
    smart_str,
)  # force_text(obj, encoding='utf-8', errors='strict')
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.views.decorators.cache import never_cache
from django.views.generic import CreateView
from rest_framework import generics, serializers, status, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView


from accounts.models import Administrator, Owner, User
from accounts.permissions import IsAdministrator, IsOwner
from accounts.send_mails import send_activation_mail, send_password_reset_email
from accounts.serializers import (
    AdministratorProfileSerializer,
    GoogleSocialLoginSerializer,
    LoginSerializer,
    OwnersProfileSerializer,
    RegisterSerializer,
    RequestPasswordResetPhoneSerializer,
    ResetPasswordEmailRequestSerializer,
    SetNewPasswordSerializer,
    TokenRequestSerializer,
    UserSerializer,
)


class LoginViewSet(ModelViewSet, TokenObtainPairView):
    """
    Users can login with using their phone number and password
    """

    serializer_class = LoginSerializer
    permission_classes = [AllowAny]
    http_method_names = ["post"]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])
        return Response(serializer.validated_data, status=status.HTTP_200_OK)


class OwnerRegisterViewSet(ModelViewSet, TokenObtainPairView):
    """
    Task Owners can register using their phone number,email,
    full_name, password and user_type
    """

    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]
    http_method_names = [
        "post",
    ]

    def create(self, request, *args, **kwargs):
        context = {
            "request": request,
        }
        serializer = self.get_serializer(data=request.data, context=context)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        refresh = RefreshToken.for_user(user)
        # Check user existance
        if User.objects.filter(phone=request.data["phone"]).exists():
            userObject = User.objects.get(phone=request.data["phone"])
            userObject.counter += 1
            userObject.save()
            keygen = TokenGen()
            key = base64.b32encode(
                keygen.generate_token(
                    userObject.email,
                    userObject.phone,
                    userObject.timestamp,
                ).encode()
            )
            OTP = pyotp.HOTP(key)
            send_otp = OTP.at(userObject.counter)
            # Send OTP to user
            print("OTP:::", send_otp)

        res = {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }
        return Response(
            {
                "user": serializer.data,
                "refresh": res["refresh"],
                "token": res["access"],
            },
            status=status.HTTP_201_CREATED,
        )


class AdminRegistrationViewSet(ModelViewSet):
    serializer_class = RegisterSerializer
    permission_classes = [IsAuthenticated, IsAdministrator]
    http_method_names = [
        "post",
    ]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        user.role = "Administrator"
        user.is_active = False
        user.save()
        Administrator.objects.update_or_create(user=user)
        user_data = serializer.data
        send_activation_mail(user_data, request)

        refresh = RefreshToken.for_user(user)
        res = {"refresh": str(refresh), "access": str(refresh.access_token)}
        return Response(
            {
                "user": serializer.data,
                "refresh": res["refresh"],
                "token": res["access"],
            },
            status=status.HTTP_201_CREATED,
        )


class RefreshViewSet(ModelViewSet, TokenRefreshView):
    """
    Endpoint allows all users to refresh their token,
    by passing the refresh token in order to get a new access token
    """

    permission_classes = (AllowAny,)
    http_method_names = ["post"]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        return Response(serializer.validated_data, status=status.HTTP_200_OK)


# logout
class LogoutViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated]
    http_method_names = ["post"]

    def create(self, request, *args, **kwargs):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(
                {"message": "Successfully logged out"},
                status=status.HTTP_205_RESET_CONTENT,
            )
        except Exception as e:
            return Response(
                {"message": "Logout failed"}, status=status.HTTP_400_BAD_REQUEST
            )


class AccountActivationViewSet(ModelViewSet):
    """
    After registration, users will receive an OTP to activate their account,
    using this endpoint
    """

    serializer_class = TokenRequestSerializer
    permission_classes = [AllowAny]
    http_method_names = ["post"]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            user = User.objects.get(phone=request.data["phone"])
            keygen = TokenGen()
            key = base64.b32encode(
                keygen.generate_token(user.email, user.phone, user.timestamp).encode(),
            )
            OTP = pyotp.HOTP(key)
            if OTP.verify(request.data["token"], user.counter):
                user.is_active = True
                user.save()
                return Response(
                    {"message": "Account activated successfully"},
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"message": "Invalid OTP"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except User.DoesNotExist:
            return Response(
                {"error": "User does not exist"},
                status=status.HTTP_400_BAD_REQUEST,
            )


# Password Reset

# Request Phone for Password Reset
class RequestPasswordResetPhoneNumber(ModelViewSet):
    """
    User can request for password reset using phone number,
    where OTP will be sent to the user.
    """

    serializer_class = RequestPasswordResetPhoneSerializer
    permission_classes = [AllowAny]
    http_method_names = ["post"]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            # Check if user exists
            if User.objects.filter(phone=request.data["phone"]).exists():
                user = User.objects.get(phone=request.data["phone"])
                user.counter += 1
                user.save()
                keygen = TokenGen()
                key = base64.b32encode(
                    keygen.generate_token(
                        user.email,
                        user.phone,
                        user.timestamp,
                    ).encode()
                )
                OTP = pyotp.HOTP(key)
                send_otp = OTP.at(user.counter)
                # Send sms to user with a token
                if user.is_active:
                    # Send sms to user with the otp
                    print("Password Reset OTP: ", send_otp)
                    return Response(
                        {
                            "data": serializer.data,
                            "message": "OTP sent successfully",
                        },
                        status=status.HTTP_200_OK,
                    )
            return Response(
                {"error": "User with this phone number does not exist"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except User.DoesNotExist:
            return Response(
                {"error": "User with this phone number does not exist"},
                status=status.HTTP_400_BAD_REQUEST,
            )


# Password Reset Token Check
class PasswordResetTokenCheckViewSet(ModelViewSet):
    """
    User enters the token sent to their phone number, if the token is valid,
    the user is redirected to the password reset page.
    Return phone and OTP
    """

    serializer_class = TokenRequestSerializer
    permission_classes = [AllowAny]
    http_method_names = ["post"]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            if User.objects.filter(phone=request.data["phone"]).exists():
                user = User.objects.get(phone=request.data["phone"])
                keygen = TokenGen()
                key = base64.b32encode(
                    keygen.generate_token(
                        user.email,
                        user.phone,
                        user.timestamp,
                    ).encode()
                )
                OTP = pyotp.HOTP(key)
                if OTP.verify(request.data["token"], user.counter):
                    return Response(
                        {
                            "otpData": serializer.data,
                            "message": "OTP verified successfully",
                        },
                        status=status.HTTP_200_OK,
                    )
                else:
                    return Response(
                        {"error": "Invalid OTP"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            else:
                return Response(
                    {"error": "User with this phone number does not exist"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except User.DoesNotExist:
            return Response(
                {"error": "User with this phone number does not exist"},
                status=status.HTTP_400_BAD_REQUEST,
            )


# If the above OTP is verified, the user can reset their password


class SetNewPasswordViewSet(ModelViewSet):
    """
    The user can set a new password, if the OTP is verified successfully.
    Return password, password_confirm, phone and the verified token
    """

    serializer_class = SetNewPasswordSerializer
    permission_classes = [AllowAny]
    http_method_names = ["post"]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            if User.objects.filter(phone=request.data["phone"]).exists():
                user = User.objects.get(phone=request.data["phone"])
                keygen = TokenGen()
                key = base64.b32encode(
                    keygen.generate_token(
                        user.email,
                        user.phone,
                        user.timestamp,
                    ).encode()
                )
                OTP = pyotp.HOTP(key)
                if OTP.verify(request.data["token"], user.counter):
                    password = request.data["password"]
                    password_confirm = request.data["password_confirm"]
                    if password and password_confirm and password != password_confirm:
                        raise serializers.ValidationError(
                            {"error": "Passwords do not match"}
                        )
                    else:
                        user.set_password(password)
                        user.save()
                        return Response(
                            {"message": "password reset successful"},
                            status=status.HTTP_200_OK,
                        )
                else:
                    return Response(
                        {"error": "Invalid OTP"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            else:
                return Response(
                    {"error": "User with this phone number does not exist"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except User.DoesNotExist:
            return Response(
                {"error": "User with this phone number does not exist"},
                status=status.HTTP_400_BAD_REQUEST,
            )


# Google Login
# https://www.googleapis.com/auth/userinfo.email
# https://developers.google.com/oauthplayground/
class GoogleSocialLogin(ModelViewSet):
    """
    Google Social Login, Use the url below to test the endpoint;
    https://www.googleapis.com/auth/userinfo.email
    https://developers.google.com/oauthplayground/
    return access_token from the url above
    """

    serializer_class = GoogleSocialLoginSerializer
    permission_classes = [AllowAny]
    http_method_names = ["post"]

    def create(self, request, *args, **kwargs):
        payload = {
            "access_token": request.data.get("token"),
        }
        r = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo", params=payload
        )
        data = json.loads(r.text)
        if "error" in data:
            return Response(
                {"error": "Invalid or expired token"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check user if does not exists
        try:
            user = User.objects.get(email=data["email"])
        except User.DoesNotExist:
            user = User.objects.create(
                email=data["email"],
                full_name="",
                phone=data["id"],
                is_active=True,
            )
            password = User.objects.make_random_password()
            user.set_password(password)
            user.save()
        token = RefreshToken.for_user(user)
        return Response(
            {
                "refresh": str(token),
                "access": str(token.access_token),
            },
            status=status.HTTP_200_OK,
        )


# Profiles


class OwnerProfileAPIView(ModelViewSet):
    """
    Owner Profile API View
    """

    serializer_class = OwnersProfileSerializer
    permission_classes = [IsAuthenticated, IsOwner]
    http_method_names = ["get", "put", "patch"]

    def get_queryset(self):
        user = self.request.user
        queryset = Owner.objects.filter(user=user)
        return queryset

    def retrieve(self, request, pk=None, *args, **kwargs):
        queryset = self.get_queryset()
        queryset = get_object_or_404(queryset, pk=pk)
        serializer = self.get_serializer(queryset)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def update(self, request, pk=None, *args, **kwargs):
        queryset = self.get_queryset()
        queryset = get_object_or_404(queryset, pk=pk)
        serializer = self.get_serializer(
            queryset,
            data=request.data,
            partial=True,
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)


class AdministratorProfileAPIView(ModelViewSet):
    """
    Administrator Profile API View
    """

    serializer_class = AdministratorProfileSerializer
    permission_classes = [IsAuthenticated, IsAdministrator]
    http_method_names = ["get", "put"]

    def get_queryset(self):
        user = self.request.user
        adminQuery = Administrator.objects.filter(Q(user=user))
        return adminQuery

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, many=False)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        userSerializer = UserSerializer(request.user, data=request.data["user"])
        userSerializer.is_valid(raise_exception=True)
        userSerializer.save()
        return Response(serializer.data, status=status.HTTP_202_ACCEPTED)
