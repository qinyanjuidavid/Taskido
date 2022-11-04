from django.contrib.auth import validators
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.db import models
from django.utils.translation import gettext as _
from django_countries.fields import CountryField
from phonenumber_field.modelfields import PhoneNumberField
from django.core.validators import (
    MaxLengthValidator,
    MaxValueValidator,
    MinLengthValidator,
)

from django.core.mail import send_mail


class TrackingModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
        ordering = ["-created_at"]


class CustomManager(BaseUserManager):
    def create_user(
        self,
        phone,
        email,
        password=None,
        is_active=True,
        is_admin=False,
        is_staff=False,
        role="",
        **extra_fields
    ):
        if phone is None:
            raise ValueError("phone number must be set")
        if email is None:
            raise ValueError("email address must be set")
        if password is None:
            raise ValueError("password must be set")
        user_obj = self.model(
            phone=self.normalize_email(phone),
            email=email,
        )
        user_obj.set_password(password)
        user_obj.is_active = is_active
        user_obj.is_admin = is_admin
        user_obj.is_staff = is_staff
        user_obj.role = role
        user_obj.save(using=self._db)
        return user_obj

    def create_staffuser(self, phone, email, password=None):
        user = self.create_user(
            phone,
            email,
            password=password,
            role="Administrator",
            is_staff=True,
            is_active=True,
            is_admin=False,
        )
        return user

    def create_superuser(self, phone, email, password=None):
        user = self.create_user(
            phone,
            email,
            password=password,
            role="Administrator",
            is_staff=True,
            is_active=True,
            is_admin=True,
        )
        return user


class User(AbstractBaseUser, TrackingModel):
    ROLE_CHOICES = (
        ("Adminisrator", "Adminisrator"),
        ("Owner", "Owner"),
    )
    full_name = models.CharField(
        _("fullname"),
        max_length=100,
        blank=True,
        null=True,
    )
    email = models.EmailField(_("email address"), max_length=255, unique=True)
    phone = PhoneNumberField(
        _("phone number"),
        unique=True,
        blank=True,
        null=True,
    )
    is_staff = models.BooleanField(
        _("staff"),
        default=False,
    )
    is_active = models.BooleanField(_("active"), default=False)
    is_admin = models.BooleanField(_("admin"), default=False)
    role = models.CharField(
        _("role"), max_length=27, choices=ROLE_CHOICES, default="Owner"
    )
    timestamp = models.DateTimeField(_("timestamp"), auto_now_add=True)
    counter = models.IntegerField(
        _("otp counter"), default=0, blank=False
    )  # For HOTP Verification

    objects = CustomManager()
    USERNAME_FIELD = "phone"
    REQUIRED_FIELDS = ["email"]

    def __str__(self):
        return self.email or self.phone

    class Meta:
        verbose_name_plural = _("users")
        ordering = ["-id"]

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    def email_user(self, subject, message, from_email=None, **kwargs):
        """
        Sends an email to this User.
        """
        send_mail(subject, message, from_email, [self.email], **kwargs)

    @property
    def admin(self):
        return self.is_admin

    @property
    def staff(self):
        return self.is_staff

    @property
    def active(self):
        return self.is_active


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, unique=True)
    bio = models.TextField(_("bio"), blank=True, null=True)
    profile_picture = models.ImageField(
        _("profile picture"),
        upload_to="profile_pictures/",
        default="default.png",
    )

    class Meta:
        abstract = True


class Administrator(Profile):
    pass

    def __str__(self):
        return self.user.full_name or self.user.email


class Owner(Profile):
    pass

    def __str__(self):
        return self.user.full_name or self.user.email
