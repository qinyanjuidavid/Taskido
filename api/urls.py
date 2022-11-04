from accounts.views import (
    AccountActivationViewSet,
    AdminRegistrationViewSet,
    AdministratorProfileAPIView,
    GoogleSocialLogin,
    LoginViewSet,
    OwnerProfileAPIView,
    OwnerRegisterViewSet,
    PasswordResetTokenCheck,
    PasswordResetTokenCheckViewSet,
    RefreshViewSet,
    RequestPasswordResetEmail,
    RequestPasswordResetPhoneNumber,
    SetNewPasswordAPIView,
    SetNewPasswordViewSet,
    VerifyEmail,
)
from rest_framework.routers import SimpleRouter
from django.views.generic import TemplateView
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from tasks.views import CategoryAPIView, TaskAPIView


app_name = "api"
routes = SimpleRouter()

# Accounts Routes
routes.register("login", LoginViewSet, basename="login")
routes.register("register", OwnerRegisterViewSet, basename="register")  # Done
routes.register(
    r"admin/sign-up", AdminRegistrationViewSet, basename="admin-register"
)  # Done
routes.register("auth/refresh", RefreshViewSet, basename="authRefresh")
routes.register("activate", AccountActivationViewSet, basename="activate")
routes.register(
    "password-reset",
    RequestPasswordResetPhoneNumber,
    basename="requestPasswordResetPhoneNumber",
)
routes.register(
    "password-reset-token-check",
    PasswordResetTokenCheckViewSet,
    basename="passwordResetTokenCheck",
)
routes.register(
    "password-reset-complete",
    SetNewPasswordViewSet,
    basename="password-reset-complete",
)
# Google Login
routes.register("google/login", GoogleSocialLogin, basename="googleLogin")
routes.register(
    "admin/profile",
    AdministratorProfileAPIView,
    basename="admin-profile",
)
routes.register("owner/profile", OwnerProfileAPIView, basename="owner-profile")
# Tasks Routes
routes.register("category", CategoryAPIView, basename="categories")
routes.register("tasks", TaskAPIView, basename="tasks")

urlpatterns = [
    *routes.urls,
    path("activate/", VerifyEmail, name="email-verify"),
    path(
        "password-reset/<uidb64>/<token>",
        PasswordResetTokenCheck,
        name="password-reset-confirm",
    ),
    path(
        "password-reset-successful/",
        TemplateView.as_view(
            template_name="accounts/password_reset_success.html",
        ),
        name="passwordResetSuccess",
    ),
]
