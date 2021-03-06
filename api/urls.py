from accounts.views import (AdminRegistrationViewSet, AdministratorProfileAPIView, LoginViewSet,
                            OwnerProfileAPIView, PasswordResetTokenCheck,
                            RefreshViewSet, OwnerRegistrationViewSet,
                            RequestPasswordResetEmail, SetNewPasswordAPIView,
                            VerifyEmail)
from rest_framework.routers import SimpleRouter
from django.views.generic import TemplateView
from django.urls import path
from rest_framework_simplejwt.views import (TokenRefreshView)
from tasks.views import CategoryAPIView, TaskAPIView


app_name = "api"
routes = SimpleRouter()

# Accounts Routes
routes.register(r'login', LoginViewSet, basename='login')  # Done
routes.register(r'register', OwnerRegistrationViewSet,
                basename='register')  # Done
routes.register(r'admin/sign-up', AdminRegistrationViewSet,
                basename='admin-register')  # Done
routes.register(r'auth/refresh', RefreshViewSet,
                basename='auth-refresh')  # Done
routes.register('password-reset', RequestPasswordResetEmail,
                basename="requestPasswordReset")  # Done
routes.register('password-reset-complete',  SetNewPasswordAPIView,
                basename="password-reset-complete")
routes.register("admin/profile", AdministratorProfileAPIView,
                basename="admin-profile")
routes.register('owner/profile', OwnerProfileAPIView,
                basename="owner-profile")
# Tasks Routes
routes.register("category", CategoryAPIView, basename="categories")
routes.register("tasks", TaskAPIView, basename="tasks")

urlpatterns = [
    *routes.urls,
    path('activate/', VerifyEmail,
         name="email-verify"),
    path('password-reset/<uidb64>/<token>', PasswordResetTokenCheck,
         name='password-reset-confirm'),
    path('password-reset-successful/',
         TemplateView.as_view(
             template_name="accounts/password_reset_success.html"),
         name="passwordResetSuccess"
         ),
]
