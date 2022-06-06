from rest_framework.permissions import (SAFE_METHODS,
                                        BasePermission)


class IsAdministrator(BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            return True

    def has_object_permission(self, request, view, obj):
        if request.user.role == "Administrator":
            return True
        if request.method in SAFE_METHODS:
            return True
        return False


class IsOwner(BasePermission):
    def has_permission(self, request, view):
        if request.user.is_authenticated:
            return True

    def has_object_permission(self, request, view, obj):
        if request.user.role == "Owner":
            return True
        if request.method in SAFE_METHODS:
            return True
        return False
