from django.contrib import admin

from django.contrib.auth.models import Group
from accounts.models import User, Administrator, Owner


admin.site.unregister(Group)


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    search_fields = ["email", "full_name"]
    list_display = (
        "email",
        "role",
        "phone",
        "is_active",
        "is_admin",
        "is_staff",
        "timestamp",
    )
    list_filter = ("is_active", "is_admin", "is_staff", "role")


@admin.register(Owner)
class OwnerAdmin(admin.ModelAdmin):
    pass


@admin.register(Administrator)
class AdministratorAdmin(admin.ModelAdmin):
    pass
