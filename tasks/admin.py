from django.contrib import admin
from tasks.models import Task, Category


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ("get_owner_username", "category",
                    "completed")
    list_filter = ["completed"]

    def get_owner_username(self, obj):
        return obj.owner.user.username
    get_owner_username.short_description = "Owner"
    get_owner_username.admin_order_field = "owner__user__username"


@admin.register(Task)
class Taskdmin(admin.ModelAdmin):
    list_display = ("get_owner_username", "category",
                    "completed", "due_date",
                    "important", "created_at")
    list_filter = ("completed", "important")

    def get_owner_username(self, obj):
        return obj.owner.user.username
    get_owner_username.short_description = "Owner"
    get_owner_username.admin_order_field = "owner__user__username"
