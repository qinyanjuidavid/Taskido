from django.contrib import admin
from tasks.models import Task, Category


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ("get_owner_full_name", "category", "completed")
    list_filter = ["completed"]

    def get_owner_full_name(self, obj):
        return obj.owner.user.full_name

    get_owner_full_name.short_description = "Owner"
    get_owner_full_name.admin_order_field = "owner__user__full_name"


@admin.register(Task)
class Taskdmin(admin.ModelAdmin):
    list_display = (
        "get_owner_full_name",
        "task",
        "category",
        "due_date",
        "created_at",
        "completed",
        "important",
    )
    list_filter = ("completed", "important")

    def get_owner_full_name(self, obj):
        return obj.owner.user.full_name

    get_owner_full_name.short_description = "Owner"
    get_owner_full_name.admin_order_field = "owner__user__full_name"
