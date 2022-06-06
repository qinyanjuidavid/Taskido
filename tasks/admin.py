from django.contrib import admin
from tasks.models import Task, Category


@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
    pass


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    pass
