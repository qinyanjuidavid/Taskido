from accounts.serializers import OwnersProfileSerializer
from rest_framework import serializers

from tasks.models import Category, Task


class CategorySerializer(serializers.ModelSerializer):
    owner = OwnersProfileSerializer(read_only=True)
    category = serializers.CharField(required=True)
    color = serializers.CharField(required=True)

    class Meta:
        model = Category
        fields = (
            "id",
            "category",
            "color",
            "owner",
            "completed",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id",)


class TaskSerializer(serializers.ModelSerializer):
    owner = OwnersProfileSerializer(read_only=True)
    # category = CategorySerializer(read_only=True)
    due_date = serializers.CharField(required=True)
    task = serializers.CharField(required=True)

    class Meta:
        model = Task
        fields = (
            "id",
            "task",
            "owner",
            "category",
            "note",
            "due_date",
            "important",
            "completed",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("id",)
