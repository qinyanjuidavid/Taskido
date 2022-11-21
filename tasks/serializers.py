from accounts.models import Owner
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

    def create(self, validated_data):
        owner = Owner.objects.get(user=self.context["request"].user)
        category_query = Category.objects.create(
            category=validated_data["category"],
            owner=owner,
            color=validated_data["color"],
        )
        return category_query

    def update(self, instance, validated_data):
        instance.category = validated_data.get("category", instance.category)
        instance.color = validated_data.get("color", instance.color)
        instance.save()
        return instance


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

    def create(self, validated_data):
        owner = Owner.objects.get(user=self.context["request"].user)
        taskQuery = Task.objects.create(
            task=validated_data["task"],
            owner=owner,
            category=validated_data["category"],
            note=validated_data["note"],
            due_date=validated_data["due_date"],
            important=validated_data["important"],
            completed=validated_data["completed"],
        )
        return taskQuery

    def update(self, instance, validated_data):
        instance.task = validated_data.get("task", instance.task)
        instance.category = validated_data.get("category", instance.category)
        instance.note = validated_data.get("note", instance.note)
        instance.due_date = validated_data.get("due_date", instance.due_date)
        instance.important = validated_data.get(
            "important",
            instance.important,
        )
        instance.completed = validated_data.get(
            "completed",
            instance.completed,
        )
        instance.save()
        return instance
