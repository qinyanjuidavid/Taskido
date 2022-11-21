from accounts.models import Owner
from accounts.permissions import IsAdministrator, IsOwner
from django.db.models import Q
from django.shortcuts import render, get_object_or_404
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from rest_framework import generics, serializers, status, viewsets

from tasks.models import Category, Task
from tasks.paginations import StandardResultsSetPagination
from tasks.serializers import CategorySerializer, TaskSerializer


class CategoryAPIView(ModelViewSet):
    serializer_class = CategorySerializer
    permission_classes = [IsAuthenticated, IsOwner]
    http_method_names = ["get", "post", "put", "delete"]

    def get_queryset(self):
        owner = Owner.objects.get(user=self.request.user)
        queryset = Category.objects.filter(
            owner=owner,
        ).order_by("-id")
        query = self.request.query_params.get("q")
        if query:
            queryset = queryset.filter(
                Q(category__icontains=query),
            )
        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        if request.method == "GET":
            if len(queryset) > 0:
                paginator = StandardResultsSetPagination()
                result_page = paginator.paginate_queryset(queryset, request)
                serializer = self.get_serializer(result_page, many=True)
                return paginator.get_paginated_response(serializer.data)
            else:
                return Response(
                    {"message": "No Category found"},
                    status=status.HTTP_200_OK,
                )

    def retrieve(self, request, pk=None, *args, **kwargs):
        queryset = self.get_queryset()
        queryset = get_object_or_404(queryset, pk=pk)
        serializer = self.get_serializer(queryset)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        context = {"request": request}
        serializer = self.get_serializer(data=request.data, context=context)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, pk=None, *args, **kwargs):
        queryset = self.get_queryset()
        queryset = get_object_or_404(queryset, pk=pk)
        serializer = self.get_serializer(queryset, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def destroy(self, request, pk=None, *args, **kwargs):
        queryset = self.get_queryset()
        queryset = get_object_or_404(queryset, pk=pk)
        queryset.delete()
        return Response(
            {"Category was successfully deleted."}, status=status.HTTP_204_NO_CONTENT
        )


class TaskAPIView(ModelViewSet):
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated, IsOwner]
    http_method_names = ["get", "post", "put", "delete"]

    def get_queryset(self):
        owner = Owner.objects.get(user=self.request.user)
        queryset = Task.objects.filter(
            owner=owner,
        ).order_by("-id")
        query = self.request.query_params.get("q")
        if query:
            queryset = queryset.filter(
                Q(task__icontains=query),
            )
        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        if request.method == "GET":
            if len(queryset) > 0:
                paginator = StandardResultsSetPagination()
                result_page = paginator.paginate_queryset(queryset, request)
                serializer = self.get_serializer(result_page, many=True)
                return paginator.get_paginated_response(serializer.data)
            else:
                return Response(
                    {"message": "No Task found"},
                    status=status.HTTP_200_OK,
                )

    def retrieve(self, request, pk=None, *args, **kwargs):
        queryset = self.get_queryset()
        queryset = get_object_or_404(queryset, pk=pk)
        serializer = self.get_serializer(queryset)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        context = {"request": request}
        serializer = self.get_serializer(data=request.data, context=context)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, pk=None, *args, **kwargs):
        queryset = self.get_queryset()
        queryset = get_object_or_404(queryset, pk=pk)
        serializer = self.get_serializer(
            queryset,
            data=request.data,
            partial=True,
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def destroy(self, request, pk=None, *args, **kwargs):
        queryset = self.get_queryset()
        queryset = get_object_or_404(queryset, pk=pk)
        queryset.delete()
        return Response(
            {"Task was successfully deleted."}, status=status.HTTP_204_NO_CONTENT
        )
