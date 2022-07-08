from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include
from rest_framework.documentation import include_docs_urls
from rest_framework import permissions  # new
from drf_yasg.views import get_schema_view  # new
from drf_yasg import openapi

API_TITLE = "Taskido API"
API_DESCRIPTION = "Todo Application API"

schema_view = get_schema_view(
    openapi.Info(
        title="Taskido API",
        default_version="v1",
        description="A simple to-do list API",
        terms_of_service="https://coderpass.herokuapp.com",
        contact=openapi.Contact(email="davidkinyanjui052@gmail.com"),
        license=openapi.License(name="DayCodes License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)
urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/v1/', include('api.urls')),
    path("api/v1/docs/", include_docs_urls(title=API_TITLE,
                                           description=API_DESCRIPTION)),
    path('', schema_view.with_ui(
        'swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui(
        'redoc', cache_timeout=0), name='schema-redoc'),
]

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
