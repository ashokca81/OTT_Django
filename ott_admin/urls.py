"""
URL configuration for ott_admin project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include   
from django.conf import settings
from django.conf.urls.static import static
from rest_framework.routers import DefaultRouter
from main_accounts.views import CategoryViewSet, LiveStreamViewSet, StateViewSet, DistrictViewSet, ConstituencyViewSet, MandalViewSet, VillageViewSet, RegionalVideoViewSet

router = DefaultRouter()
router.register(r'categories', CategoryViewSet)
router.register(r'live-streams', LiveStreamViewSet)
router.register(r'states', StateViewSet)
router.register(r'districts', DistrictViewSet)
router.register(r'constituencies', ConstituencyViewSet)
router.register(r'mandals', MandalViewSet)
router.register(r'villages', VillageViewSet)
router.register(r'regional-videos', RegionalVideoViewSet)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('main_accounts.urls')),  # Include main_accounts URLs at root
    path('users/', include('users.urls')),
    path('api/', include(router.urls)),
    path('api/payment/', include('users.payment_urls')),  # Add payment URLs under /api/
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)