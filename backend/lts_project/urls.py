from django.urls import path
from lts_app import views 
from . import views

urlpatterns = [

    path('', views.health_check, name='health_check'), 

    path('api/v1/traffic/', views.get_traffic_data, name='get_traffic'),
]