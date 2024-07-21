from django.urls import path
from .views import *

urlpatterns = [

    path('',index.as_view()),
    path('register/',RegisterApi.as_view()),
    path('login/',LoginApi.as_view()),
    path("reset-password/",PasswordReset.as_view()),
    path("password-reset/<str:encoded_pk>/<str:token>/",ResetPasswordAPI.as_view(),name="reset-password"),
]
