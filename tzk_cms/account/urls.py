from django.urls import path
from .views import register_page, login_page, forget_password_page, reset_password_page

urlpatterns = [
    path('register/', register_page, name='register-page'),
    path('login/', login_page, name='login-page'),
    path('forget-password/', forget_password_page, name='forget-password-page'),
    path('reset-password/', reset_password_page, name='reset-password-page')
]
