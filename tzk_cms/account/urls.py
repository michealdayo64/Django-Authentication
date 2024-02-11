from django.urls import path
from .views import register_page, login_page, forget_password_page, reset_forgot_password_page, activate, index_page, logout_function, reset_password

urlpatterns = [
    path('register/', register_page, name='register-page'),
    path('login/', login_page, name='login-page'),
    path('logout/', logout_function, name="logout"),
    path('forget-password/', forget_password_page, name='forget-password-page'),
    path('reset-forgot-password/<uidb64>/<token>/', reset_forgot_password_page,
         name='reset-forgot-password-page'),
    path('reset-password/', reset_password, name='reset-password'),
    path('activate/<uidb64>/<token>/', activate, name='activate'),
    path('index/', index_page, name='index-page')
]
