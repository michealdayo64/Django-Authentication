from django.shortcuts import render, redirect
from .forms import RegisterForm
from django.contrib.auth import login, logout, authenticate
from .models import Accounts
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
#from .utils import account_activation_token
from django.contrib import messages
from django.contrib.auth.decorators import login_required
# import threading
# import validate_email
from django.contrib.auth.tokens import PasswordResetTokenGenerator

# Create your views here.



# REGISTER FUNCTION
def register_page(request):
    if request.user.is_authenticated:
        print("Your are already Logged In")
    context = {}

    if request.POST:

        form = RegisterForm(request.POST or None)

        if form.is_valid():
            form.save()
            # print(user_form)
            email = form.cleaned_data['email']
            password = form.cleaned_data['password1']
            user = authenticate(email=email, password=password)
            # print(user)
            if user:
                if user.is_active:
                    login(request, user)
                    return redirect("index")
                else:
                    print("User not active")
            else:
                print("Invalid User")
        else:
            print(form.errors.as_data())
            context["reg_form"] = form
    else:
        print("Http request not valid")
    return render(request, 'account/register.html')

# LOGIN FUNCTION
def login_page(request):
    return render(request, 'account/login.html')

# FORGET PASSWORD FUNTION
def forget_password_page(request):
    return render(request, 'account/forget_password.html')

#RESET PASSWORD FUNCTION
def reset_password_page(request):
    return render(request, 'account/reset_password.html')
