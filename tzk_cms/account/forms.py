from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import Accounts
from django.contrib.auth import authenticate


"""
Registration Form to sign up users
"""
class RegisterForm(UserCreationForm):
    email = forms.EmailField(max_length = 255, help_text = "Required. Add a valid email addrress")
    
    class Meta:
        model = Accounts
        fields = ('first_name', 'last_name' ,'email', 'username', 'password', )

    
    def clean_username(self):
        username = self.cleaned_data["username"]
        try:
            Accounts.objects.get(username = username)
        except Exception as e:
            return username
        raise forms.ValidationError(f"This username {username} already in use")
    
    def clean_email(self):
        email = self.cleaned_data["email"]
        try:
            Accounts.objects.get(email = email)
        except Exception as e:
            return email
        raise forms.ValidationError(f"This username {email} already in use")