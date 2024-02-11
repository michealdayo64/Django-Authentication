from django.shortcuts import render, redirect
from .forms import RegisterForm
from django.contrib.auth import login, logout, authenticate, get_user_model
from .models import Accounts
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.urls import reverse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
# import validate_email
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .tokens import account_activation_token

# Create your views here.


def index_page(request):
    return render(request, 'index.html')

# Redirect Link


def get_redirect_if_exists(request):
    redirect = None
    if request.GET:
        if request.GET.get("next"):
            redirect = str(request.GET.get("next"))
        return redirect


# Activate account
def activate(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except:
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.is_staff = True
        user.save()
        messages.success(
            request, "Thank you for your email confirmation. Now you can login your account.")
        return redirect('login-page')
    else:
        messages.error(request, "Activation link is invalid!")
    return redirect('login-page')


# Send accout to email to activate
def activateEmail(request, user, to_email):
    mail_subject = "Activate your user account."
    email_content = {
        'user': user.username,
        'domain': get_current_site(request).domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': account_activation_token.make_token(user),
        "protocol": 'https' if request.is_secure() else 'http'
    }
    message = render_to_string(
        "account/template_activate_account.html", email_content)
    # email = EmailMessage(mail_subject, settings.EMAIL_FROM, message, to=[to_email])

    # email.send(fail_silently=False)
    print(message)
    messages.success(request, f'Dear <b>{user}</b>, please go to you email <b>{to_email}</b> inbox and click on \
                received activation link to confirm and complete the registration. <b>Note:</b> Check your spam folder.')


# REGISTER FUNCTION
def register_page(request, *args, **kwargs):
    if request.user.is_authenticated:
        return redirect('index')
    context = {}

    if request.method == 'POST':
        firstname = request.POST.get('firstname')
        lastname = request.POST.get('lastname')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = Accounts.objects.create(
            first_name=firstname, last_name=lastname, username=username, email=email)
        user.is_active = False
        user.set_password(password)
        user.save()
        activateEmail(request, user, email)
        destination = kwargs.get("next")
        if destination:
            return redirect(destination)
        return redirect("login-page")
    return render(request, 'account/register.html')


# LOGIN FUNCTION
def login_page(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")
        user = authenticate(email=email, password=password)
        if user:
            if user.is_active:
                if user.is_staff:
                    login(request, user)
                    messages.success(request, "Login Successfully")
                    return redirect("index-page")
                else:
                    messages.success(request, "User not autheenticated")
                    print("User not autheenticated")
                    return redirect("login-page")
            else:
                messages.success(request, "User not authenticated")
                print("User not autheenticated")
                return redirect("login-page")
        else:
            messages.warning(request, "Invalid User")
            print("User not autheenticated")
            return redirect("login-page")
    else:
        messages.warning(request, "No inputed data")
        print("User not autheenticated")
    return render(request, 'account/login.html')


# Logout Function
def logout_function(request):
    if request.user.is_authenticated:
        logout(request)
        return redirect('login-page')


# FORGET PASSWORD FUNTION
def forget_password_page(request):
    context = {}
    if request.method == "POST":
        email = request.POST.get('email')
        context = {
            'values': request.POST
        }
        current_site = get_current_site(request)
        user = Accounts.objects.filter(email=email)
        if user.exists():
            email_content = {
                'user': user[0],
                'doamin': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
                'token': PasswordResetTokenGenerator().make_token(user[0]),
                "protocol": 'https' if request.is_secure() else 'http'
            }
            link = reverse('reset-forgot-password-page', kwargs={
                'uidb64': email_content['uid'], 'token': email_content['token']
            })
            reset_url = f'http://{current_site.domain}{link}'

            message = f"Hi {user[0].username}, Kindly click the link below to reset your password\n {reset_url}"
            print(message)

            messages.success(
                request, f"You copy the link in the console")
            return redirect('login-page')
        else:
            messages.success(
                request, "Account not valid, Kindly provide a valid email account")
            return redirect('forget-password-page')
    return render(request, 'account/forget_password.html', context)


# RESET FORGOT PASSWORD FUNCTION
def reset_forgot_password_page(request, uidb64, token):
    if request.method == "POST":
        new_password = request.POST.get('new_password')
        retype_new_password = request.POST.get('retype_new_password')
        if retype_new_password != new_password:
            messages.info(request, "Password deos not match")
            print('Password not match')
            return render(request, "account/reset_forgot_password.html")
        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            print(user_id)
            user = Accounts.objects.get(pk=user_id)
            if PasswordResetTokenGenerator().check_token(user, token):
                messages.info(
                    request, 'Password link invalid, Pls request for a new one')
                return redirect('forget-password-page')
            else:
                user.set_password(new_password)
                user.save()
                messages.info(request, "Password was set successfully")
                return redirect('login')
            
        except Exception as identifier:
            messages.info(request, 'something went wrong, try again')
            print("something went wrong")
            return render(request, "account/reset_forgot_password.html")
    return render(request, 'account/reset_forgot_password.html')


# RESET PASSWORD
def reset_password(request):
    user = request.user
    if user.is_authenticated:
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        if user.check_password(old_password):
            user_id = Accounts.objects.get(id=user.id)
            user_id.set_password(new_password)
            user_id.save()
            messages.success(request, 'Password reset successfully')
            return redirect("reset-password")
        else:
            messages.info(request, 'Password does not match old password')
            return redirect("reset-password")
    else:
        messages.warning(request, "User is not authenticatedtan")
        redirect("index")
    return render(request, 'account/reset_password.html')
