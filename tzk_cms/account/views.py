from django.shortcuts import render

# Create your views here.


def register_page(request):
    return render(request, 'account/register.html')
