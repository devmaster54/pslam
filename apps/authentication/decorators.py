from functools import wraps

from django.urls import reverse
from django.utils.decorators import available_attrs
from django.shortcuts import redirect, render_to_response, render

def check_otp(function):
    def wrap(request, *args, **kwargs):
        if request.user.is_authenticated() and request.session.get('otp-verified') and\
          self.request.user.two_factor_status:
            return function(request, *args, **kwargs)
        else:
            return redirect(reverse('otp'))
    wrap.__doc__ = function.__doc__
    wrap.__name__ = function.__name__
    return wrap
