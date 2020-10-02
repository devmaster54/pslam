import os
import json
import random

from random import shuffle
from twilio.rest import Client
from random_words import RandomWords

from django.utils import six
from django.db.models import Q
from django.conf import settings
from django.contrib import messages
from django.core.mail import send_mail
from django.template import RequestContext
from django.urls import reverse, reverse_lazy
from django.shortcuts import get_object_or_404
from django.core.exceptions import PermissionDenied
from django.utils.decorators import method_decorator
from django.utils.module_loading import import_string
from django.utils.encoding import force_bytes, force_text
from django.http import JsonResponse, Http404, HttpResponse
from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import redirect, render_to_response, render, HttpResponseRedirect
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.views.decorators.debug import sensitive_post_parameters
from django.contrib.auth.mixins import LoginRequiredMixin, AccessMixin
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.views.generic import TemplateView, View, FormView, UpdateView, DetailView


from apps.authentication.models import User, UserProfile, UserTwoFactor, Passphrase
from apps.authentication.forms import (ResendActivationForm, RegistrationForm, UserProfileForm, 
            TwoFactorStatusForm, PhoneUpdateForm, PhraseCheckForm, ResetPasswordForm)


class AuthVerifiedMixin(AccessMixin):
    """Verify that the current user is authenticated."""

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            if request.user.last_login:
                try:
                    if self.request.user.usertwofactor.two_factor_status:
                        try:
                            if not self.request.session['otp-verified']:
                                messages.add_message(
                                    self.request, messages.WARNING, 'You cannot access this page without verifying otp!')
                                return self.handle_no_permission()
                            else:
                                return super().dispatch(request, *args, **kwargs)
                        except:
                            messages.add_message(
                                self.request, messages.INFO, 'Please verify otp')
                            return redirect('auth:otp')
                    else:
                        return super().dispatch(request, *args, **kwargs)
                except:
                    pass
            else:
                return redirect('auth:mnemonicgen')

        elif request.path == '/' and not request.user.is_authenticated :
            return super().dispatch(request, *args, **kwargs)
        else:
            print("user is not authenticated")
            messages.add_message(self.request, messages.ERROR,
                                 'You cannot access this page without loggin in. Please login or signup!')
            return self.handle_no_permission()

        return super().dispatch(request, *args, **kwargs)


class AuthAdminMixin(AccessMixin):
    def dispatch(self, request, *args, **kwargs):
        if request.user.is_superuser:
            return super().dispatch(request, *args, **kwargs)
        else:
            messages.add_message(self.request, messages.INFO,
                                 'Only Admin can access this page. Please login with admin credentials')
            return redirect('auth:logout')


class RegistrationView(FormView):
    """
    User registration view.

    """
    form_class = RegistrationForm
    success_url = None
    template_name = 'authentication/signup.html'

    def form_valid(self, form):
        new_user = form.save()
        if new_user:
            new_user.is_active = False
            new_user.save()
            token = account_activation_token.make_token(new_user)
            confirm_url = self.request.scheme+"://"+self.request.META['HTTP_HOST'] +\
                reverse('auth:email_confirmation', kwargs={'uidb64': urlsafe_base64_encode(
                    force_bytes(new_user.pk)).decode("utf-8"), 'token': token})
            html_message = "Click the link to verify email address <a href='" + \
                confirm_url+"'>Verify</a>"
            try:
                send_mail('Confrim Registration',
                          '',
                          settings.DEFAULT_FROM_EMAIL,
                          [new_user.email],
                          html_message=html_message,
                          fail_silently=False
                          )
            except:
                pass
            return render_to_response('authentication/success.html')
        else:
            return redirect(reverse('signup'))


class TwoFactorAuthenticationView(LoginRequiredMixin, TemplateView):
    """
    Enabling 2FA.
    This will set a otp-verified in session when user enters the correct otp.
    """
    template_name = "authentication/otp.html"

    def dispatch(self, request, *args, **kwargs):
        if not self.request.user.phone_number and not self.request.method == "POST":
            return render(self.request, "authentication/mobile.html")
        elif self.request.user.phone_number and not self.request.method == "POST":
            pin = self._get_pin()
            self.request.session['otp'] = pin
            print("this is the pin", pin)
            self.send_otp(pin, self.request.user.phone_number)
            return render(self.request, "authentication/otp.html")
        else:
            return self.post(self, request, args, kwargs)

    def post(self, request, *args, **kwargs):
        number = self.request.POST.get('phone_number')
        if number:
            # User.objects.filter(id=self.request.user.id).update(
            #     phone_number=number)
            pin = self._get_pin()
            self.request.session['otp'] = pin
            self.request.session['phone_number'] = number
            print("this is the pin", pin)
            try:
                self.send_otp(pin, number)
            except:
                User.objects.filter(
                    id=self.request.user.id).update(phone_number='')
                return render(self.request, "authentication/mobile.html", {"error": "Please Check the Phone Number"})
            return render(self.request, "authentication/otp.html")
        else:
            if self.request.POST.get('otp') == self.request.session['otp']:
                del self.request.session['otp']
                self.request.session['otp-verified'] = True
                messages.add_message(
                    self.request, messages.SUCCESS, 'OTP Verified!')
                device = self.request.META['HTTP_USER_AGENT']
                ip = self.request.META['REMOTE_ADDR']
                if self.request.session.get('phone_number'):
                    User.objects.filter(id=self.request.user.id).update(
                    phone_number=self.request.session.get('phone_number') )
                # AccessLog.objects.create(
                #     user=self.request.user, device=device, ip=ip)
                return redirect(reverse('welcome'))
            else:
                pin = self._get_pin()
                self.request.session['otp'] = pin
                self.send_otp(pin, self.request.user.phone_number)
                messages.add_message(
                    self.request, messages.INFO, 'OTP send to registered number')
                return render(self.request, "authentication/otp.html")

    def send_otp(self, pin, number):
        client = Client(settings.TWILIO_ACCOUNT_SID,
                        settings.TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            body="Your verification code is %s" % pin,
            to=number,
            from_=settings.TWILIO_FROM_NUMBER,
        )

    def _get_pin(self, length=5):
        """ Return a numeric PIN with length digits """
        return str(random.sample(range(10**(length-1), 10**length), 1)[0])


class AccountActivationTokenGenerator(PasswordResetTokenGenerator):
    """ Overriding default Password reset token generator for email confirmation"""

    def _make_hash_value(self, user, timestamp):
        return (six.text_type(user.pk) + six.text_type(timestamp)) + six.text_type(user.is_active)


account_activation_token = AccountActivationTokenGenerator()


class ConfirmSignUpView(View):
    """ Confirming sign up via link provided in email"""
    template_name = 'authentication/email_verified.html'

    def get(self, request, *args, **kwargs):
        """ Ckecking token and conforming account activation"""
        pk = force_text(urlsafe_base64_decode(kwargs.get('uidb64')))
        token = kwargs.get('token')
        user = get_object_or_404(User, pk=pk)
        if account_activation_token.check_token(user, token):
            user.is_active = True
            user.save()
            temp_obj = UserTwoFactor.objects.create(
                user=user,
                two_factor_status=False,
            )
            temp_obj.save()
            return render(request, self.template_name, {'error': False})
        else:
            return render(request, self.template_name, {'error': True})


class UserProfileFormView(AuthVerifiedMixin, FormView):
    form_class = UserProfileForm
    template_name = 'authentication/userprofile.html'
    success_url = reverse_lazy('coins:home')

    def form_valid(self, form):
        temp_form = form.save(commit=False)
        temp_form.user = self.request.user
        temp_form.save()
        messages.add_message(self.request, messages.SUCCESS,
                             'Success!. Profile Updated')
        return super().form_valid(form)

    def form_invalid(self, form):
        messages.add_message(self.request, messages.ERROR,
                             'Error. Please recheck form')

        return self.render_to_response(self.get_context_data(form=form))


class UserProfileView(AuthVerifiedMixin, DetailView):
    model = UserProfile
    context_object_name = 'userprofile'
    template_name = 'authentication/user_profile_view.html'

    def dispatch(self, request, *args, **kwargs):
        try:
            del self.request.session['otp']
        except:
            pass        
        try:
            if self.request.user.passphrase.word_list:
                pass
        except:
            return redirect('auth:mnemonicgen')
        try:
            self.object = self.request.user.userprofile
        except:
            return redirect('auth:userprofile')

        self.get_object()
        return super(UserProfileView, self).dispatch(request, *args, **kwargs)

    def get_object(self):
        return self.request.user.userprofile

    def redirect_to_mnemonic(self):
        return redirect('auth:mnemonicgen')

    def get_context_data(self, **kwargs):
        context = {}
        context['mnemonic'] = self.request.user.passphrase.word_list

        if self.request.user.phone_number:
            context['ph_no'] = self.request.user.phone_number
            return super().get_context_data(**context)
        else:
            context['ph_no'] = False
            context['ph_no_form'] = PhoneUpdateForm()
            return super().get_context_data(**context)
        try:
            if self.request.user.usertwofactor.two_factor_status:
                context['2stepvalue'] = True
                return super().get_context_data(**context)
            else:
                context['2stepvalue'] = False
                return super().get_context_data(**context)

        except:
            context['2stepvalue'] = False
            return super().get_context_data(**context)


class Mnemonicgenerator(TemplateView):
    template_name = 'passphrase.html'

    def __init__(self, **kwargs):
        try:
            del self.request.session['sessionwords']
        except:
            pass

    def dispatch(self, request, *args, **kwargs):
        try:
            if self.request.user.passphrase:
                return redirect('auth:welcome')
        except:
            return super(Mnemonicgenerator, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = {}
        context['mnemonic'] = self.get_wordlist()
        x = [(i+1) for i in range(8)]
        shuffle(x)
        print(x)
        context['rand_list'] = x[:4]
        try:
            del self.request.session['sessionwords']
        except:
            pass
        self.request.session['sessionwords'] = context['mnemonic']
        return context

    def post(self, request, *args, **kwargs):
        temp_list = self.request.session['sessionwords']
        print(temp_list)
        for i in '1234':
            word = self.request.POST.get('word'+i)
            num = self.request.POST.get('num'+i)
            if temp_list[num] == word:
                print("it actually worked")
            else:
                return JsonResponse({'status': 'fail'})
        user_passphrase = Passphrase.objects.create(
            user=self.request.user,
            word_list=temp_list,
            viewed=True
        )

        return JsonResponse({'status': "success"})

    def get_wordlist(self):
        rw = RandomWords()
        mnemonic_seed = rw.random_words(count=8)
        word_list = {}
        count = 1
        for word in mnemonic_seed:
            word_list[count] = word
            count += 1
        print(word_list)
        return word_list


class VerifyPhone(AuthVerifiedMixin, View):

    def post(self, request, *args, **kwargs):
        try:
            if self.request.session['otp']:
                if self.request.POST.get('otp') == self.request.session['otp']:
                    try:
                        del self.request.session['otp']
                    except:
                        pass
                    ph_no = self.request.session['temp_ph_no']
                    temp_obj = User.objects.get(username=self.request.user)
                    temp_obj.phone_number = ph_no
                    temp_obj.save()
                    return JsonResponse({'status': "success"})
                else:
                    del self.request.session['otp']
                    return JsonResponse({'status': "false"}, status=500)

        except:
            try:
                del self.request.session['otp']
            except:
                pass
            ph_no = self.request.POST.get('phone_number')
            pin = self._get_pin()
            self.request.session['otp'] = pin
            self.request.session['temp_ph_no'] = ph_no
            print("this is the pin", pin)
            try:
                self.send_otp(pin, ph_no)
                return JsonResponse({'status': "Please enter the OTP"})
            except:
                User.objects.filter(
                    id=self.request.user.id).update(phone_number='')
                return JsonResponse({'status': "false"}, status=500)

        return JsonResponse({'status': "success"})

    def send_otp(self, pin, number):
        client = Client(settings.TWILIO_ACCOUNT_SID,
                        settings.TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            body="Your verification code is %s" % pin,
            to=number,
            from_=settings.TWILIO_FROM_NUMBER,
        )

    def _get_pin(self, length=5):
        """ Return a numeric PIN with length digits """
        return str(random.sample(range(10**(length-1), 10**length), 1)[0])


class ResendOTP(View):

    def get(self, request, *args, **kwargs):
        try:
            number = self.request.session['temp_ph_no']
        except:
            number = self.request.user.phone_number
        pin = self._get_pin()
        try:
            del self.request.session['otp']
        except:
            pass
        print("this is the pin :" + pin)
        self.request.session['otp'] = pin
        self.send_otp(pin, number)
        return JsonResponse({'status': 'success'})

    def send_otp(self, pin, number):
        client = Client(settings.TWILIO_ACCOUNT_SID,
                        settings.TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            body="Your verification code is %s" % pin,
            to=number,
            from_=settings.TWILIO_FROM_NUMBER,
        )

    def _get_pin(self, length=5):
        """ Return a numeric PIN with length digits """
        return str(random.sample(range(10**(length-1), 10**length), 1)[0])


class UserProfileUpdate(AuthVerifiedMixin, UpdateView):
    model = UserProfile
    fields = ('address_line_1', 'address_line_2', 'address_line_3',
              'city', 'state', 'country', 'pincode')

    template_name = 'authentication/userprofile.html'
    success_url = reverse_lazy('auth:userprofileview')

    def get_object(self):
        return self.request.user.userprofile


class PasswordResetView(TemplateView):
    template_name = 'authentication/password_reset.html'

    def post(self, request, *args, **kwargs):
        in_email = self.request.POST.get('email')
        try:
            temp_user = User.objects.get(email=in_email)
            try:
                del self.request.session['reset_email']
            except:
                pass
            self.request.session['reset_email'] = in_email
            return JsonResponse({"success": True, "message": "success"})
        except:
            return JsonResponse({"success": False, "error": "No user matching email exists!. Please check email again or create a new account."})


class PasswordResetConfirmView(FormView):
    template_name = 'authentication/password_reset_confirm.html'
    form_class = PhraseCheckForm
    success_url = reverse_lazy('auth:password_reset_form')

    def get_context_data(self, **kwargs):
        context = {}
        x = [(i+1) for i in range(8)]
        shuffle(x)
        context['foo'] = zip(x[:4], PhraseCheckForm())
        return context

    def form_valid(self, form):
        
        try:
            temp_email = self.request.session['reset_email']
        except:
            return JsonResponse({"success": False, "error": "No user matching email exists!. Please check email again or create a new account."})
        try:
            temp_user = User.objects.get(email=temp_email)
        except Exception as e:
            return JsonResponse({"success": False, "error": "No user matching email exists!. Please check email again or create a new account."})

        temp_list = eval(temp_user.passphrase.word_list)
        for i in '1234':
            word = self.request.POST.get('word'+i)
            num = self.request.POST.get('num'+i)
            print(word + " - "+ num)
            if temp_list[num] == word:
                print(temp_list[num] +" == "+word)
            else: 
                messages.add_message(
                                    self.request, messages.WARNING, 'Phrases do not match. Please try again')
                               
                return super().form_invalid(form)
        return super().form_valid(form)

    def form_invalid(self, form):
        
        return super().form_invalid(form)

class PasswordResetFormView(FormView):
    template_name = 'authentication/password_reset_form.html'
    form_class = ResetPasswordForm
    success_url = reverse_lazy('auth:login')

    def form_valid(self, form):
        
        try:
            temp_email = self.request.session['reset_email']
        except:
            return JsonResponse({"success": False, "error": "No user matching email exists!. Please check email again or create a new account."})
        try:
            temp_user = User.objects.get(email=temp_email)
        except Exception as e:
            return JsonResponse({"success": False, "error": "No user matching email exists!. Please check email again or create a new account."})
        
        password = form.cleaned_data['new_password2']
        temp_user.set_password(password)
        temp_user.save()
        return super().form_valid(form)
        

    def form_invalid(self, form):
        messages.add_message(self.request, messages.ERROR, 'Passwords doesn\'t meet requirements. Please try again')
        return super().form_invalid(form)

class WelcomeView(AuthVerifiedMixin, TemplateView):
    template_name = 'welcome.html'

    def dispatch(self, request, *args, **kwargs):
        try:
            if not self.request.user.usertwofactor.two_factor_status or self.request.session.get('otp-verified'):
                pass
            else:
                return redirect('auth:otp')
        except:
            return redirect('auth:otp')        
        try:
            if self.request.user.passphrase.word_list:
                pass
        except:
            return redirect('auth:mnemonicgen')
        try:
            self.object = self.request.user.userprofile
        except:
            return redirect('auth:userprofile')
        return super(WelcomeView, self).dispatch(request, *args, **kwargs)



    def get(self, request, *args, **kwargs):
        
        try:
            if self.request.user.usertwofactor.two_factor_status == True:
                try:
                    if self.request.session['otp-verified']:
                        try:
                            if self.request.user.passphrase.viewed:
                                return render(self.request, template_name='welcome.html')
                        except:
                            return redirect('auth:mnemonicgen')
                    else:
                        return redirect('auth:otp')
                except:
                    return redirect('auth:otp')

            else:
                try:
                    if self.request.user.passphrase:
                        if self.request.user.userprofile:
                            return render(request, self.template_name)
                        else:
                            return redirect(reverse('auth:userprofile'))
                    else:
                        return redirect('auth:mnemonicgen')
                except:
                    return redirect('auth:mnemonicgen')

        except:
            try:
                if self.request.user.userprofile:
                    return render(request, self.template_name)
            except:
                return redirect(reverse('auth:userprofile'))


class AboutView(TemplateView):
    template_name = 'aboutus.html'


class TwoFactorToggleview(AuthVerifiedMixin, View):

    def post(self, request, *args, **kwargs):
        fastatus = self.request.POST.get('two_factor_status')
        boolvalue = None
        if fastatus == 'on':
            boolvalue = True

        elif fastatus == 'On':
            boolvalue = True

        elif fastatus == 'ON':
            boolvalue = True
            pass
        else:
            boolvalue = False
        try:
            if self.request.user.usertwofactor:
                temp_obj = UserTwoFactor.objects.get(user=self.request.user)
                temp_obj.two_factor_status = boolvalue
                temp_obj.save()
                return JsonResponse({'status': "success"})
        except:
            temp_obj = UserTwoFactor.objects.create(
                user=self.request.user,
                two_factor_status=boolvalue
            )
            temp_obj.save()
            return JsonResponse({'status': "fail"})


class Update(View):
    def get(self, *args, **kwargs):
        try:
            os.system("bash ../update")
            return HttpResponse("Success")
        except:
            return HttpResponse("Error")


class ToggleAccess(View):
    def get(self, request, *args, **kwargs):
        username = kwargs.get('slug')
        temp_user = User.objects.get(username=username)
        if temp_user.is_active == True:
            temp_user.is_active = False
        else:
            temp_user.is_active = True

        temp_user.save()
        return JsonResponse({'status': "success"})
