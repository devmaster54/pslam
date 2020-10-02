from django import forms
from django.forms import ModelForm
from django.core.exceptions import *
from django.contrib.auth.forms import UserCreationForm
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth import authenticate, get_user_model, password_validation

from .users import UserModel
from .users import UsernameField
from .models import UserProfile, UserTwoFactor
User = UserModel()


class RegistrationForm(UserCreationForm):
    """
    Form for registering a new user account.

    """
    required_css_class = 'required'
    email = forms.EmailField(label=_("E-mail"))

    class Meta:
        model = User
        fields = (UsernameField(), 'email', 'first_name', 'last_name')

    def clean_username(self):
        username = self.cleaned_data.get('username', '').lower()
        if User.objects.filter(**{UsernameField(): username}).exists():
            raise forms.ValidationError(
                _('A user with that username already exists.'))

        return username

    def clean_email(self):
        """
        Validate that the supplied email address is unique for the
        site.

        """
        if User.objects.filter(email__iexact=self.cleaned_data['email']):
            raise forms.ValidationError(
                _("This email address is already in use. Please supply a different email address."))
        return self.cleaned_data['email']


class TwoFactorStatusForm(ModelForm):

    """
    Form for enabling/disabling two factor authentication.

    """
    class Meta:
        model = UserTwoFactor
        fields = ('two_factor_status',)


class PhoneUpdateForm(ModelForm):
    
    """
    Form for updating Mobile Number.

    """
    class Meta:
        model = User
        fields = ('phone_number',)

    # def __init__(self, *args, **kwargs):
    #     super().__init__(*args, **kwargs)
    #     self.fields['phone_number'].help_text = 'Enter your Mobile Number.'



class ResendActivationForm(forms.Form):
    required_css_class = 'required'
    email = forms.EmailField(label=_("E-mail"))


class UserProfileForm(ModelForm):
    class Meta:
        model = UserProfile
        labels = {
            "address_line_1": "Home Address",
            "address_line_2": "Apartment/Suite number",
            "pincode":"zipcode",
        }
        fields = ('address_line_1', 'address_line_2','city', 'state','pincode', 'country' )

class PhraseCheckForm(forms.Form):
    word1 = forms.CharField(max_length=20, required=True)
    word2 = forms.CharField(max_length=20, required=True)
    word3 = forms.CharField(max_length=20, required=True)
    word4 = forms.CharField(max_length=20, required=True)
    
    def clean(self):
        cleaned_data = super(PhraseCheckForm, self).clean()
        word1 = cleaned_data.get('word1')
        word2 = cleaned_data.get('word2')
        word3 = cleaned_data.get('word3')
        word4 = cleaned_data.get('word4')
        if not word1 and not word2 and not word3 and not word4:
            raise forms.ValidationError('You have to write something!')

class ResetPasswordForm(forms.Form):
    """
    A form that lets a user change set their password without entering the old
    password
    """
    error_messages = {
        'password_mismatch': _("The two password fields didn't match."),
    }
    new_password1 = forms.CharField(
        label=_("New password"),
        widget=forms.PasswordInput,
        strip=False
    )
    new_password2 = forms.CharField(
        label=_("New password confirmation"),
        strip=False,
        widget=forms.PasswordInput,
    )


    def clean_new_password2(self):
        password1 = self.cleaned_data.get('new_password1')
        password2 = self.cleaned_data.get('new_password2')
        if password1 and password2:
            if password1 != password2:
                raise forms.ValidationError(
                    self.error_messages['password_mismatch'],
                    code='password_mismatch',
                )
        return password2

