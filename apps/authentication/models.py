import datetime
from django.db import models
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.utils.translation import ugettext_lazy as _
from django_unixdatetimefield import UnixDateTimeField
from django.contrib.auth.models import AbstractUser, User


class User(AbstractUser):
    first_name = models.CharField(max_length=200, blank=True, default="")
    last_name = models.CharField(max_length=200, blank=True, default="")
    phone_number = models.CharField(max_length=20, blank=True, default="")
    timestamp = UnixDateTimeField(auto_now=True)

    @property
    def unique_id(self):
        return self.first_name + self.timestamp


class UserProfile(models.Model):
    """User Profile"""
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    country = models.CharField(
        max_length=128, help_text='Country')
    state = models.CharField(
        max_length=128, help_text='State')
    city = models.CharField(
        max_length=128, help_text='City')
    address_line_1 = models.CharField(
        max_length=128, help_text='Home Address')
    address_line_2 = models.CharField(
        max_length=128, help_text='Apartment/Suite number')
    address_line_3 = models.CharField(
        max_length=128, help_text='Locality Name')
    pincode = models.CharField(
        max_length=128, null=False, help_text='Zipcode')

    def __str__(self):
        return self.user.email


class UserTwoFactor(models.Model):
    """ Two factor settings of User"""
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    two_factor_status = models.BooleanField(default=False)

    def __str__(self):
        return self.user.email


class Passphrase(models.Model):
    """ Mnemonic passphrase for resetting password"""
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    word_list = models.CharField(max_length=500, blank=True, null=True)
    viewed = models.BooleanField(default=False)

    def __str__(self):
        return self.user.email
