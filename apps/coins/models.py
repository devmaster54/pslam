from django.db import models
from apps.authentication.models import User


class WalletAddress(models.Model):
    address = models.CharField(max_length=500, blank=True, default="")

    def __str__(self):
        return self.address


class MoneroPaymentid(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    username = models.CharField(max_length=50, blank = True, default="")
    paymentid = models.CharField(max_length=500, blank=True, default="")

    def __str__(self):
        return self.user.username+"_"+ self.paymentid


class Wallet(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=20, blank=True, default="")
    addresses = models.ManyToManyField(WalletAddress) 
    private = models.CharField(max_length=500, blank=True, default="")
    public = models.CharField(max_length=500, blank=True, default="")
    words = models.CharField(max_length=500, blank=True, default="")

    def __str__(self):
        return self.name +" "+ self.user.first_name+" "+ self.user.last_name

class Transaction(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.CharField(blank=False, max_length=200)
    balance = models.CharField(blank=True, max_length=20)
    currency = models.CharField(blank=True, max_length=20)
    transaction_id = models.CharField(blank=True, max_length=200)
    transaction_to = models.CharField(blank=True, max_length=200)

    def __str__(self):
        return self.user.username


class VaultTransaction(models.Model):
    user = models.CharField(blank=True, max_length=200)
    amount = models.CharField(blank=False, max_length=200)
    balance = models.CharField(blank=True, max_length=20)
    currency = models.CharField(blank=True, max_length=20)
    transaction_id = models.CharField(blank=True, max_length=200)
    transaction_to = models.CharField(blank=True, max_length=200)
    to_user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return self.to_user.username

class VaultWallet(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    username = models.CharField(blank=False, max_length=200, unique=True)
    name = models.CharField(max_length=20, blank=True, default="")
    addresses = models.ManyToManyField(WalletAddress) 
    private = models.CharField(max_length=500, blank=True, default="")
    public = models.CharField(max_length=500, blank=True, default="")
    words = models.CharField(max_length=500, blank=True, default="")
    created_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.username

class VaultRetrieveRequest(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    username = models.CharField(blank=False, max_length=200, unique=True)
    currency = models.CharField(max_length=20, blank=True, default="")
    amount = models.DecimalField(max_digits=15, decimal_places=8)
    created_date = models.DateTimeField(auto_now_add=True)
    processed_date = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return self.username
