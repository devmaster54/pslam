from django.contrib import admin
from . models import Wallet, Transaction, VaultWallet, VaultRetrieveRequest, VaultTransaction,WalletAddress, MoneroPaymentid

# Register your models here.

admin.site.register(Wallet)
admin.site.register(Transaction)
admin.site.register(VaultWallet)
admin.site.register(VaultRetrieveRequest)
admin.site.register(VaultTransaction)
admin.site.register(WalletAddress)
admin.site.register(MoneroPaymentid)