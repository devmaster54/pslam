
from django.urls import path, register_converter
from django.views.generic import TemplateView, FormView, View, ListView
from . views import IndexView, ExchangeRateView, ExchangeView, WalletsView, TransactionView, SendTransactionView,\
    SendConfirmView, TestView, VaultCoinView, TransactionPdfView, MyVault, VaultRetrieve, VaultRetrieveApprove,\
    AdminVaultRequestView, SystemStat,SystemStatUser, NewCoinAddr

from psalm import convertor
register_converter(convertor.PKConverter, 'slug')


app_name = 'coins'
urlpatterns = [
    path('', IndexView.as_view(), name='home'),
    path('exchange/', ExchangeView.as_view(), name='exchange'),
    path('exchange-rate/', ExchangeRateView.as_view(), name='exchange_rate'),
    path('wallets/', WalletsView.as_view(), name='wallets'),
    path('newaddr/', NewCoinAddr.as_view(), name='newaddr'),
    path('transaction/', TransactionView.as_view(), name='transaction'),
    path('sendcoin/<slug:slug>/', SendTransactionView.as_view(), name='sendcoin'),
    path('sendconfirm/<slug:slug>/', SendConfirmView.as_view(), name='sendconfirm'),
    path('approve/', VaultRetrieveApprove.as_view(), name='vaultreqapprove'),
    path('vault/<slug:slug>/', VaultCoinView.as_view(), name='send2vault'),
    path('vault/retrieve/<slug:slug>/', VaultRetrieve.as_view(), name='retrievefromvault'),
    path('transactionpdf', TransactionPdfView.as_view(), name='transactionpdf'),
    path('myvault', MyVault.as_view(), name='myvault'),
    path('adminvaultrequest/', AdminVaultRequestView.as_view(), name='adminvaultrequest'),
    path('system_stat/', SystemStat.as_view(), name='systemstat'),
    path('system_user/<slug:slug>/', SystemStatUser.as_view(), name='systemstatuser'),
    path('test/', TestView.as_view(), name='test'),
]
