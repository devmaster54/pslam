import apps.coins.utils

from decimal import Decimal
from django.urls import reverse
from easy_pdf.views import PDFTemplateView
from django.utils.decorators import method_decorator
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
from django.shortcuts import HttpResponse, render, redirect
from django.views.generic import TemplateView, FormView, View, ListView

from apps.coins.utils import *
from apps.coins.models import Wallet, Transaction, VaultWallet, VaultRetrieveRequest
from apps.authentication.decorators import check_otp
from apps.authentication.models import User
from apps.authentication.views import AuthAdminMixin
from apps.authentication.views import AuthVerifiedMixin


CURRENCIES = ['btc', 'ltc', 'bch', 'eth', 'btg', 'xlm', 'xmr', 'xrp', 'dash', 'ada']

CURRENCY = {
    '0': 'btc',
    '1': 'eth',
    '2': 'ltc',
    '3': 'xmr',
    '4': 'bch',
    '5': 'btg',

}


class IndexView(AuthVerifiedMixin, TemplateView):
    template_name = 'index.html'

    def get_context_data(self, **kwargs):
        context = {}
        context['coin_list'] = {
            'BTC': '1',
            'BCH': '2',
            'BTG': '3',
            'ETH': '4',
            'XMR': '5',
            'LTC': '6',
            'XRP': '7',
            'ADA': '8',
            'XLM': '9',
            'EOS': '10',
            'NEO': '11',
            'IOT': '12',
            'DASH': '13',
            'TRX': '14',
            'XEM': '15'
        }
        return context


class ExchangeView(AuthVerifiedMixin, TemplateView):
    template_name = 'exchange.html'


class ExchangeRateView(AuthVerifiedMixin, View):
    """
    Displaying the exchange rate based on the amount.
    If no amount entered will take the minimum transaction amount
    """

    def post(self, request, *args, **kwargs):
        convert_from = CURRENCY[request.POST.get('from')]
        convert_to = CURRENCY[request.POST.get('to')]
        amount = request.POST.get('amount')

        if amount:
            params = {
                "from": convert_from,
                "to": convert_to,
                "amount": amount
            }
            method = "getExchangeAmount"
        else:
            params = {
                "from": convert_from,
                "to": convert_to,
            }
            method = 'getMinAmount'
        data = changelly_transaction(method, params)
        if not data.get('error'):
            request.session['convert_from'] = convert_from
            request.session['convert_to'] = convert_to
            request.session['amount'] = amount
            if not amount:
                request.session['amount'] = '1'
        return HttpResponse(json.dumps(data), content_type='application/json')


class WalletsView(LoginRequiredMixin, AuthVerifiedMixin, TemplateView):
    template_name = 'wallets.html'

    def get_context_data(self, *args, **kwargs):
        context = super(WalletsView, self).get_context_data(**kwargs)
        for currency in CURRENCIES:
            if not Wallet.objects.filter(user=self.request.user, name=currency):
                create_wallet(self.request.user, currency)
        context['coin_list'] = {
            'BTC': '1',
            'BCH': '2',
            'BTG': '3',
            'ETH': '4',
            'XMR': '5',
            'LTC': '6',
            'XRP': '7',
            'ADA': '8',
            'XLM': '9',
            'EOS': '10',
            'NEO': '11',
            'IOT': '12',
            'DASH': '13',
            'TRX': '14',
            'XEM': '15'
        }
        context['wallets'] = Wallet.objects.filter(user=self.request.user)
        return context

    def post(self, *args, **kwargs):
        try:
            wallet_name = self.request.POST.get(
                "convert").strip().split('"')[3]
            create_wallet(self.request.user, wallet_name)
            # wallets = Wallet.objects.filter(user=self.request.user)
            # if not wallets.filter(name=wallet_name):
            #     getattr(apps.coins.utils, "create_" +
            #             wallet_name+"_wallet")(self.request.user)
        except:
            pass
        return redirect(reverse('coins:wallets'))


class NewCoinAddr(LoginRequiredMixin,AuthVerifiedMixin, View):
    def post(self, request, *args, **kwargs):
        currency = self.request.POST.get('currency')
        username = self.request.POST.get('user')
        user = User.objects.get(username=username)
        try:
            addr = create_wallet(user, currency)
            return HttpResponse(json.dumps({"success": True, "addr": addr}), content_type='application/json')
        except:
            return HttpResponse(json.dumps({"error": "An error occured"}), content_type='application/json')


class TransactionView(LoginRequiredMixin, AuthVerifiedMixin, TemplateView):
    template_name = 'transactions.html'

    def get_context_data(self, *args, **kwargs):
        context = super(TransactionView, self).get_context_data(**kwargs)
        ctx = {}
        context['currencies'] = CURRENCIES

        for currency in CURRENCIES:
            if currency not in ('eth', 'xlm', 'xmr', 'xrp', 'ada'):
                access = getattr(apps.coins.utils, 'create_' +
                                 currency+'_connection')()
                ctx['transactions_rcv_' +
                    currency] = access.listtransactions(self.request.user.username)
                txns = Transaction.objects.filter(
                    currency=currency, user=self.request.user)
                ctx['transactions_snd_' +
                    currency] = self.get_transaction(txns, access)
            elif currency == 'xmr':
                ctx['transactions_rcv_' +
                    currency] = get_xmr_transaction(self.request.user, "in")
                ctx['transactions_snd_' +
                    currency] = get_xmr_transaction(self.request.user, "out")
            elif currency == 'xlm':
                txns = Transaction.objects.filter(
                    currency=currency, user=self.request.user)
                ctx['transactions_snd_' +
                    currency] = self.get_xlm_transactions(txns)
        context['ctx'] = ctx
        return context

    def get_transaction(self, txns, access):
        txns_list = []
        for txn in txns:
            txn_row = access.gettransaction(txn.transaction_id)
            txns_list.append(self.change_txn_format(txn_row))
        return txns_list

    def change_txn_format(self, txn_row):
        out = {}
        out['address'] = txn_row['details'][0]['address']
        out['amount'] = txn_row['details'][0]['amount']
        out['confirmations'] = txn_row['confirmations']
        out['txid'] = txn_row['txid']
        out['time'] = txn_row['time']
        return out

    def get_xlm_transactions(self, txns):
        txns_list = []
        for txn in txns:
            out = {}
            out['address'] = txn.transaction_to
            out['amount'] = txn.amount
            out['confirmations'] = ''
            out['txid'] = txn.transaction_id
            out['time'] = ''
            txns_list.append(out)
        return txns_list


class SendTransactionView(LoginRequiredMixin, TemplateView):
    """
    For rendering send coin page and validating the given details in post.
    """
    template_name = 'send_coin.html'

    def get_context_data(self, *args, **kwargs):
        context = super(SendTransactionView, self).get_context_data(**kwargs)
        context['currency'] = kwargs.get('slug')
        return context

    def post(self, request, *args, **kwargs):
        address = request.POST.get('to')
        currency = kwargs.get('slug')

        amount = Decimal(request.POST.get('amount'))
        if currency not in ('eth', 'xlm', 'xmr','xrp', 'ada'):
            access = globals()['create_'+currency+'_connection']()
            valid = access.validateaddress(address)
            balance = get_balance(request.user.username, currency)
            if valid['isvalid'] and balance >= amount:
                return HttpResponse(json.dumps({"success": True}), content_type='application/json')
            if valid['isvalid']:
                return HttpResponse(json.dumps({"error": "Insufficient balance"}), content_type='application/json')
            if balance >= amount:
                return HttpResponse(json.dumps({"error": "Please enter a valid address"}), content_type='application/json')
            else:
                return HttpResponse(json.dumps({"error": "Please verify the data"}), content_type='application/json')
        elif currency == 'xmr':
            balance = get_xmr_balance(self.request.user)
            valid = validate_xmr_address(address)
            if valid['isvalid'] and balance >= amount:
                return HttpResponse(json.dumps({"success": True}), content_type='application/json')
            if valid['isvalid']:
                return HttpResponse(json.dumps({"error": "Insufficient balance"}), content_type='application/json')
            if balance >= amount:
                return HttpResponse(json.dumps({"error": "Please enter a valid address"}), content_type='application/json')
            else:
                return HttpResponse(json.dumps({"error": "Please verify the data"}), content_type='application/json')

        return HttpResponse(json.dumps({"success": True}), content_type='application/json')


class SendConfirmView(LoginRequiredMixin, View):
    """
    For sending coins to given address
    """

    def post(self, request, *args, **kwargs):
        address = request.POST.get('to')
        currency = kwargs.get('slug')
        amount = Decimal(request.POST.get('amount'))
        if currency not in ('eth', 'xlm', 'xmr','xrp', 'ada'):
            access = getattr(apps.coins.utils, 'create_' +
                             currency+'_connection')()
            valid = access.sendtoaddress(address, amount)
            balance = get_balance(request.user.username, currency)
            balance = balance - amount
        elif currency == "eth":
            valid = send_eth_transaction(self.request.user, amount, address)
        elif currency == 'xmr':
            amount = int(amount)
            balance = get_xmr_balance(self.request.user)
            valid = validate_xmr_address(address)
            param = {
                "destinations": [{"amount": amount, "address": address}]
            }
            try:
                res = create_xmr_connection("transfer", param)
                if res['error']:
                    return HttpResponse(json.dumps({"error": res['error']['message']}), content_type='application/json')
                valid = "true"
            except:
                valid = False
        elif currency == 'xlm':
            valid = send_xlm_transaction(
                self.request.user, address, str(amount))
            balance = get_xlm_balance(user=self.request.user)
        elif currency == 'xrp':
            obj = XRP(self.request.user)
            valid = obj.send(address, str(amount))
            balance = get_xlm_balance(user=self.request.user)
        elif currency == 'ada':
            obj = ADA(self.request.user)
            valid = obj.send(address, str(amount))
            balance = obj.balance()
        if type(valid) == str:
            Transaction.objects.create(user=self.request.user, currency=currency,
                                       balance=balance, amount=amount, transaction_id=valid, transaction_to=address)
            return HttpResponse(json.dumps({"success": True}), content_type='application/json')

        return HttpResponse(json.dumps(valid), content_type='application/json')


class TransactionPdfView(PDFTemplateView):
    template_name = 'transactionpdf.html'

    def get_context_data(self, *args, **kwargs):
        context = super(TransactionPdfView, self).get_context_data(**kwargs)
        ctx = {}
        context['currencies'] = CURRENCIES

        for currency in CURRENCIES:
            access = getattr(apps.coins.utils, 'create_' +
                             currency+'_connection')()
            ctx['transactions_rcv_' +
                currency] = access.listtransactions(self.request.user.username)
            txns = Transaction.objects.filter(
                currency=currency, user=self.request.user)
            ctx['transactions_snd_' +
                currency] = self.get_transaction(txns, access)
        context['ctx'] = ctx
        return context

    def get_transaction(self, txns, access):
        txns_list = []
        for txn in txns:
            txn_row = access.gettransaction(txn.transaction_id)
            txns_list.append(self.change_txn_format(txn_row))
        return txns_list

    def change_txn_format(self, txn_row):
        out = {}
        out['address'] = txn_row['details'][0]['address']
        out['amount'] = txn_row['details'][0]['amount']
        out['confirmations'] = txn_row['confirmations']
        out['txid'] = txn_row['txid']
        out['time'] = txn_row['time']
        return out


class VaultCoinView(LoginRequiredMixin, AuthVerifiedMixin, TemplateView):
    template_name = 'vault.html'

    def get_context_data(self, *args, **kwargs):
        context = super(VaultCoinView, self).get_context_data(**kwargs)
        context['currency'] = kwargs.get('slug')
        return context

    def post(self, request, *args, **kwargs):
        amt = Decimal(request.POST.get('amt_2_vault'))
        currency = kwargs.get('slug')
        if currency not in ('eth', 'xlm', 'xmr'):
            access = globals()['create_'+currency+'_connection']()

        vault_user = self.request.user.username+'_vault'+'_'+currency
        try:
            vault_wallets = VaultWallet.objects.get(username=vault_user)
        except:
            create_vault_wallet(self.request.user, vault_user, currency)
            vault_wallets = VaultWallet.objects.filter(username=vault_user)
        balance = get_balance(request.user.username, currency)
        obj = VaultWallet.objects.filter(
            username=vault_user).order_by('-id')[0]
        addr = str(obj.addresses.last())
        if currency not in ('eth', 'xlm', 'xmr'):
            validate = access.validateaddress(addr)
        elif currency == 'xmr':
            validate = validate_xmr_address(addr)
        elif currency == 'xlm':
            validate = {
                "isvalid": True,
                "address": addr,
            }
        elif currency == 'eth':
            validate = {
                "isvalid": True,
                "address": addr,
            }
            
        if validate['isvalid'] and balance >= amt:
            if currency not in ('eth', 'xlm', 'xmr'):
                valid = access.sendtoaddress(addr, amt)

            elif currency == 'xmr':
                param = {
                    "destinations": [{"amount": amt, "address": addr}]
                }
                try:
                    res = create_xmr_connection("transfer", param)
                    if res['error']:
                        return HttpResponse(json.dumps({"error": res['error']['message']}), content_type='application/json')
                    valid = "true"
                except:
                    valid = False

            elif currency == 'xlm':
                valid = send_xlm_transaction(self.request.user, addr, str(amt))
                print(valid)
            elif currency =='eth':
                valid = send_eth_transaction(self.request.user, addr, str(amt))

            if valid:
                balance = balance - amt
                Transaction.objects.create(user=self.request.user, currency=currency,
                                           balance=balance, amount=amt, transaction_id=valid, transaction_to=addr)
                return HttpResponse(json.dumps({"success": True}), content_type='application/json')
            else:
                return HttpResponse(json.dumps({"error": "something went wrong"}), content_type='application/json')
        if validate['isvalid']:
            return HttpResponse(json.dumps({"error": "Insufficient balance"}), content_type='application/json')
        if balance >= amt:
            return HttpResponse(json.dumps({"error": "Please enter a valid address"}), content_type='application/json')
        else:
            return HttpResponse(json.dumps({"error": "Please verify the data"}), content_type='application/json')


class AdminVaultRequestView(AuthAdminMixin, AuthVerifiedMixin, TemplateView):
    template_name = 'admin_vault.html'

    def get_context_data(self, *args, **kwargs):
        context = super(AdminVaultRequestView, self).get_context_data(**kwargs)
        context['retrieverequests'] = VaultRetrieveRequest.objects.all()
        return context


class MyVault(LoginRequiredMixin, AuthVerifiedMixin, TemplateView):
    template_name = 'vault_list.html'

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(**kwargs)
        context['allvault'] = VaultWallet.objects.filter(
            user=self.request.user)
        return context


class VaultRetrieve(AuthVerifiedMixin, TemplateView):
    template_name = 'vault2wallet.html'

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(**kwargs)
        context['currency'] = kwargs.get('slug')
        return context

    def post(self, request, *args, **kwargs):
        amt = Decimal(request.POST.get('amt_from_vault'))
        currency = kwargs.get('slug')
        vault_user = self.request.user.username+'_vault'+'_'+currency
        vault_bal = get_vault_balance_utils(vault_user, currency)
        if vault_bal > amt :
            VaultRetrieveRequest.objects.create(
                user=self.request.user,
                username=self.request.user.username + '_vault_' + currency,
                currency=currency,
                amount=amt
            )
            return HttpResponse(json.dumps({"success": True}), content_type='application/json')
        else:
            return HttpResponse(json.dumps({"error": "Insufficient balance to cover Transaction fees + Retrieve amount"}), content_type='application/json')
            

class VaultRetrieveApprove(AuthVerifiedMixin, View):
    def post(self, request, *args, **kwargs):
        username = request.POST.get('user')
        vaultuser = request.POST.get('vaultusername')
        amt = Decimal(request.POST.get('amount'))
        currency = request.POST.get('currency')
        balance = get_vault_balance_utils(vaultuser, currency)
        requesting_user = User.objects.get(username=username)
        if currency not in ('xlm', 'xmr', 'eth'):
            access = globals()['create_'+currency+'_connection']()
        obj = Wallet.objects.filter(
            user=requesting_user).filter(name=currency).order_by('-id')[0]
        addr = str(obj.addresses.last())
        if currency not in ('xlm', 'xmr', 'eth'):
            validate = access.validateaddress(addr)
        else:
            validate = {
                'isvalid': True,
            }
            
        if validate['isvalid'] and balance >= amt:
            if currency not in ('xlm', 'xmr', 'eth'):
                valid = access.sendtoaddress(addr, amt)
            elif currency == 'xmr':
                param = {
                    "destinations": [{"amount": amt, "address": addr}]
                }
                try:
                    res = create_xmr_connection("transfer", param)
                    if res['error']:
                        valid = False
                    valid = "true"
                except:
                    valid = False

            elif currency == 'xlm':
                valid = send_xlm_vault_transaction(vaultuser, addr, str(amt))
                print(valid)
            elif currency == 'eth':
                valid = send_eth_vault_transaction(vaultuser, addr, str(amt))

            if valid:
                balance = balance - amt
                
                VaultTransaction.objects.create(user=vaultuser, currency=currency,
                                                balance=balance, amount=amt, transaction_id=valid, transaction_to=addr, to_user=requesting_user)
                tempobj = VaultRetrieveRequest.objects.filter(
                    username=vaultuser)
                tempobj.delete()
                return HttpResponse(json.dumps({"success": True}), content_type='application/json')
            else:
                return HttpResponse(json.dumps({"error": "something went wrong"}), content_type='application/json')
        if validate['isvalid']:
            return HttpResponse(json.dumps({"error": "Insufficient balance"}), content_type='application/json')
        if balance >= amt:
            return HttpResponse(json.dumps({"error": "Please enter a valid address"}), content_type='application/json')
        else:
            return HttpResponse(json.dumps({"error": "Please verify the data"}), content_type='application/json')


class SystemStat(AuthAdminMixin, TemplateView):
    template_name = 'admin/system_stat.html'

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(**kwargs)
        context['allusers'] = User.objects.all()
        alt_list = []
        context['allcoins'] = CURRENCIES
        for coins in CURRENCIES:
            if coins != 'eth' and coins != 'xlm' and coins != 'xmr' and coins != 'ada'\
            and coins != 'xrp':
                temp = wallet_info(coins)
                alt_list.append([coins, temp['wallet_info']['balance']])
            elif coins == 'eth':
                # temp = get_eth_balance(User.objects.get(username='kagerot'))
                temp = get_eth_system_balance()
                print(temp)
                alt_list.append([coins, temp])
        context['altcoins'] = alt_list
        user_bal_list = []
        user_vaultbal_list = []
        for user in User.objects.values_list('username', flat=True):
            for coins in CURRENCIES:
                try:
                    user_bal_list.append(
                        [user, coins, get_balance(user, coins)])
                except:
                    user_bal_list.append([user, coins, 0])

                vaultusername = user + '_vault_'+coins
                try:
                    user_vaultbal_list.append(
                        [user, coins, get_vault_balance_utils(vaultusername, coins)])
                except:
                    user_vaultbal_list.append([user, coins, 0])
        context['userballist'] = user_bal_list
        context['uservaultballist'] = user_vaultbal_list

        return context


class SystemStatUser(AuthAdminMixin, TemplateView):
    template_name = 'admin/system_user.html'

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(**kwargs)
        username = kwargs.get('slug')
        context['stat_user'] = User.objects.get(username=username)
        user_bal_list = []
        for coins in CURRENCIES:
            vaultusername = username + '_vault_'+coins
            try:
                temp_coin_bal = get_balance(username, coins)
            except:
                temp_coin_bal = 0
            try:
                temp_vault_bal = get_vault_balance_utils(vaultusername, coins)
            except:
                temp_vault_bal = 0
            user_bal_list.append([coins, temp_coin_bal, temp_vault_bal])
        context['userballist'] = user_bal_list
        return context


class TestView(AuthAdminMixin, TemplateView):
    pass
