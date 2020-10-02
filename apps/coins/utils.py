import os
import binascii
import hashlib
import hmac
import json
import requests
import subprocess

from bitcoin import *
from pywallet import wallet
from decimal import Decimal
from mnemonic import Mnemonic
from eth_utils import add_0x_prefix
from bitcoinrpc.authproxy import AuthServiceProxy
from blockcypher import create_wallet_from_address
from cryptocurrency_wallet_generator import generate_wallet

from stellar_base.asset import Asset
from stellar_base.memo import TextMemo
from stellar_base.address import Address
from stellar_base.keypair import Keypair
from stellar_base.operation import CreateAccount, Payment
from stellar_base.horizon import horizon_livenet, horizon_testnet
from stellar_base.transaction_envelope import TransactionEnvelope as Te


from apps.authentication.models import User
from apps.coins.models import WalletAddress, Wallet, Transaction, VaultWallet, VaultTransaction, MoneroPaymentid


CHANGELLY_API_URL = 'https://api.changelly.com'

CHANGELLY_API_KEY = os.environ.get('CHANGELLY_API_KEY')
CHANGELLY_API_SECRET = "f97918edfc5d4fcbb41c14e59c22fe67"
BLOCKCIPHER_API_KEY = "df4467c879034735a814fd633feb034e"


def changelly_transaction(method, params):
    message = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    }

    serialized_data = json.dumps(message)

    headers = {'api-key': CHANGELLY_API_KEY,
               'sign': sign, 'Content-type': 'application/json'}
    response = requests.post(
        CHANGELLY_API_URL, headers=headers, data=serialized_data)

    return response.json()


def create_btc_connection():
    access = AuthServiceProxy("http://anand:anandkrishnan@127.0.0.1:18332")
    return access


def create_ltc_connection():
    access = AuthServiceProxy("http://anand:anandkrishnan@127.0.0.1:19332")
    return access


def create_bch_connection():
    access = AuthServiceProxy("http://anand:anandkrishnan@13.58.70.247:18332")
    return access


def create_eth_connection():
    access = AuthServiceProxy("http://anand:anandkrishnan@18.218.176.0:18332")
    return access


def create_btg_connection():
    access = AuthServiceProxy("http://anand:anandkrishnan@13.59.29.224:18332")
    return access

def create_dash_connection():
    access = AuthServiceProxy("http://psalm:psalmpw@18.216.255.207:19998")
    return access


def create_xmr_connection(method, params):
    url = "http://18.188.122.162:18083/json_rpc"
    headers = {'content-type': 'application/json'}
    data = {"jsonrpc": "2.0", "id": "0", "method": method, "params": params}
    response = requests.post(url, json=data, headers={
                             'content-type': 'application/json'})
    return response.json()



def gen_address(user):
    priv = sha256(user.password)
    pub = privtopub(priv)
    addr = pubtoaddr(pub)
    return addr, pub, priv


def create_wallet(user, currency):
    if currency == "eth":
        addr = create_eth_wallet(user)
    elif currency == "xlm":
        addr = generate_xlm_wallet(user)
    elif currency == "xmr":
        addr = create_xmr_wallet(user)
    elif currency == "xrp":
        addr = create_xrp_wallet(user)
    elif currency == "ada":
        addr = ADA(user).generate_addreess()
    else:
        access = globals()['create_'+currency+'_connection']()
        addr = access.getnewaddress(user.username)
        wallet, created = Wallet.objects.get_or_create(
            user=user, name=currency)
        wallet.addresses.add(WalletAddress.objects.create(address=addr))
    return addr


def create_ltc_wallet(user):
    w = wallet.create_wallet(network="LTC", children=0)
    wallet = Wallet.objects.create(user=user, name='ltc')
    wallet.addresses.add(WalletAddress.objects.create(address=w["address"]))
    return w["address"]


def create_eth_wallet(user):
    wallet, created = Wallet.objects.get_or_create(user=user, name="eth")
    if created:
        address = get_results("personal_newAccount", ["psalm"])["result"]
        wallet.addresses.add(WalletAddress.objects.create(address=address))
    else:
        address = wallet.addresses.all()[0].address
    return address


def create_xmr_wallet(user):
    wallet, created = Wallet.objects.get_or_create(user=user, name="xmr")
    paymentid = (binascii.b2a_hex(os.urandom(8))).decode()
    moneropaymentid = MoneroPaymentid.objects.create(
        user=user, paymentid=paymentid)
    param = {
        "payment_id": paymentid
    }
    address = create_xmr_connection("make_integrated_address", param)["result"]['integrated_address']
    wallet.addresses.add(WalletAddress.objects.create(address=address))
    return address


def create_btg_wallet(user):
    w = wallet.create_wallet(network="BTG", children=1)
    wallet = Wallet.objects.create(user=user, name='btg')
    wallet.addresses.add(WalletAddress.objects.create(address=w["address"]))
    return w["address"]


def create_bch_wallet(user):
    w = wallet.create_wallet(network="BCH", children=1)
    wallet = Wallet.objects.create(user=user, name='btg')
    wallet.addresses.add(WalletAddress.objects.create(address=w["address"]))
    return w["address"]


def create_xrp_wallet(user):
    # address_process = subprocess.Popen(
    #     ['node', '../ripple-wallet/test.js'], stdout=subprocess.PIPE)
    # address_data, err = address_process.communicate()
    # addresses = address_data.decode("utf-8") .replace("\n", "")
    # pub_address = addresses.split("{ address: '")[1].split("'")[0]
    # priv_address = addresses.split("secret: '")[-1].replace("' }", "")
    addresses = json.loads(requests.post("https://faucet.altnet.rippletest.net/accounts").text)
    pub_address = addresses["account"]["address"] 
    priv_address = addresses["account"]["secret"] 
    wallet, created = Wallet.objects.get_or_create(user=user, name='xrp')
    if created:
        wallet.addresses.add(WalletAddress.objects.create(address=pub_address))
        wallet.private=priv_address
        wallet.save()
    else:
        pub_address = wallet.addresses.all()[0].address
    return pub_address


def get_balance(user, currency):
    if currency == "eth":
        try:
            balance = get_eth_balance(user)
        except:
            balance = get_eth_balance(User.objects.get(username=user))

    elif currency == "xlm":
        try:
            balance = get_xlm_balance(user)
        except:
            balance = get_xlm_balance(User.objects.get(username=user))

    elif currency == "xmr":
        try:
            balance = get_xmr_balance(User.objects.get(username=user))
        except:
            balance = get_xmr_balance(user)
    elif currency == "xrp":
        try:
            obj = XRP(user)
            balance = obj.balance()
        except:
            obj = XRP(User.objects.get(username=user))
            balance = obj.balance()
    elif currency == "ada":
        try:
            obj = ADA(user)
            balance = obj.balance()
        except:
            obj = ADA(User.objects.get(username=user))
            balance = obj.balance()

    else:
        access = globals()['create_'+currency+'_connection']()
        balance = access.getreceivedbyaccount(user)
        transaction = Transaction.objects.filter(
            user__username=user, currency=currency)
        if transaction:
            balance = balance - sum([Decimal(obj.amount)
                                     for obj in transaction])

    return balance


def get_vault_balance_utils(username, currency):
    if currency == "eth":
        try:
            balance = get_eth_vault_balance(username)
        except:
            balance = get_eth_vault_balance(
                User.objects.get(username=username))
    elif currency == 'xmr':
        try:
            balance = get_xmr_vault_balance(username)
        except:
            balance = get_xmr_vault_balance(
                User.objects.get(username=username))
        
    elif currency == 'xlm':
        try:
            balance = get_xlm_vault_balance(username)
        except:
            balance = get_xlm_vault_balance(
                User.objects.get(username=username))
        
    else:
        access = globals()['create_'+currency+'_connection']()
        balance = access.getreceivedbyaccount(username)
        transaction = VaultTransaction.objects.filter(
            user=username, currency=currency)
        if transaction:
            balance = balance - sum([Decimal(obj.amount)
                                     for obj in transaction])

    return balance


def create_vault_wallet(user, username, currency):
    if currency not in ('xmr','eth','xlm'):
        access = globals()['create_'+currency+'_connection']()
        addr = access.getnewaddress(username)
    elif currency == 'xmr':
        paymentid = (binascii.b2a_hex(os.urandom(8))).decode()
        moneropaymentid = MoneroPaymentid.objects.create(
            user=user, paymentid=paymentid)
        param = {
            "payment_id": paymentid
        }
        addr = create_xmr_connection("make_integrated_address", param)[
            "result"]['integrated_address']
    elif currency == 'xlm':
        kp = Keypair.random()
        addr = kp.address().decode()
        requests.get('https://friendbot.stellar.org/?addr=' + addr)    
        vault, created = VaultWallet.objects.get_or_create(
        user=user, username=username, name=currency)
        vault.addresses.add(WalletAddress.objects.create(address=addr))
        vault.private = kp.seed().decode()
        vault.save()
        return addr
        
    wallet, created = VaultWallet.objects.get_or_create(
        user=user, username=username, name=currency)
    wallet.addresses.add(WalletAddress.objects.create(address=addr))
    return addr


def wallet_info(currency):
    """
    Retrive all wallet info such as:
    All Users and their balance.
    Admin Wallet info.
    """
    context = {}
    access = globals()['create_'+currency+'_connection']()
    context["users"] = access.listaccounts()
    context['wallet_info'] = access.getwalletinfo()
    return context


def get_results(method, params):
    message = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    }

    serialized_data = json.dumps(message)

    headers = {'Content-type': 'application/json'}
    response = requests.post("http://13.59.29.224:8545",headers=headers, data=serialized_data)
    return response.json()


def get_eth_balance(user):
    user_addr = Wallet.objects.get(
        user=user, name='eth').addresses.all()[0].address
    params = [user_addr, "latest"]
    balance = get_results("eth_getBalance", params)['result']
    return balance


def get_eth_vault_balance(user):
    user_addr = VaultWallet.objects.get(
        username=user, name='eth').addresses.all()[0].address
    params = [user_addr, "latest"]
    balance = get_results("eth_getBalance", params)['result']
    return balance


def get_eth_system_balance():
    all_eth_wallets = Wallet.objects.filter(name='eth')
    balance = 0
    for ethwallet in all_eth_wallets:
        for addresses in ethwallet.addresses.all():
            params = [addresses.address, "latest"]
            balance = balance + \
                hex_to_float(get_results("eth_getBalance", params)['result'])
    return balance


def unlock_eth_transaction(user):
    user_addr = Wallet.objects.get(
        user=user, name='eth').addresses.all()[0].address
    params = [user_addr, "psalm", 15000]
    result = get_results("personal_unlockAccount", params)


def send_eth_transaction(user, amount, to_addr):
    user_addr = Wallet.objects.get(
        user=user, name='eth').addresses.all()[0].address
    params = [
        {
            "from": user_addr,
            "to": to_addr,
            "value": float_to_hex(amount)
        },
        "psalm"
    ]
    result = get_results("personal_sendTransaction", params)
    if result.get("error"):
        return {"error": result.get("error").get("message")}
    else:
        return True



def send_eth_vault_transaction(user, amount, to_addr):
    user_addr = VaultWallet.objects.get(
        user=user, name='eth').addresses.all()[0].address
    params = [
        {
            "from": user_addr,
            "to": to_addr,
            "value": float_to_hex(amount)
        },
        "psalm"
    ]
    result = get_results("personal_sendTransaction", params)
    if result.get("error"):
        return {"error": result.get("error").get("message")}
    else:
        return True


def float_to_hex(f):
    return hex(struct.unpack('<I', struct.pack('<f', f))[0])


def hex_to_float(h):
    return float.fromhex(h)


def generate_xlm_wallet(user):
    wallet, created = Wallet.objects.get_or_create(user=user, name="xlm")
    if created:
        kp = Keypair.random()
        address = kp.address().decode()
        requests.get('https://friendbot.stellar.org/?addr=' + address)
        wallet.addresses.add(WalletAddress.objects.create(address=address))
        wallet.private = kp.seed().decode()
        wallet.save()
    else:
        address = wallet.addresses.all()[0].address
        requests.get('https://friendbot.stellar.org/?addr=' + address)
    return address


def get_xlm_balance(user):
    user_addr = Wallet.objects.get(
        user=user, name='xlm').addresses.all()[0].address
    address = Address(address=user_addr)
    try:
        address.get()
        return Decimal(address.balances[0]['balance'])
    except:
        return None

def get_xlm_vault_balance(user):
    user_addr = VaultWallet.objects.get(
        username=user, name='xlm').addresses.all()[0].address
    address = Address(address=user_addr)
    try:
        address.get()
        return Decimal(address.balances[0]['balance'])
    except:
        return None
    


def get_xmr_balance(user):
    wallet = Wallet.objects.get(user=user, name="xmr")
    if wallet:
        temp_list = MoneroPaymentid.objects.filter(user=user)
        balance = 0
        for pids in temp_list:
            param = {
                "payment_id": pids.paymentid
            }
            try:
                temp_balance = create_xmr_connection("get_payments", param)[
                    "result"]['payments'][0]['amount']
            except:
                temp_balance = 0
            balance = balance + temp_balance
    else:
        balance = 0
    return balance


def get_xmr_vault_balance(user):
    wallet = VaultWallet.objects.filter(
        username=user, name='xmr')
    if wallet:
        temp_list = MoneroPaymentid.objects.filter(username=user)
        balance = 0
        for pids in temp_list:
            param = {
                "payment_id": pids.paymentid
            }
            try:
                temp_balance = create_xmr_connection("get_payments", param)[
                    "result"]['payments'][0]['amount']
            except:
                temp_balance = 0
            balance = balance + temp_balance
    else:
        balance = 0
    return balance


def get_xmr_transaction(user, type):
    wallet = Wallet.objects.get(user=user, name="xmr")
    if wallet:
        param = {
            type: True
        }
        try:
            incoming_trx = create_xmr_connection(
                "get_transfers", param)['result']['in']
            incoming_transactions = []
            for in_trx in incoming_trx:
                incoming_transactions.append({
                    "amount": in_trx['amount'],
                    "txid": in_trx['txid'],
                    "time": in_trx['timestamp'],
                    "paymentid": in_trx['payment_id'],
                    "address": in_trx['destinations']
                })
            print(incoming_transactions)
        except:
            incoming_transactions = None
    else:
        incoming_transactions = None
    return incoming_transactions


def send_xlm_transaction(user, destination, amount):
    from stellar_base.transaction import Transaction
    wallet = Wallet.objects.get(user=user, name="xlm")
    User = Keypair.from_seed(wallet.private)
    horizon = horizon_testnet()
    asset = Asset.native()

    op = Payment({
        'destination': destination,
        'asset': asset,
        'amount': amount
    })
    msg = TextMemo('From test net !')

    sequence = horizon.account(User.address().decode('utf-8')).get('sequence')

    tx = Transaction(
        source=User.address().decode(),
        opts={
            'sequence': sequence,
            'memo': msg,
            'operations': [
                op,
            ],
        },
    )
    try:
        envelope = Te(tx=tx, opts={"network_id": "TESTNET"})
        envelope.sign(User)
        xdr = envelope.xdr()
        response = horizon.submit(xdr)
        return response['hash']
    except:
        return {"error": ""}


def send_xlm_vault_transaction(user, destination, amount):
    from stellar_base.transaction import Transaction
    wallet = VaultWallet.objects.get(username=user, name="xlm")
    User = Keypair.from_seed(wallet.private)
    horizon = horizon_testnet()
    asset = Asset.native()

    op = Payment({
        'destination': destination,
        'asset': asset,
        'amount': amount
    })
    msg = TextMemo('From test net !')

    sequence = horizon.account(User.address().decode('utf-8')).get('sequence')

    tx = Transaction(
        source=User.address().decode(),
        opts={
            'sequence': sequence,
            'memo': msg,
            'operations': [
                op,
            ],
        },
    )
    try:
        envelope = Te(tx=tx, opts={"network_id": "TESTNET"})
        envelope.sign(User)
        xdr = envelope.xdr()
        response = horizon.submit(xdr)
        return response['hash']
    except:
        return {"error": ""}

def validate_xmr_address(address):
    addr_len = len(address)
    first_char = str(address[:1])
    second_char = address[1:2]
    print(addr_len)
    result= {
		"isvalid": False,
		"address": address
	}
    if addr_len not in (95, 106):
        print("length is diff")
        return result
    if first_char == '4':
        result['isvalid'] =True
        return result
        
    return result


class XRP():
    def __init__(self, user):
        self.user = user

    def balance(self):
        wallet = Wallet.objects.get(user=self.user, name="xrp")
        secret = wallet.private
        address = wallet.addresses.all().first().address
        params =    {
                        "method": "account_info",
                        "params": [
                            {
                                "account": address,
                                "strict": True,
                                "ledger_index": "validated"
                            }
                        ]
                    }
        result = json.loads(requests.post("https://s.altnet.rippletest.net:51234",json=params).text)
        try:
            return Decimal(result['result']['account_data']['Balance'])/Decimal(1000000)
        except:
            return "0"

    def send(self, destination, amount):
        wallet = Wallet.objects.get(user=self.user, name="xrp")
        secret = wallet.private
        address = wallet.addresses.all().first().address
        params =    { "method" : "sign",
                      "params" : [ 
                                    { 
                                        "secret" : secret,
                                        "tx_json" : {
                                                        "TransactionType":"Payment",
                                                        "Account":address,
                                                        "Amount":str(int(amount)*1000000),
                                                        "Destination":destination
                                                    }
                                    } 
                                ] 
                    }
        result = json.loads(requests.post("https://s.altnet.rippletest.net:51234",json=params).text)
        params = {
                    "method": "submit",
                    "params": [
                        {
                            "tx_blob": result['result']['tx_blob']
                        }
                    ]
                }
        submit = json.loads(requests.post("https://s.altnet.rippletest.net:51234",json=params).text)
        try:
            return result['result']['tx_json']['hash']
        except:
            return result['result']['error']




def send_xrp_transaction(user, destination, amount):
    wallet = Wallet.objects.get(user=user, name="xlm")
    secret = wallet.private
    address = wallet.addresses.all().first().address
    params =    {
                    "method": "account_info",
                    "params": [
                        {
                            "account": address,
                            "strict": true,
                            "ledger_index": "validated"
                        }
                    ]
                }
    
    return {"error": ""}


class ADA():
    def __init__(self, user):
        self.user = user

    def generate_addreess(self):
        wallet, created = Wallet.objects.get_or_create(user=self.user, name='ada')
        if created:
            mnemonic = Mnemonic("english")
            mnemonic_list = [word for word in mnemonic.generate(128).split(" ")]

            data =  { 
                        "cwInitMeta":      { 
                                                "cwName": self.user.username,
                                                "cwAssurance": "CWANormal", 
                                                "cwUnit": 0 
                                            }, 
                        "cwBackupPhrase":   { 
                                                "bpToList": mnemonic_list
                                            } 
                   }
            wallet_data = self.result("https://18.217.31.221:8090/api/wallets/new",data)

            data =  {
                        "caInitMeta": {
                                        "caName": self.user.username
                                        },
                          "caInitWId": wallet_data["Right"]["cwId"]
                    }
            addresses = self.result("https://18.217.31.221:8090/api/accounts/",data)
            priv_address = addresses["Right"]["caId"]
            pub_address = addresses["Right"]["caAddresses"][-1]["cadId"]         
            wallet.addresses.add(WalletAddress.objects.create(address=pub_address))
            wallet.private=priv_address
            wallet.save()
        else:
            pub_address = wallet.addresses.all()[0].address
        return pub_address

    def balance(self):
        wallet = Wallet.objects.get(user=self.user, name='ada')
        address = wallet.private
        result = self.result("https://18.217.31.221:8090/api/accounts/"+address,[])
        return int(result["Right"]["caAmount"]["getCCoin"])/1000000


    def send(self, destination, amount):
        wallet = Wallet.objects.get(user=self.user, name='ada')
        private = wallet.private
        data = {
                  "groupingPolicy": "OptimizeForHighThroughput"
                }
        result = self.result("https://18.217.31.221:8090/api/txs/payments/"+private+"/"+destination+"/"+str(Decimal(amount)*1000000).split('.0')[0],data)
        if result.get("Right"):
            return "success"
        else:
            return {"error":result.get("Left").get("contents")}

    def result(self, url, data):
        if not data:
            data = json.loads(requests.get(url, verify=False).text)
        else:
            data = json.loads(requests.post(url,json=data, verify=False).text)
        return data