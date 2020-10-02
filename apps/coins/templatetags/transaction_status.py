import json
import requests
import datetime

from django import template
from apps.coins.utils import *

register = template.Library()


@register.simple_tag
def transaction_status(trans_id):
    params = {"id": trans_id}

    data = changelly_transaction('getStatus', params)
    if data.get('error'):
        return "Payment not received.Failed."
    else:
        return data.get('result')


@register.simple_tag
def get_balance_btc(user):
    balance = get_balance(user, "btc")
    if not balance:
        balance = 0
    return balance

@register.simple_tag
def get_balance_btg(user):
    balance = get_balance(user, "btg")
    if not balance:
        balance = 0
    return balance

@register.simple_tag
def get_balance_ltc(user):
    balance = get_balance(user, "ltc")
    if not balance:
        balance = 0
    return balance


@register.simple_tag
def get_balance_bch(user):
    balance = get_balance(user, "bch")
    if not balance:
        balance = 0
    return balance


@register.simple_tag
def get_balance_eth(user):
    balance = get_balance(user, "eth")
    if not balance:
        balance = 0
    return balance


@register.simple_tag
def get_btg_balance(address):
    bal_req = requests.get("http://btgblocks.com/ext/getbalance/"+address).text
    if "error" in bal_req:
        balance = 0
    else:
        balance = bal_req
    return balance


@register.simple_tag
def get_ltc_balance(address):
    bal_req = requests.get(
        "https://api.blockcypher.com/v1/ltc/main/addrs/"+address).text
    bal = json.loads(bal_req)
    return bal['balance']


@register.filter
def rcv(mapping, key):
    return mapping.get('transactions_rcv_'+key, '')


@register.filter
def snd(mapping, key):
    return mapping.get('transactions_snd_'+key, '')


@register.simple_tag
def get_bal_coin(key, user):
    try:
        balance = get_balance(user, key)
    except:
        return 0
    if not balance:
        balance = 0
    return balance


@register.filter(name='unix_to_datetime')
def unix_to_datetime(value):
    try:
        date = datetime.datetime.fromtimestamp(int(value))
    except:
        date = value
    return date

@register.simple_tag
def get_vault_balance(username, currency):
    username = username+'_vault'+'_'+currency
    balance = get_vault_balance_utils(username, currency)
    if not balance:
        balance = 0
    return balance


