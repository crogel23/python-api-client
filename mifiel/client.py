from binascii import unhexlify
from bip32utils import BIP32Key
from .api_auth import RequestsApiAuth

class Client:
  def __init__(self, app_id, secret_key, master_key=None):
    self.sandbox = False
    self.auth = RequestsApiAuth(app_id, secret_key)
    self.base_url = 'https://www.mifiel.com'
    self.master_key = None
    if master_key is not None:
      self.set_master_key(master_key)

  def use_sandbox(self):
    self.sandbox = True
    self.base_url = 'https://sandbox.mifiel.com'

  def set_base_url(self, base_url):
    self.base_url = base_url

  def set_master_key(self, seed):
    master = BIP32Key.fromEntropy(unhexlify(seed))
    self.master_key = master

  def url(self):
    return self.base_url + '/api/v1/{path}'

