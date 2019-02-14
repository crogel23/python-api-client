import mimetypes
import requests
from bip32utils import BIP32_HARDEN
from os.path import basename
from mifiel import Base, Response
from mifiel.crypto import AES, PBE, PKCS5, ECIES

class Document(Base):
  def __init__(self, client):
    Base.__init__(self, client, 'documents')

  @staticmethod
  def find(client, doc_id):
    doc = Document(client)
    doc.process_request('get', url=doc.url(doc_id))
    return doc

  @staticmethod
  def all(client):
    base = Document(client)
    response = base.execute_request('get', url=base.url())
    result = []
    for single in response.json():
      obj = Document(client)
      obj.set_data(single)
      result.append(obj)
    return result

  @staticmethod
  def create(client, signatories, file=None, dhash=None, callback_url=None, name=None, encrypted=False):
    Document.__validate_create(client, name, file, dhash, encrypted)

    sig_numbers = {}

    for index, item in enumerate(signatories):
      for key, val in item.items():
        sig_numbers.update(
          {'signatories[' + str(index) + '][' + str(key) + ']': val}
        )

    data = sig_numbers

    if callback_url: data['callback_url'] = callback_url
    if file: file, random_password = Document.__prepare_file_to_store(file, encrypted)
    if dhash: data['original_hash'] = dhash
    if name: data['name'] = name

    doc = Document(client)
    doc.process_request('post', data=data, files=file)
    if encrypted:
      doc.__cipher_doc_secrets(client.master_key, random_password)
    return doc

  def request_signature(self, signer, cc=None):
    path = '{}/{}'.format(self.id, 'request_signature')
    data = {
      'email': signer,
      'cc': cc
    }
    response = self.execute_request('post', url=self.url(path), json=data)
    return response.json()

  @staticmethod
  def delete(client, doc_id):
    base = Document(client)
    response = base.execute_request('delete', url=base.url(doc_id))
    return response.json()

  @staticmethod
  def create_from_template(client, args={}):
    call = Base(client, 'templates')
    path = '{}/{}'.format(args['template_id'], 'generate_document')
    response = call.execute_request('post', url=call.url(path), json=args)
    doc = Document(client)
    doc.set_data(response)
    return doc

  @staticmethod
  def create_many_from_template(client, args={}):
    call = Base(client, 'templates')
    url = '{}/{}'.format(args['template_id'], 'generate_documents')
    response = call.execute_request('post', url=call.url(url), json=args)
    return response.json()

  def save_file(self, path):
    url_ = self.url('{}/file').format(self.id)
    response = requests.get(url_, auth=self.client.auth)
    with open(path, 'w') as file_:
      file_.write(response.text)

  def save_file_signed(self, path):
    url_ = self.url('{}/file_signed').format(self.id)
    response = requests.get(url_, auth=self.client.auth)
    with open(path, 'w') as file_:
      file_.write(response.text)

  def save_xml(self, path):
    url_ = self.url('{}/xml').format(self.id)
    response = requests.get(url_, auth=self.client.auth)
    with open(path, 'w') as file_:
      file_.write(response.text)

  def __cipher_doc_secrets(self, master_key, random_password):
    # Document.__key_derivation(master_key, doc, signer)
    return
    signatories = {}
    for signer in self.signers:
      signer_id = signer.id
      public_key_hex = signer.e2ee.group.e_client.pub
      e_pass = ECIES.encrypt(public_key_hex, random_password)
      signatories[signer_id] = {
        'e_client': {
          'e_pass': e_pass
        }
      }
    self.signatories = signatories
    self.save()

  @staticmethod
  def __key_derivation(master_key, doc, signer):
    node = master_key.CKDpriv(doc + BIP32_HARDEN).CKDpub(signer)
    return node.PublicKey().hex()

  @staticmethod
  def __validate_create(client, name, file, dhash, encrypted):
    if not file and not dhash:
      raise ValueError('Either file or hash must be provided')
    if encrypted:
      if client.master_key is None:
        raise ValueError('Master key is needed to create encrypted documents. client.set_master_key(seed_as_hex_string)')
      elif not file or not dhash:
        raise ValueError('Both file and dhash are required for encrypted documents')
    else:
      if file and dhash:
        raise ValueError('Only one of file or hash must be provided')
      if dhash and not name:
        raise ValueError('A name is required when using hash')

  @staticmethod
  def __prepare_file_to_store(file_path, encrypted):
    random_password = None
    original_file = open(file_path, 'rb')
    filename = basename(original_file.name)
    mimetype = 'text/plain' if encrypted else mimetypes.guess_type(file_path)[0]
    file_data = Document.__encrypt_file(original_file) if encrypted else original_file
    if encrypted:
      filename += '.enc'
      file_data, random_password = file_data
    return (
      {'file': (filename, file_data, mimetype)},
      random_password
    )

  @staticmethod
  def __encrypt_file(file):
    random_iv = AES.random_iv()
    random_salt = PBE.random_salt()
    random_password = PBE.random_password()
    derived_key = PBE.get_derived_key(random_password, salt=random_salt)
    file_bytes = file.read()
    encrypted_doc = AES.encrypt(derived_key, file_bytes, random_iv)
    pkcs5_attrs = {
      'iv': random_iv,
      'salt': random_salt,
      'iterations': 1000,
      'key_size': PKCS5.AES_256_CBC_OID,
      'cipher_data': encrypted_doc
    }
    pkcs5 = PKCS5(pkcs5_attrs)
    asn1_hex = pkcs5.dump_asn1()
    return (
      bytes.fromhex(asn1_hex),
      random_password
    )
