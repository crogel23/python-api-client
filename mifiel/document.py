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
    signatories = {}
    for signer in self.signers:
      signer_id = signer['id']
      doc_i, signer_i = signer['e2ee']['e_index'].split('/')
      public_key_hex = Document.__key_derivation(master_key, doc_i, signer_i)
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
    if type(doc) is str:
      doc = int(doc[:-1]) + BIP32_HARDEN if "'" in doc or 'H' in doc else int(doc)
    if type(signer) is str:
      signer = int(signer)
    node = master_key.CKDpriv(doc).CKDpub(signer)
    return node.PublicKey().hex()

  @staticmethod
  def __key_derivation_from_widget_id(master_key, widget_id):
    widget_map = widget_id.split('-')
    signer = widget_map.pop()
    doc = widget_map.pop()
    return Document.__key_derivation(master_key, doc, signer)

  @staticmethod
  def __validate_create(client, name, file, dhash, encrypted):
    neither_file_and_hash = not file and not dhash
    encrypted_and_empty_master_key = encrypted and client.master_key is None
    encrypted_and_not_file_or_hash = encrypted and (not file or not dhash)
    not_encrypted_with_file_and_hash = not encrypted and file and dhash
    not_encrypted_with_hash_and_empty_name = not encrypted and dhash and not name
    if encrypted_and_empty_master_key:
      raise ValueError('Master key is needed to create encrypted documents. client.set_master_key(seed_as_hex_string)')
    if encrypted_and_not_file_or_hash:
      raise ValueError('Both file and dhash are required for encrypted documents')
    if neither_file_and_hash:
      raise ValueError('Either file or hash must be provided')
    if not_encrypted_with_file_and_hash:
      raise ValueError('Only one of file or hash must be provided')
    if not_encrypted_with_hash_and_empty_name:
      raise ValueError('A name is required when using the documents hash')

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
