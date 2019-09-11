#!/usr/bin/env python
"""
Hashicorp Vault management class
Currently supported kv secrets engine - version 2 (https://www.vaultproject.io/api/secret/kv/kv-v2.html#delete-metadata-and-all-versions)
and jwt auth method (https://www.vaultproject.io/docs/auth/jwt.html)
"""

# Imports
import os
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import json
import ast

class VaultIntegration:
  def __init__(self, vault_url, issuer_url, client_id, client_secret, audience_claim, jwt_token, secrets_root):
    """
    Constructor require vault endpoint, a vaild jwt token and the secrets root path.
    """

    # token retrieved with Flask-dance does not have audience claim
    # Use exchange token to add it.
    issuer_url = issuer_url + '/token'
    
    payload_string = '{ "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "audience": "'+audience_claim+'", "subject_token": "'+jwt_token+'", "scope": "openid address phone profile offline_access email" }'

    # Convert string payload to dictionary
    payload =  ast.literal_eval(payload_string)

    iam_response = requests.post(issuer_url, data=payload, auth=(client_id, client_secret), verify=False)

    deserialized_iam_response = json.loads(iam_response.text)

    new_access_token = deserialized_iam_response['access_token']

    self.vault_url = vault_url

    self.secrets_root = secrets_root

    login_url = self.vault_url + '/v1/auth/jwt/login'

    data = '{ "jwt": "'+ new_access_token +  '" }'

    response = requests.post(login_url, data=data, verify=False)

    deserialized_response = json.loads(response.text)

    self.vault_auth_token = deserialized_response["auth"]["client_token"]

  #______________________________________
  def get_auth_token(self): return self.vault_auth_token

  #______________________________________
  def get_wrapping_token(self, wrap_ttl, auth_token, policy, ttl, period):
    """
    Get Vault wrapping token with specific policy
    """

    create_url = self.vault_url + '/v1/auth/token/create'

    headers = {
               "X-Vault-Wrap-TTL": wrap_ttl,
               "X-Vault-Token": auth_token
              }

    data = '{ "policies": ["'+policy+'"], "ttl": "'+ttl+'", "period": "'+period+'" }'

    response = requests.post(create_url, headers=headers, data=data, verify=False)

    deserialized_response = json.loads(response.text)

    return deserialized_response["wrap_info"]["token"]

  #______________________________________
  def get_token(self, auth_token, policy, ttl, period):
    """
    Get Vault token with specific policy
    """

    create_url = self.vault_url + '/v1/auth/token/create'

    headers = {
               "X-Vault-Token": auth_token
              }

    data = '{ "policies": ["'+policy+'"], "ttl": "'+ttl+'", "period": "'+period+'" }'

    response = requests.post(create_url, headers=headers, data=data, verify=False)

    deserialized_response = json.loads(response.text)

    return deserialized_response["auth"]["client_token"]

  #______________________________________
  def write_secret(self, token, secret_path, key, value):
    """
    Write Secret to Vault
    """

    write_url = self.vault_url + '/v1/'+self.secrets_root+'/data/' + secret_path

    headers = {
               "X-Vault-Token": token
              }

    data = '{ "options": { "cas": 0 }, "data": { "'+key+'": "'+value+'"} }'

    response = requests.post(write_url, headers=headers, data=data, verify=False)

    deserialized_response = json.loads(response.text)
    print(deserialized_response)
    try:
      deserialized_response["data"]
    except KeyError:
      raise Exception("[FATAL] Unable to write vault path.")

    return deserialized_response


  #______________________________________
  def read_secret(self, token, secret_path, key):
    """
    Read Secret from Vault.
    """

    read_url = self.vault_url + '/v1/'+self.secrets_root+'/data/' + secret_path

    headers = {
               "X-Vault-Token": token
              }

    response = requests.get( read_url, headers=headers, verify=False )

    deserialized_response = json.loads(response.text)

    try:
      deserialized_response["data"]
    except KeyError:
      raise Exception("[FATAL] Unable to read vault path.")

    return deserialized_response["data"]["data"][key]

  #______________________________________
  def delete_secret(self, token, secret_path):
    """
    Permanently delete secret and metadata from Vault.
    """

    delete_url = self.vault_url + '/v1/'+self.secrets_root+'/metadata/' + secret_path

    headers = {
               "X-Vault-Token": token
              }

    response = requests.delete(delete_url, headers=headers, verify=False)

  #______________________________________
  def revoke_token(self, token):
    """
    Revoke (self) token
    """

    revoke_url = self.vault_url + '/v1/auth/token/revoke-self'

    headers = {
               "X-Vault-Token": token
              }

    response = requests.post( revoke_url, headers=headers, verify=False )
