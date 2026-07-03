# Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2019-2020
# Copyright (c) CNR-IBIOM and ELIXIR-IT. 2026
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from flask import Blueprint, render_template, flash, request, redirect, url_for, session, json
from app import app, iam_blueprint, vaultservice
from app.lib import auth, sshkey as sshkeyhelpers, settings, dbhelpers
from app.providers import sla
from app.models.Deployment import Deployment
from app.models.User import User
import json
import requests

luks_api_bp = Blueprint('luks_api_bp', __name__, template_folder='templates', static_folder='static')

iam_base_url = settings.iamUrl
iam_client_id = settings.iamClientID
iam_client_secret = settings.iamClientSecret

issuer = settings.iamUrl
if not issuer.endswith('/'):
    issuer += '/'

@luks_api_bp.route('/encrypted_volume_status/<depid>')
@auth.authorized_with_valid_token
def encrypted_volume_status(depid=None):

    lusk_api_port = app.config.get('EXTRA_FEATURE_LUKS_API_PORT')
    luks_api_https = app.config.get('EXTRA_FEATURE_LUKS_API_HTTPS')
    luks_api_status_route = app.config.get('EXTRA_FEATURE_LUKS_API_STATUS')
    api_status = 'https://' if luks_api_https == "yes" else 'http://'

    # retrieve deployment from DB
    dep = dbhelpers.get_deployment(depid)
    outputs_dict = json.loads(dep.outputs)
    if dep is None:
        return redirect(url_for('home_bp.home'))
    else:

        if 'node_ip' in outputs_dict:
            api_status = api_status + outputs_dict['node_ip'] + ':' + lusk_api_port + luks_api_status_route
            app.logger.debug(f'URL used to communicate with the API: {api_status}')
        else:
            return 'unavailable'

        try:
            response = requests.get(api_status, verify=False)
        except:
            return 'unavailable'

        deserialized_response = json.loads(response.text)
        return deserialized_response['volume_state']


@luks_api_bp.route('/encrypted_volume_open/<depid>')
@auth.authorized_with_valid_token
def encrypted_volume_open(depid=None):

    vault_url = app.config.get('VAULT_URL')
    vault_role = app.config.get("VAULT_ROLE")
    vault_bound_audience = app.config.get('VAULT_BOUND_AUDIENCE')
    vault_secrets_path = app.config.get("VAULT_SECRETS_PATH")
    vault_wrapping_token_time_duration = app.config.get("WRAPPING_TOKEN_TIME_DURATION")
    vault_read_policy = app.config.get("READ_POLICY")
    vault_read_token_time_duration = app.config.get("READ_TOKEN_TIME_DURATION")
    vault_read_token_renewal_time_duration = app.config.get("READ_TOKEN_RENEWAL_TIME_DURATION")

    lusk_api_port = app.config.get('EXTRA_FEATURE_LUKS_API_PORT')
    luks_api_https = app.config.get('EXTRA_FEATURE_LUKS_API_HTTPS')
    luks_api_open_route = app.config.get('EXTRA_FEATURE_LUKS_API_OPEN')
    api_open = 'https://' if luks_api_https == "yes" else 'http://'

    access_token = auth.get_access_token()

    # retrieve deployment from DB
    dep = dbhelpers.get_deployment(depid)
    if dep == {}:
        return redirect(url_for('home_bp.home'))
    else:
 
        jwt_token = auth.exchange_token_with_audience(iam_base_url,
                                                      iam_client_id,
                                                      iam_client_secret,
                                                      access_token,
                                                      vault_bound_audience)

        vault_client = vaultservice.connect(jwt_token, vault_role)

        wrapping_read_token = vault_client.get_wrapping_token(vault_wrapping_token_time_duration,
                                                              vault_read_policy,
                                                              vault_read_token_time_duration,
                                                              vault_read_token_renewal_time_duration)
  
        # retrieval of secret_path and secret_key from the db goes here
        secret_path = session['userid'] + "/" + dep.vault_secret_uuid + '/storage_encryption'
        inputs = json.loads(dep.inputs) # this is taken from tosca template and not tosca parameter. Tosca template and parameter should match.
        user_key = inputs['vault_encryption_key']

        payload = {
                "vault_url": vault_url,
                "vault_token": wrapping_read_token,
                "secret_root": vault_secrets_path,
                "secret_path": secret_path,
                "secret_key": user_key
               }
 
        outputs_dict = json.loads(dep.outputs)
        if 'node_ip' in outputs_dict:
            api_open = api_open + outputs_dict['node_ip'] + ':' + lusk_api_port + luks_api_open_route
        else:
            return 'unavailable'
  
        response = requests.post(api_open, json=payload, verify=False)

        deserialized_response = json.loads(response.text)

        return deserialized_response['volume_state']
