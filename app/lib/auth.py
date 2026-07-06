# Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2019-2020
# Modifications Copyright (c) CNR-IBIOM and ELIXIR-IT. 2024-2026
# Modifications Copyright (c) Riccardo Caccia. 2026
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

from app import app, iam_blueprint, keycloak_blueprint
from flask import redirect, render_template, session, url_for, json
from functools import wraps
import ast
import requests
from . import utils, settings


def active_session():
    """Returns the active OAuth session based on auth provider"""
    if session.get('auth_provider') == 'keycloak':
        return keycloak_blueprint.session
    return iam_blueprint.session

def get_access_token():
    """Returns the access token from the active session"""
    return active_session().token['access_token']

def get_active_idp_url():
    if session.get('auth_provider') == 'keycloak':
        return settings.keycloakUrl
    return settings.iamUrl

def get_active_issuer():
    url = get_active_idp_url()
    return url if url.endswith('/') else url + '/'


def get_active_client_id():
    if session.get('auth_provider') == 'keycloak':
        return settings.keycloakClientID
    return settings.iamClientID


def get_active_client_secret():
    if session.get('auth_provider') == 'keycloak':
        return settings.keycloakClientSecret
    return settings.iamClientSecret


def get_active_groups():
    if session.get('auth_provider') == 'keycloak':
        return settings.keycloakGroups
    return settings.iamGroups


def validate_configuration():
    if not settings.orchestratorConf.get('im_url'):
        app.logger.debug("Trying to (re)load config from Orchestrator: " + json.dumps(settings.orchestratorConf))
        access_token = auth.get_access_token()
        configuration = utils.getorchestratorconfiguration(settings.orchestratorUrl, access_token)
        settings.orchestratorConf = configuration


def get_account_info():
    if keycloak_blueprint.session.authorized:
        session["auth_provider"] = "keycloak"
        return keycloak_blueprint.session.get(keycloak_blueprint.session.base_url.rstrip("/") + "/protocol/openid-connect/userinfo")
    else:
        session["auth_provider"] = "iam"
        return iam_blueprint.session.get("/userinfo")


def set_user_info():
    account_info = get_account_info()
    ###
    if not account_info.ok:
        raise Exception(f"userinfo failed ({account_info.status_code})")
    #account_info = iam_blueprint.session.get('/userinfo')
    account_info_json = account_info.json()
    #user_groups = account_info_json['groups']
    user_groups = account_info_json.get('groups', [])
    session['given_name'] = account_info_json['given_name']        
    session['family_name'] = account_info_json['family_name']
    session['organisation_name'] = account_info_json.get('organisation_name', 'keycloak')

    user_id = account_info_json['sub']

    supported_groups = []
    if get_active_groups():
        supported_groups = list(set(get_active_groups()) & set(user_groups))
        if len(supported_groups) == 0:
            app.logger.warning("The user {} does not belong to any supported user group".format(user_id))

    session['userid'] = user_id
    session['username'] = account_info_json['name']
    session['preferred_username'] = account_info_json['preferred_username']
    session['given_name'] = account_info_json['given_name']
    session['family_name'] = account_info_json['family_name']
    session['useremail'] = account_info_json['email']
    session['userrole'] = 'user'
    session['gravatar'] = utils.avatar(account_info_json['email'], 26)
    #session['organisation_name'] = account_info_json['organisation_name']
    session['usergroups'] = user_groups
    session['supported_usergroups'] = supported_groups
    if 'active_usergroup' not in session:
        session['active_usergroup'] = next(iter(supported_groups), None)

def update_user_info():
    account_info = get_account_info()
    #account_info = iam_blueprint.session.get('/userinfo')
    account_info_json = account_info.json()
    #user_groups = account_info_json['groups']
    user_groups = account_info_json.get('groups', [])
    user_id = account_info_json['sub']

    supported_groups = []
    if get_active_groups():
        supported_groups = list(set(get_active_groups()) & set(user_groups))
        if len(supported_groups) == 0:
            app.logger.warning("The user {} does not belong to any supported user group".format(user_id))

    session['usergroups'] = user_groups
    session['supported_usergroups'] = supported_groups
    if 'active_usergroup' not in session:
        session['active_usergroup'] = next(iter(supported_groups), None)


def authorized_with_valid_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        authorized = iam_blueprint.session.authorized or keycloak_blueprint.session.authorized
        if not authorized or 'username' not in session:
            return redirect(url_for('home_bp.home'))

        if active_session().token['expires_in'] < 60:
            app.logger.debug("Token will expire soon...Refresh token")
            update_user_info()

        return f(*args, **kwargs)
    return decorated_function


#def authorized_with_valid_token(f):
#    @wraps(f)
#    def decorated_function(*args, **kwargs):
#
#        if not iam_blueprint.session.authorized or 'username' not in session:
#            return redirect(url_for('iam.login'))
#
#        if iam_blueprint.session.token['expires_in'] < 60:
#            app.logger.debug("Token will expire soon...Refresh token")
#            update_user_info()
#
#        return f(*args, **kwargs)
#
#    return decorated_function


def only_for_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session['userrole'].lower() == 'admin':
            return render_template(app.config.get('HOME_TEMPLATE'))

        return f(*args, **kwargs)

    return decorated_function


def exchange_token_with_audience(idp_url, client_id, client_secret, access_token, audience):

    active_idp = get_active_issuer()

    if session.get('auth_provider') == 'iam':
        idp_url = idp_url + "/token"
        payload = {
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "audience": audience,
                "subject_token": access_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "scope": "openid email profile offline_access"
                }
    elif session.get('auth_provider') == 'keycloak':
        idp_url = idp_url + "/protocol/openid-connect/token"
        payload = {
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": access_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "scope": "orchestrator-dashboard-audience"
                }
    else:
        raise Exception("Unsupported Identity provider")

    idp_response = requests.post(idp_url, data=payload, auth=(client_id, client_secret), verify=False)

    if not idp_response.ok:
        raise Exception("Error exchanging token: {} - {}".format(idp_response.status_code, idp_response.text))

    deserialized_idp_response = json.loads(idp_response.text)

    return deserialized_idp_response['access_token']
