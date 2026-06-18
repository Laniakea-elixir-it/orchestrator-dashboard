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
from app.lib import auth, utils, sshkey as sshkeyhelpers, settings, dbhelpers, keycloak
from app.providers import sla
from app.models.Deployment import Deployment
from app.models.User import User
import json
import requests

from app.lib.keycloak import KC_REALM_URL

laniakea_nebula_bp = Blueprint('laniakea_nebula_bp', __name__, template_folder='templates', static_folder='static')

# HERE WE NEED THE LOGIC TO CALL THE REAL OIDC PROVIDER.
# THE BEST WOULD BE LOADING ONLY THE BLUEPRINT THROUGH A FUNCTION

iam_base_url = settings.iamUrl
iam_client_id = settings.iamClientID
iam_client_secret = settings.iamClientSecret

issuer = settings.iamUrl
if not issuer.endswith('/'):
    issuer += '/'


@laniakea_nebula_bp.route('/laniakea_nebula/<depid>/invite', methods=['POST'])
@auth.authorized_with_valid_token
def invite(depid=None):

    invited_user_email = request.form.get('email', '').strip()

    dep = dbhelpers.get_deployment(depid)

    # Get ovpn file
    outputs = json.loads(dep.outputs.strip('\"')) if dep.outputs else {}
    vpn_conf_filename = outputs.get('vpn_client_conf_url', '')

    # Get Galaxy endpoint
    galaxy_ip = outputs.get('endpoint', outputs.get('node_ip', 'N/A'))

    # Get ovpn file from Vault
    vault_bound_audience = app.config.get('VAULT_BOUND_AUDIENCE')
    vault_mountpoint_kv2 = app.config.get('VAULT_MOUNTPOINT_KV2')
    vault_role = app.config.get("VAULT_ROLE")
    vault_read_policy = app.config.get("READ_POLICY")
    vault_read_token_time_duration = app.config.get("READ_TOKEN_TIME_DURATION")
    vault_read_token_renewal_duration = app.config.get("READ_TOKEN_RENEWAL_TIME_DURATION")

    access_token = iam_blueprint.session.token['access_token']
    jwt_token = auth.exchange_token_with_audience(iam_base_url, iam_client_id, iam_client_secret, access_token, vault_bound_audience)
    vault_client = vaultservice.connect(jwt_token, vault_role)
    read_token = vault_client.get_token(vault_read_policy, vault_read_token_time_duration, vault_read_token_renewal_duration)

    try:
        import base64
        ovpn_content = base64.b64decode(
            vault_client.read_secret(read_token, f'vpn/{vpn_conf_filename}', 'vpnconfile')
        ).decode('utf-8')
    except Exception as e:
        app.logger.warning(f'Error retrieving ovpn file: {e}')
        ovpn_content = None
    finally:
        vault_client.revoke_token()

    # Get tenant group
    user_group = session.get('active_usergroup', '')

    # Keycloak
    iam_token_with_aud = keycloak.exchange_iam_token()
    kc_token = keycloak.get_keycloak_token(iam_token_with_aud)
    group_name = f'vpn_{depid}'
    keycloak.create_group(kc_token, group_name)
    temp_password = keycloak.create_user(kc_token, invited_user_email, group_name, user_group)

    # Build email
    html_body = render_template(
        'vpn_invite_email_galaxy.html',
        invited_user_email=invited_user_email,
        temp_password=temp_password,
        kc_realm_url=KC_REALM_URL,
        galaxy_ip=galaxy_ip
    )

    # Send email with ovpn attachment
    utils.send_email_with_attachment(
        subject="[Laniakea] You have been invited to a VPN-protected Galaxy",
        sender=app.config.get('MAIL_SENDER'),
        recipients=[invited_user_email],
        html_body=html_body,
        attachment_filename=vpn_conf_filename,
        attachment_data=ovpn_content.encode('utf-8') if ovpn_content else None
    )

    return redirect(request.referrer)


@laniakea_nebula_bp.route('/laniakea_nebula/<depid>/users', methods=['GET'])
@auth.authorized_with_valid_token
def get_vpn_users(depid=None):
    try:
        iam_token_with_aud = keycloak.exchange_iam_token()
        kc_token = keycloak.get_keycloak_token(iam_token_with_aud)
        users = keycloak.get_group_users(kc_token, f'vpn_{depid}')
        return json.dumps([{
            'id': u.get('id'),
            'username': u.get('username'),
            'email': u.get('email'),
            'enabled': u.get('enabled')
        } for u in users])
    except Exception as e:
        app.logger.error(f'Get VPN users error: {e}')
        return json.dumps([])


@laniakea_nebula_bp.route('/laniakea_nebula/<depid>/users/<uid>/activate', methods=['POST'])
@auth.authorized_with_valid_token
def activate_vpn_user(depid=None, uid=None):
    try:
        iam_token_with_aud = keycloak.exchange_iam_token()
        kc_token = keycloak.get_keycloak_token(iam_token_with_aud)
        keycloak.activate_user(kc_token, uid)
    except Exception as e:
        app.logger.error(f'Activate user error: {e}')
    return json.dumps({'status': 'ok'}), 200, {'Content-Type': 'application/json'}


@laniakea_nebula_bp.route('/laniakea_nebula/<depid>/users/<uid>/deactivate', methods=['POST'])
@auth.authorized_with_valid_token
def deactivate_vpn_user(depid=None, uid=None):
    try:
        iam_token_with_aud = keycloak.exchange_iam_token()
        kc_token = keycloak.get_keycloak_token(iam_token_with_aud)
        keycloak.deactivate_user(kc_token, uid)
    except Exception as e:
        app.logger.error(f'Deactivate user error: {e}')
    return json.dumps({'status': 'ok'}), 200, {'Content-Type': 'application/json'}


@laniakea_nebula_bp.route('/laniakea_nebula/<depid>/users/<uid>/delete', methods=['POST'])
@auth.authorized_with_valid_token
def delete_vpn_user(depid=None, uid=None):
    try:
        iam_token_with_aud = keycloak.exchange_iam_token()
        kc_token = keycloak.get_keycloak_token(iam_token_with_aud)
        group_name = f'vpn_{depid}'
        keycloak.delete_user(kc_token, group_name, uid)
    except Exception as e:
        app.logger.error(f'Delete user error: {e}')
    return json.dumps({'status': 'ok'}), 200, {'Content-Type': 'application/json'}
