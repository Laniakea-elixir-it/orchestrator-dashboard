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
    html_body = f"""
    <html xmlns="https://www.elixir-italy.org">
        <head>
            <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
            <title></title>
        </head>
        <body>
            <table border="0" cellpadding="0" cellspacing="0" height="100%" width="100%" id="bodyTable">
                <tr>
                    <td align="center" valign="top">
                        <table border="0" cellpadding="20" cellspacing="0" width="600" id="emailContainer">
                            <tr>
                                <td align="center">
                                    <img src="https://raw.githubusercontent.com/Laniakea-elixir-it/resources/master/logos/elixir_italy_white_background.png" width="200" height="150">
                                </td>
                            </tr>
                            <tr>
                                <td valign="top">
                                    Dear User,<br>
                                    This is an automatically generated notification mail.<br>
                                    <strong>YOU DO NOT NEED TO ANSWER THIS MESSAGE</strong>
                                    <p>
                                    You have been invited to access a <strong>Galaxy instance</strong> protected by a VPN.
                                    Please follow the steps below to connect.
                                    </p>

                                    <p><strong>Step 1 — Set your password</strong><br>
                                    Click the link below to login and set your new password:<br>
                                    <a href="{KC_REALM_URL}/account">Set your password</a><br>
                                    Use the following temporary credentials — you will be asked to change the password immediately.<br>
                                    Username: <strong>{invited_user_email}</strong><br>
                                    Temporary password: <strong>{temp_password}</strong>
                                    </p>

                                    <p><strong>Step 2 — Install OpenVPN Connect</strong><br>
                                    Download and install OpenVPN Connect on your computer:<br>
                                    <a href="https://openvpn.net/client/">https://openvpn.net/client/</a>
                                    </p>
    
                                    <p><strong>Step 3 — Import the configuration file</strong><br>
                                    The <strong>.ovpn configuration file</strong> is attached to this email.<br>
                                    Open OpenVPN Connect, click <em>Import Profile</em> and select the attached file.
                                    </p>

                                    <p><strong>Step 4 — Connect and access Galaxy</strong><br>
                                    Once you have imported the profile, follow these steps:
                                    <ol>
                                        <li>Open <strong>OpenVPN Connect</strong> and click <strong>Connect</strong> on the imported profile.</li>
                                        <li>A login screen will appear. Enter your email address (<strong>{invited_user_email}</strong>) as the username, and <em>any word of your choice</em> as the password — <strong>it does not matter what you type there, it will be ignored</strong>.</li>
                                        <li>You will receive an <strong>email with a confirmation link</strong>. Open that email and click the link to authenticate.</li>
                                        <li>⚠️ <strong>Important:</strong> do not close OpenVPN Connect while waiting for the email — keep it open until you have clicked the confirmation link.</li>
                                        <li>Once confirmed, the VPN will connect automatically. Open your browser and go to:<br>
                                        <a href="{galaxy_ip}">{galaxy_ip}</a></li>
                                    </ol>
                                    </p>

                                    <p><strong>Need help?</strong><br>
                                    Full instructions are available here:<br>
                                    <a href="https://laniakea.readthedocs.io/en/latest/user_documentation/galaxy/vpn_deployments.html#openvpn-connect">
                                    Laniakea VPN documentation</a>
                                    </p>
    
                                    <p>Kind Regards,<br>
                                    The Laniakea Team</p>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
        </body>
    </html>
    """

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
        keycloak.delete_user(kc_token, uid)
    except Exception as e:
        app.logger.error(f'Delete user error: {e}')
    return json.dumps({'status': 'ok'}), 200, {'Content-Type': 'application/json'}
