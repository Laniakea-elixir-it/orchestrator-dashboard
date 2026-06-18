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

from app import app, iam_blueprint, keycloak_blueprint
import requests

IAM_CLIENT_ID     = app.config['IAM_CLIENT_ID']
IAM_CLIENT_SECRET = app.config['IAM_CLIENT_SECRET']
IAM_TOKEN_URL     = app.config['IAM_BASE_URL'] + '/token'

KC_BASE_URL       = app.config['KEYCLOAK_BASE_URL']
KC_CLIENT_ID      = app.config['KEYCLOAK_CLIENT_ID']
KC_CLIENT_SECRET  = app.config['KEYCLOAK_CLIENT_SECRET']
KC_REALM_URL      = KC_BASE_URL  # es. https://keycloak.usegalaxy.it/realms/laniakea
KC_ADMIN_URL      = KC_BASE_URL.replace('/realms/', '/admin/realms/')  # https://keycloak.usegalaxy.it/admin/realms/laniakea
KC_TOKEN_URL      = app.config['KEYCLOAK_BASE_URL'] + '/protocol/openid-connect/token'


def exchange_iam_token():
    """Exchange the IAM token
       with one with valid audience
       the audience is the client_id of the keycloak client
       WARNING!!! it works only if you use the realm url!!!"""

    iam_access_token = iam_blueprint.session.token['access_token']

    r = requests.post(
        IAM_TOKEN_URL,
        auth=(IAM_CLIENT_ID, IAM_CLIENT_SECRET),
        data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
            'audience': KC_REALM_URL,
            'subject_token': iam_access_token,
            'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
            'scope': 'openid profile email offline_access',
        }
    )
    r.raise_for_status()
    return r.json()['access_token']

def get_keycloak_token(iam_token_with_aud):
    """Step 2: exchange IAM token con audience -> Keycloak admin token"""
    r = requests.post(
        KC_TOKEN_URL,
        data={
            'client_id': KC_CLIENT_ID,
            'client_secret': KC_CLIENT_SECRET,
            'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion': iam_token_with_aud,
        }
    )
    app.logger.debug(f'KC token exchange status: {r.status_code}')
    app.logger.debug(f'KC token exchange response: {r.text}')
    r.raise_for_status()
    return r.json()['access_token']

def create_group(kc_token, group_name):
    """Create vpn_<depid> group on Keycloak, ignore if it already exists (409)."""
    r = requests.post(
        f'{KC_ADMIN_URL}/groups',
        headers={'Authorization': f'Bearer {kc_token}', 'Content-Type': 'application/json'},
        json={'name': group_name}
    )
    app.logger.debug(f'Create group status: {r.status_code} - {r.text}')
    if r.status_code not in (201, 409):
        r.raise_for_status()


def create_user(kc_token, email, group_name, user_group=None):
    import secrets
    import string

    temp_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))

    groups = [f'/{group_name}']
    if user_group:
        groups.append(f'/{user_group}')

    r = requests.post(
        f'{KC_ADMIN_URL}/users',
        headers={'Authorization': f'Bearer {kc_token}', 'Content-Type': 'application/json'},
        json={
            'username': email,
            'email': email,
            'enabled': True,
            'emailVerified': True,
            'groups': groups,
            'credentials': [{'type': 'password', 'value': temp_password, 'temporary': True}],
            'requiredActions': ['UPDATE_PASSWORD'],
        }
    )
    app.logger.debug(f'Create user status: {r.status_code} - {r.text}')

    if r.status_code == 409:
        # User already exists — get user id and add to group
        app.logger.debug(f'User {email} already exists, adding to group {group_name}')
        temp_password = None        

        r2 = requests.get(
            f'{KC_ADMIN_URL}/users',
            headers={'Authorization': f'Bearer {kc_token}'},
            params={'email': email, 'exact': 'true'}
        )
        r2.raise_for_status()
        users = r2.json()
        if not users:
            raise ValueError(f'User {email} not found on Keycloak')

        user_id = users[0]['id']

        # Get group id and add user
        group = _get_group(kc_token, group_name)
        if group:
            requests.put(
                f'{KC_ADMIN_URL}/users/{user_id}/groups/{group["id"]}',
                headers={'Authorization': f'Bearer {kc_token}'}
            ).raise_for_status()

        return temp_password

    r.raise_for_status()
    return temp_password


def get_group_users(kc_token, group_name):
    """Retrieve users from the vpn_<depid> group in Keycloak"""

    group = _get_group(kc_token, group_name)
    if not group:
        return []

    group_id = group['id']

    # Get group users
    r = requests.get(
        f'{KC_ADMIN_URL}/groups/{group_id}/members',
        headers={'Authorization': f'Bearer {kc_token}'}
    )
    r.raise_for_status()
    return r.json()


def _get_group(kc_token, group_name):
    """Get group dict by exact name, returns None if not found."""

    # Get group id from group name
    r = requests.get(
        f'{KC_ADMIN_URL}/groups',
        headers={'Authorization': f'Bearer {kc_token}'},
        params={'search': group_name}
    )
    r.raise_for_status()
    groups = r.json()
    return next((g for g in groups if g['name'] == group_name), None)


def activate_user(kc_token, user_id):
    r = requests.put(
        f'{KC_ADMIN_URL}/users/{user_id}',
        headers={'Authorization': f'Bearer {kc_token}', 'Content-Type': 'application/json'},
        json={'enabled': True}
    )
    r.raise_for_status()


def deactivate_user(kc_token, user_id):
    r = requests.put(
        f'{KC_ADMIN_URL}/users/{user_id}',
        headers={'Authorization': f'Bearer {kc_token}', 'Content-Type': 'application/json'},
        json={'enabled': False}
    )
    r.raise_for_status()


def delete_user(kc_token, group_name, user_id):
    """
    Delete the user only if it is in the deployment group.
    Otherwise it is just removed from the group.
    """

    # Get current group
    group = _get_group(kc_token, group_name)
    if not group:
        return []
    group_id = group['id']

    # Get all groups of this user
    r = requests.get(
        f'{KC_ADMIN_URL}/users/{user_id}/groups',
        headers={'Authorization': f'Bearer {kc_token}'}
    )
    r.raise_for_status()
    user_groups = r.json()

    # Check if user belongs to any other vpn_ group
    other_vpn_groups = [
        g for g in user_groups
        if g['name'].startswith('vpn_') and g['name'] != group_name
    ]

    if other_vpn_groups:
        app.logger.debug(
            f'User {user_id} belongs to other VPN groups '
            f'{[g["name"] for g in other_vpn_groups]}, removing from group only'
        )
        # Remove user from group only, don't delete
        requests.delete(
            f'{KC_ADMIN_URL}/users/{user_id}/groups/{group_id}',
            headers={'Authorization': f'Bearer {kc_token}'}
        ).raise_for_status()
        return
    
    # No other vpn_ group — delete user entirely
    app.logger.debug(f'Deleting user {user["username"]} (no other VPN groups)')
    requests.delete(
        f'{KC_ADMIN_URL}/users/{user_id}',
        headers={'Authorization': f'Bearer {kc_token}'}
    ).raise_for_status()


def delete_group_and_orphan_users(kc_token, group_name):
    """
    Delete all users in group_name that don't belong to any other vpn_ group,
    then delete the group itself.
    """

    group = _get_group(kc_token, group_name)
    if not group:
        app.logger.warning(f'Group {group_name} not found on Keycloak')
        return
    group_id = group['id']

    members = get_group_users(kc_token, group_name)
    for user in members:
        user_id = user['id']

        # Get all groups of this user
        r = requests.get(
            f'{KC_ADMIN_URL}/users/{user_id}/groups',
            headers={'Authorization': f'Bearer {kc_token}'}
        )
        r.raise_for_status()
        user_groups = r.json()

        # Check if user belongs to any other vpn_ group
        other_vpn_groups = [
            g for g in user_groups
            if g['name'].startswith('vpn_') and g['name'] != group_name
        ]

        if other_vpn_groups:
            app.logger.debug(f'User {user["username"]} belongs to other VPN groups {[g["name"] for g in other_vpn_groups]}, skipping')
            continue

        # No other vpn_ group, delete user
        app.logger.debug(f'Deleting user {user["username"]} (no other VPN groups)')
        requests.delete(
            f'{KC_ADMIN_URL}/users/{user_id}',
            headers={'Authorization': f'Bearer {kc_token}'}
        ).raise_for_status()

    # Delete the group
    requests.delete(
        f'{KC_ADMIN_URL}/groups/{group_id}',
        headers={'Authorization': f'Bearer {kc_token}'}
    ).raise_for_status()
    app.logger.debug(f'Group {group_name} deleted')
