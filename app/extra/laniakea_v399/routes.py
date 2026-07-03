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

from flask import Blueprint, render_template, flash, request, redirect, url_for, session
from app import app, iam_blueprint
from app.lib import auth, dbhelpers, settings
import json
import uuid as uuid_generator
import requests

laniakea_v399_bp = Blueprint('laniakea_v399_bp', __name__, template_folder='templates', static_folder='static')

LANIAKEA_API_URL = settings.laniakeaApiUrl
LANIAKEA_API_VERIFY = False


def _get_laniakea_token(access_token):
    oidc_key = access_token[-16:]
    if session.get('laniakea_jwt') and session.get('laniakea_oidc_key') == oidc_key:
        return session['laniakea_jwt']
    resp = requests.post(
        f"{LANIAKEA_API_URL}/auth/oidc",
        json={"oidc_token": access_token},
        verify=LANIAKEA_API_VERIFY,
        timeout=15,
    )
    if not resp.ok:
        raise Exception(f"Laniakea auth failed ({resp.status_code}): {resp.text}")
    token = resp.json()["session_token"]
    session['laniakea_jwt']      = token
    session['laniakea_oidc_key'] = oidc_key
    return token


def _headers(access_token):
    return {"Authorization": f"Bearer {_get_laniakea_token(access_token)}"}


def _normalize(d):
    outputs = d.get('outputs') or {}
    if isinstance(outputs, str):
        try:
            outputs = json.loads(outputs)
        except Exception:
            outputs = {}
    return {
        'uuid':            d.get('deployment_uuid', ''),
        'status':          d.get('status', 'UNKNOWN'),
        'status_reason':   d.get('status_reason', ''),
        'description':     d.get('description', ''),
        'provider_name':   d.get('selected_provider', ''),
        'creation_time':   d.get('created_at', ''),
        'update_time':     d.get('updated_at', ''),
        'deployment_type': 'CLOUD',
        'locked':          0,
        'updatable':       0,
        'physicalId':      outputs.get('vm_ip', ''),
        'endpoint':        outputs.get('endpoint', outputs.get('vm_ip', '')),
        'outputs':         outputs,
        'requested_by':    d.get('requested_by', ''),
    }


@laniakea_v399_bp.route('/deployments')
@auth.authorized_with_valid_token
def showdeployments():
    access_token = iam_blueprint.session.token['access_token']
    deployments  = []
    try:
        resp = requests.get(
            f"{LANIAKEA_API_URL}/api/deployments",
            headers=_headers(access_token),
            verify=LANIAKEA_API_VERIFY,
            timeout=15,
        )
        resp.raise_for_status()
        payload = resp.json()
        rows = payload.get("deployments", payload) if isinstance(payload, dict) else payload
        deployments = [_normalize(d) for d in rows]
    except Exception as exc:
        flash(f"Error retrieving deployments: {exc}", 'warning')
    return render_template('deployments.html', deployments=deployments)


@laniakea_v399_bp.route('/deployments/<dep_uuid>/log')
@auth.authorized_with_valid_token
def deplog(dep_uuid):
    access_token = iam_blueprint.session.token['access_token']
    try:
        resp = requests.get(
            f"{LANIAKEA_API_URL}/api/deployments/{dep_uuid}/logs",
            params={"tail": 200},
            headers=_headers(access_token),
            verify=LANIAKEA_API_VERIFY,
            timeout=15,
        )
        data = resp.json() if resp.ok else {}
        log  = "\n".join(data.get("lines", [])) if isinstance(data, dict) else str(data)
    except Exception as exc:
        log = f"[error fetching logs: {exc}]"
    return render_template('deplog.html', log=log)


@laniakea_v399_bp.route('/deployments/<dep_uuid>/delete', methods=['POST'])
@auth.authorized_with_valid_token
def depdel(dep_uuid):
    access_token = iam_blueprint.session.token['access_token']
    try:
        requests.delete(
            f"{LANIAKEA_API_URL}/api/deployments/{dep_uuid}",
            headers=_headers(access_token),
            verify=LANIAKEA_API_VERIFY,
            timeout=15,
        )
        flash(f"Deployment {dep_uuid} deletion requested.", 'info')
    except Exception as exc:
        flash(str(exc), 'danger')
    return redirect(url_for('laniakea_v399_bp.showdeployments'))


@laniakea_v399_bp.route('/createdep', methods=['POST'])
@auth.authorized_with_valid_token
def createdep():
    access_token      = iam_blueprint.session.token['access_token']
    form              = request.form.to_dict()
    selected_template = request.args.get('template', '')
    user_sub          = session.get('userid', '')
    user_email        = session.get('email', '')
    username          = session.get('preferred_username', user_sub[:8] if user_sub else 'unknown')
    ssh_pub_key       = dbhelpers.get_ssh_pub_key(user_sub) or ''
    deployment_uuid   = str(uuid_generator.uuid1())

    # Build deployment_info — cloud config comes from form fields
    # The API and agent handle all provider-specific logic
    from datetime import datetime, timezone
    timestamp = datetime.now(timezone.utc).isoformat()

    deployment_info = {
        "deployment_uuid":   deployment_uuid,
        "timestamp":         timestamp,
        "description":       form.get('additional_description', ''),
        "selected_provider": "Openstack",
        "auth": {
            "aai_token": access_token,
            "sub":       user_sub,
            "group":     session.get('active_usergroup', 'default'),
        },
        "orchestrator": {
            "target_provider":      form.get('extra_opts.selectedCloud', 'openstack_recas'),
            "desired_orchestrator": "terraform",
            "endpoint":             "",
        },
        "cloud_providers": {
            "openstack": {
                "os_auth_url":                 form.get('os_auth_url', ''),
                "os_project_id":               form.get('os_project_id', ''),
                "region_name":                 form.get('region_name', 'RegionOne'),
                "endpoint_overrides_network":  form.get('endpoint_overrides_network', ''),
                "endpoint_overrides_volumev3": form.get('endpoint_overrides_volumev3', ''),
                "endpoint_overrides_image":    form.get('endpoint_overrides_image', ''),
                "private_network_proxy_host":  form.get('private_network_proxy_host', ''),
                "ssh_key":                     ssh_pub_key,
                "template": {
                    "url":    "",
                    "path":   form.get('extra_opts.selectedCloud', 'openstack_recas'),
                    "branch": "main",
                },
                "inputs": {
                    "flavor":          form.get('flavor', ''),
                    "image":           form.get('image', ''),
                    "os_distribution": form.get('os_distribution', ''),
                    "os_version":      form.get('os_version', ''),
                    "network_type":    'private' if 'priv' in selected_template else 'public',
                    "open_ports":      json.loads(form.get('open_ports', '[]') or '[]'),
                },
            },
            "aws": {
                "region": "", "bastion_ip": "", "ssh_key": "",
                "aws_access_key": "", "aws_secret_key": "",
                "template": {"url": "", "path": "", "branch": ""},
                "inputs": {
                    "instance_type": "", "image": "", "storage_size": "",
                    "os_distribution": "", "os_version": "", "network_type": "",
                    "open_ports": [{"port": "22", "protocol": "", "cidr": ""}],
                },
            },
        },
        "user_sub":     user_sub,
        "user_email":   user_email,
        "requested_by": username,
    }

    try:
        resp = requests.post(
            f"{LANIAKEA_API_URL}/api/deployments",
            json=deployment_info,
            headers=_headers(access_token),
            verify=LANIAKEA_API_VERIFY,
            timeout=15,
        )
        resp.raise_for_status()
        result = resp.json()
        flash(f"Deployment {deployment_uuid} submitted (job: {result.get('job_id', '?')}).", 'success')
    except Exception as exc:
        flash(f"Error submitting deployment: {exc}", 'danger')

    return redirect(url_for('laniakea_v399_bp.showdeployments'))
