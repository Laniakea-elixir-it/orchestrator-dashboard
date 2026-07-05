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
import os
import uuid as uuid_generator
import requests
import re

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
        # DB column names first
        'uuid':            d.get('uuid') or d.get('deployment_uuid', ''),
        'status':          d.get('status', 'UNKNOWN'),
        'status_reason':   d.get('status_reason', ''),
        'description':     d.get('description', ''),
        'provider_name':   d.get('provider_name') or d.get('selected_provider', ''),
        'creation_time':   d.get('creation_time') or d.get('created_at', ''),
        'update_time':     d.get('update_time') or d.get('updated_at', ''),
        'deployment_type': 'CLOUD',
        'locked':          0,
        'updatable':       0,
        'physicalId':      outputs.get('vm_ip', ''),
        'endpoint':        d.get('endpoint') or outputs.get('endpoint', outputs.get('vm_ip', '')),
        'outputs':         outputs,
        'requested_by':    d.get('sub', '')[:8],
    }

def _parse_ports(form):
    """
    Translate the legacy ports widget (hidden input name='ports') into the
    open_ports format used by the agent. SSH (22) is always included.
    Supports single ports ("80") and ranges ("[8080,8082]").
    """
    out = [{"port": 22, "protocol": "tcp", "cidr": "0.0.0.0/0"}]
    raw = form.get('ports') or form.get('open_ports') or ''
    if not raw:
        return out
    try:
        items = json.loads(raw)
        if isinstance(items, dict):
            items = list(items.values())
    except Exception:
        return out
    for it in items:
        src   = str(it.get('source', '')).strip()
        proto = (it.get('protocol') or 'tcp').lower()
        cidr  = (it.get('remote_cidr') or '0.0.0.0/0').strip()
        m = re.match(r'^\[(\d+)\s*,\s*(\d+)\]$', src)
        if m:
            out.append({"port": int(m.group(1)), "port_max": int(m.group(2)),
                        "protocol": proto, "cidr": cidr})
        elif src.isdigit():
            out.append({"port": int(src), "protocol": proto, "cidr": cidr})
    return out


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


@laniakea_v399_bp.route('/deployments/<dep_uuid>/delete', methods=['GET', 'POST'])
@auth.authorized_with_valid_token
def depdel(dep_uuid):
    access_token = iam_blueprint.session.token['access_token']
    try:
        resp = requests.delete(
            f"{LANIAKEA_API_URL}/api/deployments/{dep_uuid}",
            headers=_headers(access_token),
            json={"aai_token": access_token,
                  "group": session.get('active_usergroup', 'default')},
            verify=LANIAKEA_API_VERIFY,
            timeout=15,
        )
        if resp.ok:
            data = resp.json()
            if data.get("destroy_enqueued"):
                flash(f"Destroy of {dep_uuid} started: resources are being removed.", 'info')
            else:
                flash(f"Deployment {dep_uuid} removed.", 'success')
        else:
            detail = resp.json().get('detail', f'HTTP {resp.status_code}')
            flash(f"Delete failed: {detail}", 'warning')
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
    user_email        = session.get('useremail', '')
    username          = session.get('preferred_username', user_sub[:8] if user_sub else 'unknown')
    ssh_pub_key       = dbhelpers.get_ssh_pub_key(user_sub) or ''
    deployment_uuid   = str(uuid_generator.uuid1())

    from datetime import datetime, timezone
    timestamp = datetime.now(timezone.utc).isoformat()

    # Target cloud selected by the user in the form
    target_cloud = form.get('extra_opts.selectedCloud', 'openstack_recas').lower()

    # Load per-cloud config template (auth_url, project_id, endpoints, maps)
    clouds_dir = app.config.get('LANIAKEA_CLOUDS_DIR', '/etc/orchestrator-dashboard/settings/laniakea-clouds')
    cloud_cfg_path = os.path.join(clouds_dir, f"{target_cloud}.json")
    try:
        with open(cloud_cfg_path) as cf:
            cloud = json.load(cf)
    except Exception as exc:
        flash(f"Cloud config not found for '{target_cloud}': {exc}", 'danger')
        return redirect(url_for('laniakea_v399_bp.showdeployments'))

    # Map form fields -> flavor / image using the maps in the cloud config.
    # Keys are normalized (trimmed, collapsed whitespace, lowercased) on both
    # sides so cosmetic differences between form values and JSON keys don't break the match.
    def _norm(s: str) -> str:
        return " ".join(str(s).split()).lower()

    flavor_map = { _norm(k): v for k, v in cloud.get('flavor_map', {}).items() }
    image_map  = { _norm(k): v for k, v in cloud.get('image_map', {}).items() }

    flavor_key = _norm(f"{form.get('num_cpus', '')}|{form.get('mem_size', '')}")
    image_key  = _norm(f"{form.get('os_distribution', '')}|{form.get('os_version', '')}")
    flavor     = flavor_map.get(flavor_key, '')
    image      = image_map.get(image_key, '')

    if not flavor or not image:
        flash(f"Cannot map flavor ({flavor_key!r}, available: {list(flavor_map.keys())}) "
              f"or image ({image_key!r}, available: {list(image_map.keys())}) "
              f"for {target_cloud}. Check {cloud_cfg_path}.", 'danger')
        return redirect(url_for('laniakea_v399_bp.showdeployments'))

    network_type = 'private' if 'priv' in selected_template else 'public'

    service_type = 'galaxy' if 'galaxy' in selected_template.lower() else 'vm'

    is_aws            = cloud.get('provider', '') == 'aws' or target_cloud == 'aws'
    selected_provider = "AWS" if is_aws else "Openstack"

    openstack_block = {
        "os_auth_url": "", "os_project_id": "", "region_name": "",
        "private_net_name": "", "public_net_name": "",
        "endpoint_overrides_network": "", "endpoint_overrides_volumev3": "",
        "endpoint_overrides_image": "", "private_network_proxy_host": "",
        "ssh_key": "",
        "template": {"url": "", "path": "", "branch": ""},
        "inputs": {
            "flavor": "", "image": "", "os_distribution": "", "os_version": "",
            "storage_size": "", "network_type": "",
            "open_ports": [{"port": 22, "protocol": "tcp", "cidr": "0.0.0.0/0"}],
        },
    }
    aws_block = {
        "region": "", "bastion_ip": "", "ssh_key": "",
        "aws_access_key": "", "aws_secret_key": "",
        "template": {"url": "", "path": "", "branch": ""},
        "inputs": {
            "instance_type": "", "image": "", "storage_size": "",
            "os_distribution": "", "os_version": "", "network_type": "",
            "open_ports": [{"port": "22", "protocol": "", "cidr": ""}],
        },
    }

    if is_aws:
        aws_block = {
            "region":         cloud.get('region', ''),
            "bastion_ip":     cloud.get('bastion_ip', ''),
            "ssh_key":        ssh_pub_key,
            "aws_access_key": "",
            "aws_secret_key": "",
            "template":       cloud.get('template', {"url": "", "path": "aws", "branch": "main"}),
            "inputs": {
                "instance_type":   flavor,
                "hostname":        form.get('hostname', 'LANIAKEA-vm01'),
                "image":           image,
                "storage_size":    form.get('storage_size', ''),
                "os_distribution": form.get('os_distribution', ''),
                "os_version":      form.get('os_version', ''),
                "network_type":    network_type,
                "open_ports":      _parse_ports(form),
                #"open_ports":      json.loads(form.get('open_ports', '[]') or '[]'),
            },
        }
    else:
        openstack_block = {
            "os_auth_url":                 cloud.get('os_auth_url', ''),
            "os_project_id":               cloud.get('os_project_id', ''),
            "region_name":                 cloud.get('region_name', 'RegionOne'),
            "private_net_name":            cloud.get('private_net_name', ''),
            "public_net_name":             cloud.get('public_net_name', ''),
            "endpoint_overrides_network":  cloud.get('endpoint_overrides_network', ''),
            "endpoint_overrides_volumev3": cloud.get('endpoint_overrides_volumev3', ''),
            "endpoint_overrides_image":    cloud.get('endpoint_overrides_image', ''),
            "private_network_proxy_host":  cloud.get('private_network_proxy_host', ''),
            "ssh_key":                     ssh_pub_key,
            "template":                    cloud.get('template', {"url": "", "path": target_cloud, "branch": "main"}),
            "inputs": {
                "flavor":          flavor,
                "hostname":        form.get('hostname', 'LANIAKEA-vm01'),
                "image":           image,
                "os_distribution": form.get('os_distribution', ''),
                "os_version":      form.get('os_version', ''),
                "storage_size":    form.get('storage_size', ''),
                "network_type":    network_type,
                "open_ports":      _parse_ports(form),
                #"open_ports":      json.loads(form.get('open_ports', '[]') or '[]'),
            },
        }

    deployment_info = {
        "deployment_uuid":   deployment_uuid,
        "timestamp":         timestamp,
        "description":       form.get('additional_description', ''),
        "service_type": service_type,
        "selected_provider": selected_provider,
        "auth": {
            "aai_token": access_token,
            "sub":       user_sub,
            "group":     session.get('active_usergroup', 'default'),
        },
        "orchestrator": {
            "target_provider":      target_cloud,
            "desired_orchestrator": "terraform",
            "endpoint":             "",
        },
        "cloud_providers": {
            "openstack": openstack_block,
            "aws":       aws_block,
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

