# Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2019-2020
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

laniakea_utils_bp = Blueprint('laniakea_utils_bp', __name__, template_folder='templates', static_folder='static')

iam_base_url = settings.iamUrl
iam_client_id = settings.iamClientID
iam_client_secret = settings.iamClientSecret

issuer = settings.iamUrl
if not issuer.endswith('/'):
    issuer += '/'

@laniakea_utils_bp.route('/galaxy_startup/<depid>')
@auth.authorized_with_valid_token
def galaxy_startup(depid=None):

    laniakea_utils_port = app.config.get('EXTRA_FEATURE_LANIAKEA_UTILS_PORT')
    laniakea_utils_https = app.config.get('EXTRA_FEATURE_LANIAKEA_UTILS_HTTPS')
    laniakea_utils_galaxy_startup_route = app.config.get('EXTRA_FEATURE_LANIAKEA_UTILS_GALAXY_STARTUP')
    http_prefix = 'https://' if laniakea_utils_https == "yes" else 'http://'

    access_token = iam_blueprint.session.token['access_token']

    # retrieve deployment from DB
    dep = dbhelpers.get_deployment(depid)
    if dep == {}:
        return redirect(url_for('home_bp.home'))
    else:


        outputs_dict = json.loads(dep.outputs)

        payload = {
                "endpoint": outputs_dict['endpoint']
               }

        if 'node_ip' in outputs_dict:
            galaxy_startup = http_prefix + outputs_dict['node_ip'] + ':' + laniakea_utils_port + laniakea_utils_galaxy_startup_route
        else:
            return 'unavailable'

        header = {'Content-Type': 'application/json',
                  'Authorization': "Bearer {}".format(access_token)}

        response = requests.post(galaxy_startup, json=payload, headers=header, verify=False)

        deserialized_response = json.loads(response.text)

        return deserialized_response['galaxy']

@laniakea_utils_bp.route('/is_online/<depid>')
@auth.authorized_with_valid_token
def is_online(depid=None):
    # retrieve deployment from DB
    dep = dbhelpers.get_deployment(depid)
    if dep == {}:
        return redirect(url_for('home_bp.home'))
    else:

        outputs_dict = json.loads(dep.outputs)

        if 'endpoint' in outputs_dict:
            endpoint = outputs_dict['endpoint'] + '/'
            try:
              response = requests.get(endpoint, verify=False)
            except:
              return 'unavailable'

            return str(response.status_code)

        else:
            return 'unavailable'
