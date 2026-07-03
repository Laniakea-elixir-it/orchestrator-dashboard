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

from flask import Blueprint, session, render_template, flash, request
from app.lib import auth, dbhelpers, settings
from app.models.User import User
from app import app, iam_blueprint
import requests


users_bp = Blueprint('users_bp', __name__, template_folder='templates', static_folder='static')


@users_bp.route('/')
@auth.authorized_with_valid_token
@auth.only_for_admin
def show_users():

    users = dbhelpers.get_users()
    return render_template('users.html', users=users)


@users_bp.route('/<subject>', methods=['GET', 'POST'])
@auth.authorized_with_valid_token
@auth.only_for_admin
def show_user(subject):

    if request.method == 'POST':

        # cannot change its own role
        if session['userid'] == subject:
            role = session['userrole']
        else:
            role = request.form['role']
        active = request.form['active']
        # update database
        dbhelpers.update_user(subject, dict(role=role, active=active))

    user = dbhelpers.get_user(subject)
    if user is not None:
        return render_template('user.html', user=user)
    else:
        return render_template(app.config.get('HOME_TEMPLATE'))


@users_bp.route('/<subject>/deployments')
@auth.authorized_with_valid_token
@auth.only_for_admin
def show_deployments(subject):

    issuer = settings.iamUrl
    if not issuer.endswith('/'):
        issuer += '/'

    user = dbhelpers.get_user(subject)

    if user is not None:
        #
        # retrieve deployments from orchestrator
        access_token = auth.get_access_token()

        headers = {'Authorization': 'bearer %s' % access_token}

        url = settings.orchestratorUrl + "/deployments?createdBy={}&page={}&size={}".format(
            '{}@{}'.format(subject, issuer), 0, 999999)
        response = requests.get(url, headers=headers)

        iids = []
        if response.ok:
            deporch = response.json()["content"]
            iids = dbhelpers.updatedeploymentsstatus(deporch, subject)['iids']

        #
        # retrieve deployments from DB
        deployments = dbhelpers.cvdeployments(dbhelpers.get_user_deployments(user.sub))
        for dep in deployments:
            newremote = dep.remote
            if dep.uuid not in iids:
                if dep.remote == 1:
                    newremote = 0
            else:
                if dep.remote == 0:
                    newremote = 1
            if dep.remote != newremote:
                dbhelpers.update_deployment(dep.uuid, dict(remote=newremote))

        return render_template('dep_user.html', user=user, deployments=deployments)
    else:
        flash("User not found!", 'warning')
        users = User.get_users()
        return render_template('users.html', users=users)
