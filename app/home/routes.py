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

from .. import app, iam_blueprint, keycloak_blueprint, tosca, redis_client
from app.lib import utils, auth, settings, dbhelpers, openstack
from app.models.User import User
from datetime import datetime
from markupsafe import Markup
from flask import Blueprint, json, render_template, request, redirect, url_for, session, make_response, flash
import re, json

app.jinja_env.filters['tojson_pretty'] = utils.to_pretty_json
app.jinja_env.filters['extract_netinterface_ips'] = utils.extract_netinterface_ips
app.jinja_env.filters['intersect'] = utils.intersect
app.jinja_env.filters['python_eval'] = utils.python_eval

home_bp = Blueprint('home_bp', __name__, template_folder='templates', static_folder='static')


@home_bp.route('/settings')
@auth.authorized_with_valid_token
def show_settings():
    dashboard_last_conf = redis_client.get('last_configuration_info')
    last_settings = json.loads(dashboard_last_conf) if dashboard_last_conf else {}
    return render_template('settings.html',
                           iam_url=settings.iamUrl,
                           orchestrator_url=settings.orchestratorUrl,
                           orchestrator_conf=settings.orchestratorConf,
                           vault_url=app.config.get('VAULT_URL'),
                           tosca_settings=last_settings)


@home_bp.route('/setsettings', methods=['POST'])
@auth.authorized_with_valid_token
def submit_settings():
    if request.method == 'POST' and session['userrole'].lower() == 'admin':

        message1 = ''
        message2 = ''

        repo_url = request.form.get('tosca_templates_url')
        tag_or_branch = request.form.get('tosca_templates_tag_or_branch')

        private = request.form.get('tosca_templates_private') == 'on'
        username = request.form.get('tosca_templates_username')
        deploy_token = request.form.get('tosca_templates_token')

        serialised_value = redis_client.get("last_configuration_info")
        dashboard_configuration_info = json.loads(serialised_value) if serialised_value else {}

        if repo_url:
            app.logger.debug("Cloning TOSCA templates")
            ret, message1 = utils.download_git_repo(repo_url, settings.toscaDir, tag_or_branch,
                                                    private, username, deploy_token)
            flash(message1, "success" if ret else "danger")

            if ret:
                if repo_url: dashboard_configuration_info['tosca_templates_url'] = repo_url
                if tag_or_branch: dashboard_configuration_info['tosca_templates_tag_or_branch'] = tag_or_branch

        repo_url = request.form.get('dashboard_configuration_url')
        tag_or_branch = request.form.get('dashboard_configuration_tag_or_branch')

        private = request.form.get('dashboard_configuration_private') == 'on'
        username = request.form.get('dashboard_configuration_username')
        deploy_token = request.form.get('dashboard_configuration_token')

        if repo_url:
            app.logger.debug("Cloning dashboard configuration")
            ret, message2 = utils.download_git_repo(repo_url, settings.settingsDir, tag_or_branch,
                                                    private, username, deploy_token)
            flash(message2, "success" if ret else "danger")
            if ret:
                if repo_url: dashboard_configuration_info['dashboard_configuration_url'] = repo_url
                if tag_or_branch: dashboard_configuration_info['dashboard_configuration_tag_or_branch'] = tag_or_branch

        try:
            tosca.reload()
        except Exception as error:
            app.logger.error(f"Error reloading configuration: {error}")
            flash(f"Error reloading configuration: { type(error).__name__ }. Please check the logs.", "danger")

        app.logger.debug("Configuration reloaded")

        now = datetime.now()
        dashboard_configuration_info['updated_at'] = now.strftime("%d/%m/%Y %H:%M:%S")
        redis_client.set('last_configuration_info', json.dumps(dashboard_configuration_info))

        if message1 or message2:
            comment = request.form.get('message')
            message = Markup(
                "{} has requested the update of the dashboard configuration: "
                "<br><br>{} <br>{} <br><br>Comment: {}".format(session['username'], message1, message2, comment))

            recipients = []
            if request.form.get('notify_admins'):
                recipients = dbhelpers.get_admins_email()
            recipients.extend(request.form.getlist('notify_email'))

            if recipients:
                utils.send_email("Dashboard Configuration update",
                                 sender=app.config.get('MAIL_SENDER'),
                                 recipients=recipients,
                                 html_body=message)

    return redirect(url_for('home_bp.show_settings'))


@home_bp.route('/login')
def login():
    session.clear()
    return render_template(app.config.get('HOME_TEMPLATE'))


def set_template_access(tosca, user_groups, active_group):
    info = {}

    for k, v in tosca.items():
        metadata = v.get("metadata", {})
        visibility = metadata.get("visibility", {"type": "public"})

        if not active_group and visibility["type"] != "private":
            metadata["access_locked"] = True
            info[k] = v
        elif active_group:
            is_locked = is_access_locked(visibility, active_group)
            if not (visibility["type"] == "private" and is_locked):
                metadata["access_locked"] = is_locked
                info[k] = v

    return info


def is_access_locked(visibility, active_group):
    regex = "groups_regex" in visibility
    if regex:
        return not re.match(visibility["groups_regex"], active_group)
    else:
        allowed_groups = visibility.get("groups", [])
        return active_group not in allowed_groups


def check_template_access(user_groups, active_group):
    tosca_info, tosca_templates, tosca_gmetadata = tosca.get()
    if tosca_gmetadata:
        templates_info = set_template_access(tosca_gmetadata, user_groups, active_group)
        enable_template_groups = True
    else:
        templates_info = set_template_access(tosca_info, user_groups, active_group)
        enable_template_groups = False
    return templates_info, enable_template_groups


@app.route('/')
@home_bp.route('/')
def home():

    iam_ok = iam_blueprint.session.authorized
    kc_ok = keycloak_blueprint.session.authorized

    if not iam_ok and not kc_ok:
        return redirect(url_for('home_bp.login'))
    if not session.get('userid'):
        auth.set_user_info()
    return redirect(url_for('home_bp.portfolio'))

@app.route('/portfolio')
@home_bp.route('/portfolio')
def portfolio():

    if session.get('userid'):
        # check database
        # if user not found, insert
        user = dbhelpers.get_user(session['userid'])
        if user is None:
            email = session['useremail']
            admins = json.dumps(app.config['ADMINS'])
            role = 'admin' if email in admins else 'user'

            user = User(sub=session['userid'],
                        name=session['username'],
                        username=session['preferred_username'],
                        given_name=session['given_name'],
                        family_name=session['family_name'],
                        email=email,
                        organisation_name=session['organisation_name'],
                        picture=utils.avatar(email, 26),
                        role=role,
                        active=1)
            dbhelpers.add_object(user)

        session['userrole'] = user.role  # role

        services = dbhelpers.get_services(visibility='public')
        services.extend(dbhelpers.get_services(visibility='private', groups=[session['active_usergroup']]))
        templates_info, enable_template_groups = check_template_access(session['usergroups'], session['active_usergroup'])

        return render_template(app.config.get('PORTFOLIO_TEMPLATE'), services=services, templates_info=templates_info,
                               enable_template_groups=enable_template_groups)

    return redirect(url_for('home_bp.login'))


@home_bp.route('/set_active')
def set_active_usergroup():
    group = request.args['group']
    session['active_usergroup'] = group
    flash("Project switched to {}".format(group), 'info')
    return redirect(request.referrer)


@home_bp.route('/logout')
def logout():
    session.clear()
    iam_blueprint.session.get("/logout")
    return redirect(url_for('home_bp.login'))


@app.route('/callback', methods=['POST'])
def callback():

    payload = request.get_json()
    app.logger.info("Callback payload: " + json.dumps(payload))

    status = payload['status']
    task = payload['task']
    uuid = payload['uuid']
    providername = payload['cloudProviderName'] if 'cloudProviderName' in payload else ''
    status_reason = payload['statusReason'] if 'statusReason' in payload else ''
    rf = 0

    user = dbhelpers.get_user(payload['createdBy']['subject'])
    user_email = user.email

    dep = dbhelpers.get_deployment(uuid)

    if dep is not None:

        rf = dep.feedback_required
        pn = dep.provider_name if dep.provider_name is not None else ''
        if dep.status != status or dep.task != task or pn != providername or status_reason != dep.status_reason:
            if 'endpoint' in payload['outputs']:
                dep.endpoint = payload['outputs']['endpoint']
            elif 'node_ip' in  payload['outputs']:
                dep.endpoint = payload['outputs']['node_ip']
            dep.update_time = payload['updateTime']
            if 'physicalId' in payload:
                dep.physicalId = payload['physicalId']
            dep.status = status
            dep.outputs = json.dumps(payload['outputs'])
            dep.task = task
            dep.provider_name = providername
            dep.status_reason = status_reason
            dbhelpers.add_object(dep)
    else:
        app.logger.info("Deployment with uuid:{} not found!".format(uuid))

    # send email to user
    description = json.loads(dep.inputs).get("additional_description", "Deployment")
    is_behind_vpn = json.loads(dep.inputs).get("is_behind_vpn", False)
    mail_sender = app.config.get('MAIL_SENDER')
    if mail_sender and user_email != '' and rf == 1:
        if status == 'CREATE_COMPLETE':
            try:
                utils.create_and_send_email("Deployment complete", mail_sender, [user_email], description, dep.endpoint, status, is_behind_vpn)
            except Exception as error:
                utils.logexception("sending email:".format(error))

        if status == 'CREATE_FAILED':
            try:
                utils.create_and_send_email("Deployment failed", mail_sender, [user_email], uuid, dep.endpoint, status)
            except Exception as error:
                utils.logexception("sending email:".format(error))

        if status == 'UPDATE_COMPLETE':
            try:
                utils.create_and_send_email("Deployment update complete", mail_sender, [user_email], uuid, dep.endpoint, status)
            except Exception as error:
                utils.logexception("sending email:".format(error))

        if status == 'UPDATE_FAILED':
            try:
                utils.create_and_send_email("Deployment update failed", mail_sender, [user_email], uuid, dep.endpoint, status)
            except Exception as error:
                utils.logexception("sending email:".format(error))

    resp = make_response('')
    resp.status_code = 200
    resp.mimetype = 'application/json'

    return resp


@home_bp.route('/getauthorization', methods=['POST'])
def getauthorization():
    tasks = json.loads(request.form.to_dict()["pre_tasks"].replace("'", "\""))

    functions = {'openstack.get_unscoped_keystone_token': openstack.get_unscoped_keystone_token,
                 'send_mail': utils.send_authorization_request_email}

    for task in tasks["pre_tasks"]:
        func = task["action"]
        args = task["args"]
        args["access_token"] = iam_blueprint.session.token['access_token']
        if func in functions:
            functions[func](**args)

    return render_template("success_message.html", title="Message sent",
                           message="Your request has been sent to the support team. <br>You will receive soon a notification email about your request. <br>Thank you!")


@home_bp.route('/sendaccessreq', methods=['POST'])
def sendaccessrequest():
    form_data = request.form.to_dict()

    try:
        utils.send_authorization_request_email(form_data['service_type'], email=form_data['email'],
                                               message=form_data['message'])

        flash(
            "Your request has been sent to the support team. You will receive soon a notification email about your "
            "request. Thank you!",
            "success")

    except Exception as error:
        utils.logexception("sending email:".format(error))
        flash("Sorry, an error occurred while sending your request. Please retry.", "danger")

    return redirect(url_for('home_bp.home'))


@home_bp.route('/contact', methods=['POST'])
def contact():
    app.logger.debug("Form data: " + json.dumps(request.form.to_dict()))

    form_data = request.form.to_dict()

    try:
        message = Markup(
            "Name: {}<br>Email: {}<br>Message: {}".format(form_data['name'], form_data['email'], form_data['message']))
        utils.send_email("New contact",
                         sender=app.config.get('MAIL_SENDER'),
                         recipients=[app.config.get('SUPPORT_EMAIL')],
                         html_body=message)

    except Exception as error:
        utils.logexception("sending email:".format(error))
        return Markup("<div class='alert alert-danger' role='alert'>Oops, error sending message.</div>")

    return Markup("<div class='alert alert-success' role='alert'>Your message has been sent, Thank you!</div>")
