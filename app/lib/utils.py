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

import enum
import json
import os
import shutil
import subprocess

import requests
import linecache
import sys
import randomcolor
import re
import string
import secrets
from hashlib import md5
from app import app, mail
from flask_mail import Message
from threading import Thread
from flask import session, render_template
from markupsafe import Markup


def to_pretty_json(value):
    return json.dumps(value, sort_keys=True,
                      indent=4, separators=(',', ': '))


def enum_to_string(obj):
    if isinstance(obj, enum.Enum):
        return obj.name
    # For all other types, let Jinja use default behavior
    return obj

def python_eval(obj):
    if isinstance(obj, str):
        try:
            return eval(obj)
        except Exception as e:
            app.logger.warn("Error calling python_eval(): {}".format(e))
    return obj


def gencolors(hue, n):
    rand_color = randomcolor.RandomColor(42)
    rcolors = rand_color.generate(hue=hue, luminosity="dark", count=n)
    return rcolors


def genstatuscolors(statuses):
    colors = []
    for status in statuses:
        if status == "CREATE_COMPLETE":
            colors.append('green')
        elif status == "CREATE_IN_PROGRESS":
            colors.append("lightgreen")
        elif status == "DELETE_IN_PROGRESS":
            colors.append('salmon')
        elif status == "CREATE_FAILED":
            colors.append('red')
        elif status == "DELETE_FAILED":
            colors.append('firebrick')
        else:
            colors.append('lightgrey')
    return colors


def intersect(a, b):
    return set(a).intersection(b)


def extract_netinterface_ips(input):
    res = {}
    for key,value in input.items():
        if re.match("net_interface.[0-9].ip", key):
            new_key = key.replace('.','_')
            res[new_key] = value

    return res

def xstr(s):
    return '' if s is None else str(s)


def nnstr(s):
    return '' if (s is None or s == '') else str(s)


def avatar(email, size):
    digest = md5(email.lower().encode('utf-8')).hexdigest()
    return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(digest, size)


def logexception(err):
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    app.logger.error('{} at ({}, LINE {} "{}"): {}'.format(err, filename, lineno, line.strip(), exc_obj))


def getorchestratorversion(orchestrator_url):
    url = orchestrator_url + "/info"
    response = requests.get(url)

    return response.json()['build']['version']


def getorchestratorconfiguration(orchestrator_url, access_token):
    headers = {'Authorization': 'bearer %s' % access_token}

    url = orchestrator_url + "/configuration"
    response = requests.get(url, headers=headers)

    configuration = {}
    if response.ok:
        configuration = response.json()

    return configuration

def format_json_radl(vminfo):
    res = {}
    for elem in vminfo:
        if elem["class"] == "system":
            for field, value in elem.items():
                if field not in ["class", "id"]:
                    if field.endswith("_min"):
                        field = field[:-4]
                    res[field] = value

    return res


def generate_password():
    alphabet = string.ascii_letters + string.digits
    password = ""
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(10))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and sum(c.isdigit() for c in password) >= 3):
            break

    return password


def send_authorization_request_email(service_type, **kwargs):
    user_email = kwargs['email'] if 'email' in kwargs else ""
    message = kwargs['message'] if 'message' in kwargs else ""
    message = Markup(
        "The following user has requested access for service \"{}\": <br>username: {} " \
        "<br>IAM id (sub): {} <br>IAM groups: {} <br>email registered in IAM: {} " \
        "<br>email provided by the user: {} " \
        "<br>Message: {}".format(service_type, session['username'], session['userid'],
                                 session['usergroups'], session['useremail'], user_email, message))

    sender = kwargs['email'] if 'email' in kwargs else session['useremail']
    send_email("New Authorization Request",
               sender=sender,
               recipients=[app.config.get('SUPPORT_EMAIL')],
               html_body=message)

def send_ports_request_email(deployment_uuid, **kwargs):
    user_email = kwargs['email'] if 'email' in kwargs else ""
    message = kwargs['message'] if 'message' in kwargs else ""
    message = Markup(
        "The following user has requested to open further ports for deployment \"{}\": <br>username: {} " \
        "<br>IAM id (sub): {} <br>email registered in IAM: {} " \
        "<br>email provided by the user: {} " \
        "<br>Message: {}".format(deployment_uuid, session['username'], session['userid'],
                                  session['useremail'], user_email, message))

    sender = kwargs['email'] if 'email' in kwargs else session['useremail']
    send_email("New Ports Request",
               sender=sender,
               recipients=[app.config.get('SUPPORT_EMAIL')],
               html_body=message)

def create_and_send_email(subject, sender, recipients, uuid, url, status):
    send_email(subject,
               sender=sender,
               recipients=recipients,
               html_body=render_template(app.config.get('MAIL_TEMPLATE'), uuid=uuid, url=url, status=status))


def send_email(subject, sender, recipients, html_body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.html = html_body
    msg.body = "This email is an automatic notification"  # Add plain text, needed to avoid MPART_ALT_DIFF with AntiSpam
    Thread(target=send_async_email, args=(app, msg)).start()


def send_email_with_attachment(subject, sender, recipients, html_body, attachment_filename=None, attachment_data=None, attachment_mimetype='application/octet-stream'):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.html = html_body
    msg.body = "This email is an automatic notification"
    if attachment_filename and attachment_data:
        msg.attach(attachment_filename, attachment_mimetype, attachment_data)
    Thread(target=send_async_email, args=(app, msg)).start()


def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)


def has_write_permission(directory):
    parent_directory = os.path.dirname(os.path.normpath(directory))
    try:
        test_file = os.path.join(parent_directory, '.test_file')
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        return True
    except Exception:
        return False


def backup_directory(directory):
    try:
        backup_path = f"{os.path.normpath(directory)}.bak"
        if os.path.exists(backup_path):
            shutil.rmtree(backup_path)
        shutil.copytree(directory, backup_path)
        return backup_path
    except Exception as e:
        app.logger.error(f"Error creating backup: {e}")
        return None


def restore_directory(backup_path, target_directory):
    try:
        if os.path.exists(target_directory):
            shutil.rmtree(target_directory)
        shutil.copytree(backup_path, target_directory)
        return True
    except Exception as e:
        app.logger.error(f"Error restoring directory: {e}")
        return False


def download_git_repo(repo_url, target_directory, tag_or_branch=None, private=False, username=None, deploy_token=None):
    try:
        if not has_write_permission(target_directory):
            return False, "No permission for creating the directory {}".format(target_directory)

        backup_path = backup_directory(target_directory)

        try:
            # Check if the target directory is not empty
            if os.path.exists(target_directory) and os.listdir(target_directory):
                app.logger.warn(f"Warning: Target directory '{target_directory}' is not empty. Removing existing contents.")
                shutil.rmtree(target_directory)

            # Clone the repository
            if private and username and deploy_token:
                git_url = repo_url.replace("https://", f"https://{username}:{deploy_token}@")
                subprocess.run(['git', 'clone', git_url, target_directory], check=True, capture_output=True)
            else:
                subprocess.run(['git', 'clone', repo_url, target_directory], check=True, capture_output=True)

            # Change directory to the cloned repository
            cwd = target_directory
            if tag_or_branch:
                subprocess.run(['git', 'checkout', tag_or_branch], cwd=cwd, check=True, capture_output=True)
                app.logger.info(f"Switched to tag/branch '{tag_or_branch}'.")

            app.logger.info(f"Repository '{repo_url}' (branch: '{tag_or_branch}') downloaded to '{target_directory}'.")
            return True, f"Repository '{repo_url}' (branch: '{tag_or_branch}') downloaded to '{target_directory}'."
        except subprocess.CalledProcessError as e:
            sanitized_error_message = f"{e} {e.stderr.decode('utf-8')}".replace(username + ':' + deploy_token, '[SENSITIVE DATA]')
            restore_directory(backup_path, target_directory)
            app.logger.error(f"Error: {sanitized_error_message}")
            return False, f"Error: {sanitized_error_message}"
    except Exception as e:
        app.logger.error(f"An error occurred: {e}")
        return False, f"An error occurred: {e}"


def to_bool(value):
    """Convert common boolean-like values to bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "y", "on")

    return bool(value)
