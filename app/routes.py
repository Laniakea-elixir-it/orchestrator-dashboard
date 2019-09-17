from app import app, iam_blueprint, iam_base_url, mail
from flask import json, render_template, request, redirect, url_for, flash, session, make_response
from flask_mail import Message
from threading import Thread
import requests
import json
import datetime
import yaml
import io
import os
import linecache
import sys
from fnmatch import fnmatch
from hashlib import md5
import mysql.connector
from dateutil import parser
import uuid as uuid_generator

# Hashicorp vault support integration
from app.vault_integration import VaultIntegration

iam_base_url = app.config['IAM_BASE_URL']
iam_client_id = app.config.get('IAM_CLIENT_ID')
iam_client_secret = app.config.get('IAM_CLIENT_SECRET')

issuer = iam_base_url
if not issuer.endswith('/'):
    issuer += '/'
db_host = app.config['DB_HOST']
db_port = app.config['DB_PORT']
db_user = app.config['DB_USER']
db_password = app.config['DB_PASSWORD']
db_name = app.config['DB_NAME']


def to_pretty_json(value):
    return json.dumps(value, sort_keys=True,
                      indent=4, separators=(',', ': '))


app.jinja_env.filters['tojson_pretty'] = to_pretty_json


def avatar(email, size):
    digest = md5(email.lower().encode('utf-8')).hexdigest()
    return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(digest, size)


def getdbconnection():
    cnx = mysql.connector.connect(user=db_user,
                                  password=db_password,
                                  host=db_host,
                                  database=db_name)
    return cnx


toscaDir = app.config.get('TOSCA_TEMPLATES_DIR') + "/"
tosca_pars_dir = app.config.get('TOSCA_PARAMETERS_DIR')
tosca_metadata_dir = app.config.get('TOSCA_METADATA_DIR')

toscaTemplates = []
for path, subdirs, files in os.walk(toscaDir):
    for name in files:
        if fnmatch(name, "*.yml") or fnmatch(name, "*.yaml"):
            # skip hidden files
            if name[0] != '.':
                toscaTemplates.append(os.path.relpath(os.path.join(path, name), toscaDir))

toscaInfo = {}
for tosca in toscaTemplates:
    with io.open( toscaDir + tosca) as stream:
       template = yaml.load(stream)

       toscaInfo[tosca] = {
                            "valid": True,
                            "description": "TOSCA Template",
                            "metadata": {
                                "icon": "https://cdn4.iconfinder.com/data/icons/mosaicon-04/512/websettings-512.png"
                            },
                            "enable_config_form": False,
                            "inputs": {},
                            "tabs": {}
                          }

       if 'topology_template' not in template:
           toscaInfo[tosca]["valid"] = False

       else:

            if 'description' in template:
                toscaInfo[tosca]["description"] = template['description']

#            if 'metadata' in template and template['metadata'] is not None:
#               for k,v in template['metadata'].items():
#                   toscaInfo[tosca]["metadata"][k] = v
#
#               if 'icon' not in template['metadata']:
#                   toscaInfo[tosca]["metadata"]['icon'] = "xxxx"

            if tosca_metadata_dir:
                tosca_metadata_path = tosca_metadata_dir + "/"
                for mpath, msubs, mnames in os.walk(tosca_metadata_path):
                    for mname in mnames:
                        if fnmatch(mname, os.path.splitext(tosca)[0] + '.metadata.yml') or \
                                 fnmatch(mname, os.path.splitext(tosca)[0] + '.metadata.yaml'):
                            # skip hidden files
                            if mname[0] != '.':
                                tosca_metadata_file = os.path.join(mpath, mname)
                                with io.open(tosca_metadata_file) as metadata_file:
                                    metadata_template = yaml.load(metadata_file)

                                    if 'metadata' in metadata_template and metadata_template['metadata'] is not None:
                                        for k,v in metadata_template['metadata'].items():
                                            toscaInfo[tosca]["metadata"][k] = v
                             
                                        if 'icon' not in metadata_template['metadata']:
                                            toscaInfo[tosca]["metadata"]['icon'] = "xxxx"

            if 'inputs' in template['topology_template']:
               toscaInfo[tosca]['inputs'] = template['topology_template']['inputs']

            ## add parameters code here
            tabs = {}
            if tosca_pars_dir:
                tosca_pars_path = tosca_pars_dir + "/"  # this has to be reassigned here because is local.
                for fpath, subs, fnames in os.walk(tosca_pars_path):
                    for fname in fnames:
                        if fnmatch(fname, os.path.splitext(tosca)[0] + '.parameters.yml') or \
                                fnmatch(fname, os.path.splitext(tosca)[0] + '.parameters.yaml'):
                            # skip hidden files
                            if fname[0] != '.':
                                tosca_pars_file = os.path.join(fpath, fname)
                                with io.open(tosca_pars_file) as pars_file:
                                    toscaInfo[tosca]['enable_config_form'] = True
                                    pars_data = yaml.load(pars_file)
                                    toscaInfo[tosca]['inputs'] = pars_data["inputs"]
                                    if "tabs" in pars_data:
                                        toscaInfo[tosca]['tabs'] = pars_data["tabs"]


app.logger.debug("Extracted TOSCA INFO: " + json.dumps(toscaInfo))

orchestratorUrl = app.config.get('ORCHESTRATOR_URL')
slamUrl = app.config.get('SLAM_URL')
cmdbUrl = app.config.get('CMDB_URL')

vault_url = app.config.get('VAULT_URL')
if vault_url:
   app.config.from_json('vault-config.json')
   vault_secrets_path = app.config.get('VAULT_SECRETS_PATH')
   vault_bound_audience = app.config.get('VAULT_BOUND_AUDIENCE')
   vault_wrapping_token_time_duration = app.config.get("WRAPPING_TOKEN_TIME_DURATION")
   vault_read_policy = app.config.get("READ_POLICY")
   vault_read_token_time_duration = app.config.get("READ_TOKEN_TIME_DURATION")
   vault_read_token_renewal_duration = app.config.get("READ_TOKEN_RENEWAL_TIME_DURATION")
   vault_write_policy = app.config.get("WRITE_POLICY")
   vault_write_token_time_duration = app.config.get("WRITE_TOKEN_TIME_DURATION")
   vault_wtite_token_renewal_time_duration = app.config.get("WRITE_TOKEN_RENEWAL_TIME_DURATION")
   vault_delete_policy = app.config.get("DELETE_POLICY")
   vault_delete_token_time_duration = app.config.get("DELETE_TOKEN_TIME_DURATION")
   vault_delete_token_renewal_time_duration = app.config.get("DELETE_TOKEN_RENEWAL_TIME_DURATION")


@app.route('/settings')
def show_settings():
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))
    return render_template('settings.html', orchestrator_url=orchestratorUrl, iam_url=iam_base_url)


@app.route('/deployments/<subject>')
def show_deployments(subject):
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))
    if not session['userrole'].lower() == 'admin':
        return render_template('home.html')

    connection = None
    cursor = None

    deployments = []
    user = get_user(subject)

    if user is not {}:
        #
        # retrieve deployments from orchestrator
        access_token = iam_blueprint.token['access_token']

        headers = {'Authorization': 'bearer %s' % access_token}

        url = orchestratorUrl + "/deployments?createdBy={}&page={}&size={}".format('{}@{}'.format(subject, issuer), 0,
                                                                                   999999)
        response = requests.get(url, headers=headers)

        deporch = []
        if response.ok:
            deporch = response.json()["content"]
            deporch = updatedeploymentsstatus(deporch, subject)

        iids = []
        # make map of remote deployments
        for dep_json in deporch:
            iids.append(dep_json['uuid'])

        #
        # retrieve deployments from DB
        try:
            connection = getdbconnection()
            cursor = connection.cursor()

            select_query = "SELECT * FROM `deployments` WHERE `sub` = %s"
            cursor.execute(select_query, (user['sub'],))

            deployments = cvdeployments(cursor.fetchall())

            # update remote status
            for dep in deployments:
                remote = dep['remote']
                newremote = remote
                if not dep['uuid'] in iids:
                    if remote == 1:
                        newremote = 0
                else:
                    if remote == 0:
                        newremote = 1
                if remote != newremote:
                    update_query = "UPDATE `deployments` SET `remote` = '{}' WHERE `uuid` = '{}'"
                    update_cmd = update_query.format(newremote, dep['uuid'])
                    cursor.execute(update_cmd)
                    connection.commit()

        except mysql.connector.Error as error:
            logexception("reading deployments table: {}".format(error))
        except Exception as ex:
            logexception("reading deployments: {}".format(ex))
        finally:
            if connection is not None:
                if connection.is_connected():
                    if cursor is not None:
                        cursor.close()
                    connection.close()

        return render_template('dep_user.html', user=user, deployments=deployments)
    else:
        flash("User not found!")
        users = get_users()
        return render_template('users.html', users=users)


@app.route('/user/<subject>', methods=['GET', 'POST'])
def show_user(subject):
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))
    if not session['userrole'].lower() == 'admin':
        return render_template('home.html')

    if request.method == 'POST':

        connection = None
        cursor = None

        # cannot change its own role
        if session['userid'] == subject:
            role = session['userrole']
        else:
            role = request.form['role']
        active = request.form['active']
        # update database
        try:
            connection = getdbconnection()
            cursor = connection.cursor()

            update_query = "UPDATE `users` SET `role` = '{}', `active` = '{}' WHERE `sub` = '{}'"
            update_cmd = update_query.format(role, active, subject)
            cursor.execute(update_cmd)
            connection.commit()
        except mysql.connector.Error as error:
            logexception("updating users table {}".format(error))
        finally:
            if connection is not None:
                if connection.is_connected():
                    if cursor is not None:
                        cursor.close()
                    connection.close()

    user = get_user(subject)
    if user is not None:
        return render_template('user.html', user=user)
    else:
        return render_template('home.html')


def get_users():
    users = []
    connection = None
    cursor = None

    try:
        connection = getdbconnection()
        cursor = connection.cursor()

        # WHERE `active` = '1'
        select_query = "SELECT * FROM `users` ORDER BY `family_name`,`given_name`"
        cursor.execute(select_query)
        u = cursor.fetchall()
        for tp in u:
            users.append(cvuser(tp))
    except mysql.connector.Error as error:
        logexception("reading users table {}".format(error))
    finally:
        if connection is not None:
            if connection.is_connected():
                if cursor is not None:
                    cursor.close()
                connection.close()
    return users


def get_user(subject):
    user = {}
    connection = None
    cursor = None

    try:
        connection = getdbconnection()
        cursor = connection.cursor()

        select_query = "SELECT * FROM `users` WHERE `sub` = %s"
        cursor.execute(select_query, (subject,))
        u = cursor.fetchone()
        if cursor.rowcount == 1:
            user = cvuser(u)
    except mysql.connector.Error as error:
        logexception("reading users table {}".format(error))
    finally:
        if connection is not None:
            if connection.is_connected():
                if cursor is not None:
                    cursor.close()
                connection.close()
    return user


def get_deployment(uuid):
    deployment = {}
    connection = None
    cursor = None

    try:
        connection = getdbconnection()
        cursor = connection.cursor()

        select_query = "SELECT * FROM `deployments` WHERE `uuid` = %s"
        cursor.execute(select_query, (uuid,))

        r = cursor.fetchone()
        if cursor.rowcount == 1:
            deployment = cvdeployment(r)

    except mysql.connector.Error as error:
        logexception("reading deployments table: {}".format(error))
    finally:
        if connection is not None:
            if connection.is_connected():
                if cursor is not None:
                    cursor.close()
                connection.close()

    return deployment


@app.route('/users')
def show_users():
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))
    if not session['userrole'].lower() == 'admin':
        return render_template('home.html')

    users = get_users()

    return render_template('users.html', users=users)


@app.route('/login')
def login():
    session.clear()
    return render_template('home.html')


def get_sla_extra_info(access_token, service_id):
    headers = {'Authorization': 'bearer %s' % access_token}
    url = cmdbUrl + "/service/id/" + service_id
    response = requests.get(url, headers=headers, timeout=20)
    response.raise_for_status()
    app.logger.info(json.dumps(response.json()['data']['service_type']))

    service_type = response.json()['data']['service_type']
    sitename = response.json()['data']['sitename']
    if 'properties' in response.json()['data']:
        if 'gpu_support' in response.json()['data']['properties']:
            service_type = service_type + " (gpu_support: " + str(
                response.json()['data']['properties']['gpu_support']) + ")"

    return sitename, service_type


def get_slas(access_token):
    headers = {'Authorization': 'bearer %s' % access_token}
    url = slamUrl + "/rest/slam/preferences/" + session['organisation_name']
    response = requests.get(url, headers=headers, timeout=20)
    app.logger.info("SLA response status: " + str(response.status_code))

    response.raise_for_status()
    app.logger.info("SLA response: " + json.dumps(response.json()))
    slas = response.json()['sla']

    for i in range(len(slas)):
        sitename, service_type = get_sla_extra_info(access_token, slas[i]['services'][0]['service_id'])
        slas[i]['service_type'] = service_type
        slas[i]['sitename'] = sitename

    return slas


@app.route('/slas')
def getslas():
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    try:
        access_token = iam_blueprint.token['access_token']
        slas = get_slas(access_token)

    except Exception as e:
        flash("Error retrieving SLAs list: \n" + str(e), 'warning')
        return redirect(url_for('home'))

    return render_template('sla.html', slas=slas)


def cvdeployments(listt):
    deployments = []
    for tp in listt:
        deployments.append(cvdeployment(tp))

    return deployments


def cvdeployment(tp):
    deployment = {}
    deployment['uuid'] = tp[0]
    deployment['creationTime'] = tp[1]
    deployment['updateTime'] = tp[2]
    if not tp[3] is None:
        deployment['physicalId'] = tp[3]
    else:
        deployment['physicalId'] = ''
    deployment['additionaldescription'] = tp[4]
    deployment['status'] = tp[5]
    if not tp[6] is None and not tp[6] is '':
        deployment['outputs'] = json.loads(tp[6].replace("\n", "\\n"))
    else:
        deployment['outputs'] = ''
    deployment['task'] = tp[7]
    if not tp[8] is None and not tp[8] is '':
        deployment['links'] = json.loads(tp[8].replace("\n", "\\n"))
    else:
        deployment['links'] = ''
    createdby = {}
    createdby['issuer'] = tp[18]
    createdby['subject'] = tp[9]
    deployment['createdBy'] = createdby
    if not tp[10] is None:
        deployment['cloudProviderName'] = tp[10]
    else:
        deployment['cloudProviderName'] = ''
    deployment['endpoint'] = tp[11]
    deployment['template'] = tp[12]
    if not tp[13] is None and not tp[13] is '':
        deployment['inputs'] = json.loads(tp[13].replace("\n", "\\n"))
    else:
        deployment['inputs'] = ''
    deployment['locked'] = tp[15]
    deployment['feedbackrequired'] = tp[16]
    deployment['remote'] = tp[17]
    deployment['storage_encryption'] = tp[19]
    if not tp[20] is None:
        deployment['vault_secret_uuid'] = tp[20]
    else:
        deployment['vault_secret_uuid'] = ''
    if not tp[21] is None:
        deployment['vault_secret_key'] = tp[21]
    else:
        deployment['vault_secret_key'] = ''
    if not tp[22] is None:
        deployment['statusReason'] = tp[22]
    else:
        deployment['statusReason'] = ''
    return deployment


def cvuser(tp):
    user = {}
    user['sub'] = tp[0]
    user['name'] = tp[1]
    user['username'] = tp[2]
    user['given_name'] = tp[3]
    user['family_name'] = tp[4]
    user['email'] = tp[5]
    user['organisation_name'] = tp[6]
    user['picture'] = tp[7]
    user['role'] = tp[8]
    user['active'] = tp[9]
    return user


def updatedeploymentsstatus(deployments, userid):
    iids = []
    uuid = ''
    connection = None
    cursor = None

    # update deployments status in database
    for dep_json in deployments:
        uuid = dep_json['uuid']
        iids.append(uuid)

        # sanitize date
        dt = parser.parse(dep_json['creationTime'])
        dep_json['creationTime'] = dt.strftime("%Y-%m-%d %H:%M:%S")
        dt = parser.parse(dep_json['updateTime'])
        dep_json['updateTime'] = dt.strftime("%Y-%m-%d %H:%M:%S")
        if 'cloudProviderName' in dep_json:
            providername = dep_json['cloudProviderName']
        else:
            providername = ''
        if 'statusReason' in dep_json:
            status_reason = dep_json['statusReason']
        else:
            status_reason = ''

        dep = get_deployment(uuid)

        if dep != {}:
            dep_json['additionaldescription'] = dep['additionaldescription']
            dep_json['endpoint'] = dep['endpoint']
            pn = dep['cloudProviderName']
            rs = dep['statusReason']
        else:
            pn = ''
            rs = ''

        if (dep != {} and (dep['status'] != dep_json['status'] or pn != providername or rs != status_reason)) or dep == {}:
            try:
                connection = getdbconnection()
                cursor = connection.cursor()

                if 'physicalId' in dep_json:
                    vphid = dep_json['physicalId']
                else:
                    vphid = ''

                if dep != {}:
                    update_query = "UPDATE `deployments` SET `update_time` = '{}', `physicalId` = '{}', `status` = '{}'," \
                                   " `outputs` = '{}', `task` = '{}', `links` = '{}', `remote` = '{}' ," \
                                   " `provider_name` = '{}', `status_reason` = '{}' WHERE `uuid` = '{}'"
                    update_cmd = update_query.format(dep_json['updateTime'], vphid, dep_json['status'],
                                                     json.dumps(dep_json['outputs']), dep_json['task'],
                                                     json.dumps(dep_json['links']), '1', providername, status_reason,
                                                     uuid)
                    cursor.execute(update_cmd)
                    connection.commit()
                else:
                    app.logger.info("Deployment with uuid:{} not found!".format(uuid))

                    # retrieve template
                    access_token = iam_blueprint.session.token['access_token']
                    headers = {'Authorization': 'bearer %s' % access_token}

                    url = orchestratorUrl + "/deployments/" + uuid + "/template"
                    response = requests.get(url, headers=headers)

                    if not response.ok:
                        template = ''
                    else:
                        template = response.text

                    # insert missing deployment in database
                    if 'endpoint' in dep_json['outputs']:
                        endpoint = dep_json['outputs']['endpoint']
                    else:
                        endpoint = ''
                    insert_query = "INSERT INTO `deployments` (`uuid`, `creation_time`, `update_time`, `physicalId`, " \
                                   "`description`, `status`, `outputs`, `task`, `links`, `sub`, `template`, `inputs`, " \
                                   "`params`, `provider_name`, `endpoint`, `remote`, `issuer`, `storage_encryption`, " \
                                   "`vault_secret_uuid`, `vault_secret_key`)" \
                                   " VALUES  (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, " \
                                   "%s, %s)"
                    insert_values = (
                        uuid, dep_json['creationTime'], dep_json['updateTime'], vphid, '', dep_json['status'],
                        json.dumps(dep_json['outputs']), dep_json['task'], json.dumps(dep_json['links']),
                        userid, template, '', '', providername, endpoint, '1', dep_json['createdBy']['issuer'], '0',
                        '', '')
                    cursor.execute(insert_query, insert_values)
                    connection.commit()

            except mysql.connector.Error as error:
                connection.rollback()  # rollback if any exception occured
                logexception("updating deployment with uuid:{} in deployments table: {}".format(uuid, error))
            finally:
                if connection is not None:
                    if connection.is_connected():
                        if cursor is not None:
                            cursor.close()
                        connection.close()
    #
    # check delete in progress or missing
    try:
        uuid = ''
        connection = getdbconnection()
        cursor = connection.cursor()

        select_query = "SELECT * FROM `deployments` WHERE `sub` = %s AND `status` = 'DELETE_IN_PROGRESS'"
        cursor.execute(select_query, (userid,))

        records = cursor.fetchall()
        for r in records:
            uuid = r[0]
            if uuid not in iids:
                time_string = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                update_query = "UPDATE `deployments` SET `update_time` = '{}', `status` = '{}' WHERE `uuid` = '{}'"
                update_cmd = update_query.format(time_string, 'DELETE_COMPLETE', uuid)
                cursor.execute(update_cmd)
                connection.commit()
    except mysql.connector.Error as error:
        connection.rollback()  # rollback if any exception occured
        logexception("updating deployment with UUID:{} in deployments table: {}".format(uuid, error))
    finally:
        if connection is not None:
            if connection.is_connected():
                if cursor is not None:
                    cursor.close()
                connection.close()

    return deployments


def logexception(err):
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    app.logger.error('{} at ({}, LINE {} "{}"): {}'.format(err, filename, lineno, line.strip(), exc_obj))


@app.route('/')
def home():
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))
    try:
        account_info = iam_blueprint.session.get("/userinfo")

        if account_info.ok:
            account_info_json = account_info.json()
            session['userid'] = account_info_json['sub']
            session['username'] = account_info_json['name']
            session['useremail'] = account_info_json['email']
            session['userrole'] = 'user'
            session['gravatar'] = avatar(account_info_json['email'], 26)
            session['organisation_name'] = account_info_json['organisation_name']
            access_token = iam_blueprint.token['access_token']

            # check database
            # if user not found, insert
            #
            connection = None
            cursor = None

            try:
                connection = getdbconnection()
                cursor = connection.cursor()

                select_query = "SELECT * FROM `users` WHERE `sub` = %s"
                cursor.execute(select_query, (account_info_json['sub'],))
                r = cursor.fetchone()
                if cursor.rowcount != 1:
                    email = account_info_json['email']
                    admins = json.dumps(app.config['ADMINS'])
                    if email in admins:
                        role = 'admin'
                    else:
                        role = 'user'
                    insert_query = " INSERT INTO `users` (`sub`, `name`, `username`, `given_name`, `family_name`, " \
                                   "`email`, `organisation_name`, `picture`, `role`, `active`)" \
                                   " VALUES  (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                    insert_values = (
                        account_info_json['sub'], account_info_json['name'], account_info_json['preferred_username'],
                        account_info_json['given_name'], account_info_json['family_name'], email,
                        account_info_json['organisation_name'], avatar(email, 26), role, '1')
                    cursor.execute(insert_query, insert_values)
                    connection.commit()
                else:
                    session['userrole'] = r[8]  # role
            except mysql.connector.Error as error:
                connection.rollback()  # rollback if any exception occured
                logexception("inserting record into users table {}".format(error))
            finally:
                if connection is not None:
                    if connection.is_connected():
                        if cursor is not None:
                            cursor.close()
                        connection.close()

            return render_template('portfolio.html', templates=toscaInfo)

    except Exception as e:
        app.logger.error("Error: " + str(e))
        return redirect(url_for('logout'))


@app.route('/deployments')
def showdeployments():

    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    try:
        access_token = iam_blueprint.token['access_token']

        headers = {'Authorization': 'bearer %s' % access_token}

        url = orchestratorUrl + "/deployments?createdBy=me&page={}&size={}".format(0, 999999)
        response = requests.get(url, headers=headers)

        deployments = {}
        if not response.ok:
            return redirect(url_for('login'))
        else:
            deployments = response.json()["content"]
            deployments = updatedeploymentsstatus(deployments, session['userid'])

        inputs={}
        for deployment in deployments:
            depid = deployment['uuid']
            dep = get_deployment(depid)

            inputs[depid] = {
                             "galaxy_flavor": "",
                             "infra_config": "single_vm",
                             "instance_flavor": {
                                                 "fe": "",
                                                 "wn": ""
                                                },
                            }

            if 'instance_flavor' in dep['inputs']:
                inputs[depid]['instance_flavor']['fe'] = dep['inputs']['instance_flavor']
            elif 'fe_instance_flavor' in dep['inputs']:
                inputs[depid]['infra_config'] = 'cluster'
                inputs[depid]['instance_flavor']['fe'] = dep['inputs']['fe_instance_flavor']
                inputs[depid]['instance_flavor']['wn'] = dep['inputs']['wn_instance_flavor']

            if 'flavor' in dep['inputs']: inputs[depid]['galaxy_flavor'] = dep['inputs']['flavor']

        return render_template('deployments.html', deployments=deployments, inputs=inputs)
    except Exception as error:
        logexception(error)
        return redirect(url_for('logout'))


@app.route('/template/<depid>')
def deptemplate(depid=None):
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    access_token = iam_blueprint.session.token['access_token']
    headers = {'Authorization': 'bearer %s' % access_token}

    url = orchestratorUrl + "/deployments/" + depid + "/template"
    response = requests.get(url, headers=headers)

    if not response.ok:
        flash("Error getting template: " + response.text)
        return redirect(url_for('home'))

    template = response.text
    return render_template('deptemplate.html', template=template)


@app.route('/output/<depid>')
def depoutput(depid=None):
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    # retrieve deployment from DB
    dep = get_deployment(depid)
    if dep == {}:
        return redirect(url_for('home'))
    else:
        output = json.dumps(dep['outputs']).lstrip().replace("\\n", "\n")
        p = output.find('"token": "')
        if p != -1:
            p += 10
            output = output[:p] + '\n' + output[p:]
        # inp = json.dumps(dep['inputs'])
        inp = dep[
            'inputs']  # we keep this as json, to retrieve info to enable passphrase recovery from vault only for those deployment has storage_encryption enabled
        links = json.dumps(dep['links'])

        volume_state = dep['storage_encryption']
        if volume_state == 1:
          volume_state = encrypted_volume_status(depid)

        endpoint_state = str( is_endpoint_online(depid) )

        return render_template('depoutput.html',
                               deployment=dep,
                               volume_state=volume_state,
                               endpoint_state=endpoint_state,
                               inputs=inp,
                               outputs=output,
                               links=links)


def encrypted_volume_status(depid=None):
    # retrieve deployment from DB
    dep = get_deployment(depid)
    if dep == {}:
        return redirect(url_for('home'))
    else:

        if 'node_ip' in dep['outputs']:
            api_status = 'https://' + dep['outputs']['node_ip'] + ':5000/luksctl_api/v1.0/status'
        elif 'cluster_ip' in dep['outputs']:
            api_status = 'https://' + dep['outputs']['cluster_ip'] + ':5000/luksctl_api/v1.0/status'
        else:
            return 'unavailable'

        try:
            response = requests.get(api_status, verify=False)
        except:
            return 'unavailable'

        deserialized_response = json.loads(response.text)
        return deserialized_response['volume_state']



def is_endpoint_online(depid=None):
    # retrieve deployment from DB
    dep = get_deployment(depid)
    if dep == {}:
        return redirect(url_for('home'))
    else:

        if 'endpoint' in dep['outputs']:
            endpoint = dep['outputs']['endpoint'] + '/'
            try:
              response = requests.get(endpoint, verify=False)
            except:
              return 'unavailable'

            return response.status_code

        else:

            return 'Unavailable'


@app.route('/templatedb/<depid>')
def deptemplatedb(depid):
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    # retrieve deployment from DB
    dep = get_deployment(depid)
    if dep == {}:
        return redirect(url_for('home'))
    else:
        template = dep['template']
        return render_template('deptemplate.html', template=template)


@app.route('/delete/<depid>')
def depdel(depid=None):
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    access_token = iam_blueprint.session.token['access_token']
    headers = {'Authorization': 'bearer %s' % access_token}
    url = orchestratorUrl + "/deployments/" + depid
    response = requests.delete(url, headers=headers)

    if not response.ok:
        flash("Error deleting deployment: " + response.text)
    else:
        dep = get_deployment(depid)
        if dep != {} and dep['storage_encryption'] == 1:
            secret_path = session['userid'] + "/" + dep['vault_secret_uuid']
            delete_secret_from_vault(access_token, secret_path)

    return redirect(url_for('showdeployments'))


def delete_secret_from_vault(access_token, secret_path):

    vault = VaultIntegration(vault_url, iam_base_url, iam_client_id, iam_client_secret, vault_bound_audience,
                             access_token, vault_secrets_path)

    auth_token = vault.get_auth_token()

    delete_token = vault.get_token(auth_token, vault_delete_policy, vault_delete_token_time_duration, vault_delete_token_renewal_time_duration)

    vault.delete_secret(delete_token, secret_path)


@app.route('/configure')
def configure():
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    access_token = iam_blueprint.session.token['access_token']

    selected_tosca = request.args['selected_tosca']

    ssh_pub_key =  get_ssh_pub_key()

    try:
        slas = get_slas(access_token)

    except Exception as e:
        flash("Error retrieving SLAs list: \n" + str(e), 'warning')
        return redirect(url_for('home'))

    return render_template('createdep.html',
                           template=toscaInfo[selected_tosca],
                           selectedTemplate=selected_tosca,
                           ssh_pub_key=ssh_pub_key,
                           slas=slas)


def add_sla_to_template(template, sla_id):
    # Add the placement policy

    # nodes = template['topology_template']['node_templates']
    # compute_nodes = []
    #    for key, dict in nodes.items():
    #        node_type=dict["type"]
    #        if node_type == "tosca.nodes.indigo.Compute" or node_type == "tosca.nodes.indigo.Container.Application.Docker.Chronos" :
    #            compute_nodes.append(key)
    #    template['topology_template']['policies']=[{ "deploy_on_specific_site": { "type": "tosca.policies.Placement", "properties": { "sla_id": sla_id }, "targets": compute_nodes  } }]
    template['topology_template']['policies'] = [
        {"deploy_on_specific_site": {"type": "tosca.policies.Placement", "properties": {"sla_id": sla_id}}}]
    app.logger.info(yaml.dump(template, default_flow_style=False))
    return template


@app.route('/submit', methods=['POST'])
def createdep():
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    access_token = iam_blueprint.session.token['access_token']
    callback_url = app.config['CALLBACK_URL']

    app.logger.debug("Form data: " + json.dumps(request.form.to_dict()))

    try:
        with io.open(toscaDir + request.args.get('template')) as stream:
            template = yaml.load(stream)
            # rewind file
            stream.seek(0)
            template_text = stream.read()

            form_data = request.form.to_dict()

            params = {}
            if 'extra_opts.keepLastAttempt' in form_data:
                params['keepLastAttempt'] = 'true'
            else:
                params['keepLastAttempt'] = 'false'

            if 'extra_opts.sendEmailFeedback' in form_data:
                feedback_required = 1
            else:
                feedback_required = 0

            if form_data['extra_opts.schedtype'].lower() == "man":
                template = add_sla_to_template(template, form_data['extra_opts.selectedSLA'])

            additionaldescription = form_data['additional_description']

            inputs = {k: v for (k, v) in form_data.items() if not k.startswith("extra_opts.")}

            storage_encryption = 0
            vault_secret_uuid = ''
            vault_secret_key = ''
            if 'storage_encryption' in inputs and inputs['storage_encryption'].lower() == 'true':
                storage_encryption = 1
                vault_secret_key = 'secret'

            if storage_encryption == 1:
                vault_secret_uuid = str(uuid_generator.uuid4())
                if 'vault_secret_key' in inputs:
                    vault_secret_key = inputs['vault_secret_key']
                app.logger.debug("Storage encryption enabled, appending wrapping token.")
                inputs['vault_wrapping_token'] = create_vault_wrapping_token(access_token)
                inputs['vault_secret_path'] = session['userid'] + '/' + vault_secret_uuid

            if 'instance_key_pub' in inputs and inputs['instance_key_pub'] == '':
                inputs['instance_key_pub'] = get_ssh_pub_key() 

            app.logger.debug("Parameters: " + json.dumps(inputs))

            payload = {"template": yaml.dump(template, default_flow_style=False, sort_keys=False), "parameters": inputs,
                       "callback": callback_url}

        # body= json.dumps(payload)

        url = orchestratorUrl + "/deployments/"
        headers = {'Content-Type': 'application/json', 'Authorization': 'bearer %s' % access_token}
        # response = requests.post(url, data=body, headers=headers)
        response = requests.post(url, json=payload, params=params, headers=headers)

        if not response.ok:
            flash("Error submitting deployment: \n" + response.text)
        else:
            # store data into database
            rs_json = json.loads(response.text)
            connection = None
            cursor = None

            try:
                connection = getdbconnection()
                cursor = connection.cursor()

                uuid = rs_json['uuid']
                select_query = "SELECT * FROM `deployments` WHERE `uuid` = %s"
                cursor.execute(select_query, (uuid,))
                cursor.fetchone()
                if cursor.rowcount != 1:
                    if 'physicalId' in rs_json:
                        vphid = rs_json['physicalId']
                    else:
                        vphid = ''
                    if 'cloudProviderName' in rs_json:
                        providername = rs_json['cloudProviderName']
                    else:
                        providername = ''

                    insert_query = "INSERT INTO `deployments` (`uuid`, `creation_time`, `update_time`, `physicalId`," \
                                   " `description`, `status`, `outputs`, `task`, `links`, `sub`, `template`, `inputs`," \
                                   " `params`, `provider_name`, `endpoint`, `feedback_required`, `remote`, `issuer`," \
                                   " `storage_encryption`, `vault_secret_uuid`, `vault_secret_key`)" \
                                   " VALUES  (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, " \
                                   "%s, %s, %s)"
                    insert_values = (
                        uuid, rs_json['creationTime'], rs_json['updateTime'], vphid, additionaldescription,
                        rs_json['status'], json.dumps(rs_json['outputs']), rs_json['task'],
                        json.dumps(rs_json['links']),
                        rs_json['createdBy']['subject'], template_text, json.dumps(inputs), json.dumps(params),
                        providername, '', feedback_required, '1', rs_json['createdBy']['issuer'],
                        storage_encryption, vault_secret_uuid, vault_secret_key)
                    cursor.execute(insert_query, insert_values)
                    connection.commit()
                else:
                    flash("Deployment with uuid:{} is already in the database!".format(uuid))
            except mysql.connector.Error as error:
                connection.rollback()  # rollback if any exception occured
                logexception("inserting data into deployments table {}".format(error))
            finally:
                if connection is not None:
                    if connection.is_connected():
                        if cursor is not None:
                            cursor.close()
                        connection.close()

        return redirect(url_for('showdeployments'))

    except Exception as e:
        flash("Error submitting deployment:" + str(e) + ". Please retry")
        return redirect(url_for('home'))


def create_vault_wrapping_token(access_token):
    vault = VaultIntegration(vault_url, iam_base_url, iam_client_id, iam_client_secret, vault_bound_audience,
                             access_token, vault_secrets_path)

    auth_token = vault.get_auth_token()

    wrapping_token = vault.get_wrapping_token(vault_wrapping_token_time_duration, auth_token, vault_write_policy, vault_write_token_time_duration, vault_wtite_token_renewal_time_duration)

    return wrapping_token


@app.route('/logout')
def logout():
    session.clear()
    iam_blueprint.session.get("/logout")
    #   del iam_blueprint.session.token
    return redirect(url_for('login'))


@app.route('/callback', methods=['POST'])
def callback():
    # data=request.data
    payload = request.get_json()
    app.logger.info("Callback payload: " + json.dumps(payload))

    status = payload['status']
    task = payload['task']
    uuid = payload['uuid']
    if 'cloudProviderName' in payload:
        providername = payload['cloudProviderName']
    else:
        providername = ''
    if 'statusReason' in payload:
        status_reason = payload['statusReason']
    else:
        status_reason = ''
    rf = 0

    user = get_user(payload['createdBy']['subject'])
    user_email = user['email']  # email

    dep = get_deployment(uuid)

    if dep != {}:

        st = dep['status']
        ts = dep['task']
        rf = dep['feedbackrequired']
        rs = dep['statusReason']
        if 'cloudProviderName' in dep:
            pn = dep['cloudProviderName']
        else:
            pn = ''
        if st != status or ts != task or pn != providername or status_reason != rs:
            # get user from database
            connection = None
            cursor = None

            try:
                connection = getdbconnection()
                cursor = connection.cursor()

                if 'physicalId' in payload:
                    vphid = payload['physicalId']
                else:
                    if 'physicalId' in dep:
                        vphid = dep['physicalId']
                    else:
                        vphid = ''
                if 'endpoint' in payload['outputs']:
                    endpoint = payload['outputs']['endpoint']
                else:
                    endpoint = dep['endpoint']
                update_query = "UPDATE `deployments` SET `update_time` = '{}', `physicalId` = '{}', `status` = '{}', " \
                               "`outputs` = '{}', `task` = '{}', `provider_name` = '{}', `endpoint` = '{}', " \
                               "`status_reason` = '{}' WHERE `uuid` = '{}'"
                update_cmd = update_query.format(payload['updateTime'], vphid, status,
                                                 json.dumps(payload['outputs']), task, providername, endpoint,
                                                 status_reason, uuid)
                cursor.execute(update_cmd)
                connection.commit()
            except mysql.connector.Error as error:
                connection.rollback()  # rollback if any exception occured
                logexception("accessing database {}".format(error))
            finally:
                if connection is not None:
                    if connection.is_connected():
                        if cursor is not None:
                            cursor.close()
                        connection.close()
    else:
        app.logger.info("Deployment with uuid:{} not found!".format(uuid))

    # send email to user
    if user_email != '' and rf == 1:
        mail_sender = app.config['MAIL_SENDER']
        if status == 'CREATE_COMPLETE':
            email_recipients = [user_email]
            instance_admin_email = user_email
            if 'admin_email' in dep['inputs'] and user_email != dep['inputs']['admin_email']:
                email_recipients.append(dep['inputs']['admin_email'])
                instance_admin_email = dep['inputs']['admin_email']
            try:
                send_success_email(mail_sender, email_recipients, instance_admin_email, endpoint)
            except Exception as error:
                logexception("sending email:".format(error))

        if status == 'CREATE_FAILED':
            msg = Message("[Laniakea] Your deployment failed.",
                          sender=mail_sender,
                          recipients=[user_email])
            msg.body = "Your deployment request with uuid: {} has failed.".format(uuid)
            try:
                mail.send(msg)
            except Exception as error:
                logexception("sending email:".format(error))

    resp = make_response('')
    resp.status_code = 200
    resp.mimetype = 'application/json'

    return resp


def send_success_email(mail_sender, email_recipients, instance_admin_email, endpoint):
    send_email("[Laniakea] Your Galaxy is ready.",
               sender=mail_sender,
               recipients=email_recipients,
               html_body=render_template('email/success_email.html',
                                         endpoint=endpoint,
                                         user=instance_admin_email))


def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)


def send_email(subject, sender, recipients, html_body):
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.html = html_body
    Thread(target=send_async_email, args=(app, msg)).start()


@app.route('/read_secret_from_vault/<depid>')
def read_secret_from_vault(depid=None):
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    try:
        access_token = iam_blueprint.token['access_token']

    except Exception as e:
        flash("Token expired, realod page.", 'warning')
        return redirect(url_for('home'))

    # retrieve deployment from DB
    dep = get_deployment(depid)
    if dep == {}:
        return redirect(url_for('home'))
    else:

        vault = VaultIntegration(vault_url, iam_base_url, iam_client_id, iam_client_secret, vault_bound_audience,
                                 access_token, vault_secrets_path)

        auth_token = vault.get_auth_token()

        read_token = vault.get_token(auth_token, vault_read_policy, vault_read_token_time_duration, vault_read_token_renewal_duration)

        # retrieval of secret_path and secret_key from the db goes here
        secret_path = session['userid'] + "/" + dep['vault_secret_uuid']
        user_key = dep['vault_secret_key']

        response_output = vault.read_secret(read_token, secret_path, user_key)

        vault.revoke_token(auth_token)

        return response_output


@app.route('/encrypted_volume_open/<depid>')
def encrypted_volume_open(depid=None):
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    try:
        access_token = iam_blueprint.token['access_token']

    except Exception as e:
        flash("Token expired, realod page.", 'warning')
        return redirect(url_for('home'))

    # retrieve deployment from DB
    dep = get_deployment(depid)
    if dep == {}:
        return redirect(url_for('home'))
    else:

        vault = VaultIntegration(vault_url, iam_base_url, iam_client_id, iam_client_secret, vault_bound_audience,
                                 access_token, vault_secrets_path)

        auth_token = vault.get_auth_token()

        wrapping_read_token = vault.get_wrapping_token('20m', auth_token, 'read_only', '20m', '20m')

        # retrieval of secret_path and secret_key from the db goes here
        secret_path = session['userid'] + "/" + dep['vault_secret_uuid']
        user_key = dep['vault_secret_key']

        payload = {
                "vault_url": vault_url,
                "vault_token": wrapping_read_token,
                "secret_root": vault_secrets_path,
                "secret_path": secret_path,
                "secret_key": user_key
               }

        if 'node_ip' in dep['outputs']:
            api_open = 'https://' + dep['outputs']['node_ip'] + ':5000/luksctl_api/v1.0/open'
        elif 'cluster_ip' in dep['outputs']:
            api_open = 'https://' + dep['outputs']['cluster_ip'] + ':5000/luksctl_api/v1.0/open'
        else:
            return 'unavailable'

        response = requests.post(api_open, json=payload, verify=False)

        deserialized_response = json.loads(response.text)

        return deserialized_response['volume_state']


@app.route('/galaxy_startup/<depid>')
def galaxy_startup(depid=None):
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    try:
        access_token = iam_blueprint.token['access_token']

    except Exception as e:
        flash("Token expired, realod page.", 'warning')
        return redirect(url_for('home'))

    # retrieve deployment from DB
    dep = get_deployment(depid)
    if dep == {}:
        return redirect(url_for('home'))
    else:

        payload = {
                "endpoint": dep['outputs']['endpoint']
               }

        if 'node_ip' in dep['outputs']:
            api_startup = 'http://' + dep['outputs']['node_ip'] + ':5001/galaxyctl_api/v1.0/galaxy-startup'
        elif 'cluster_ip' in dep['outputs']:
            api_startup = 'http://' + dep['outputs']['cluster_ip'] + ':5001/galaxyctl_api/v1.0/galaxy-startup'
        else:
            return 'unavailable'

        response = requests.post(api_startup, json=payload, verify=False)

        deserialized_response = json.loads(response.text)

        return deserialized_response['galaxy']


@app.route('/ssh_keys')
def ssh_keys():
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    try:
        access_token = iam_blueprint.token['access_token']
    except Exception as e:
        flash("Token expired, realod page.", 'warning')
        return redirect(url_for('home'))

    connection = None
    cursor = None

    sshkey = get_ssh_pub_key()

    return render_template('ssh_keys.html', sshkey=sshkey)


def get_ssh_pub_key():

    # read database
    try:
        connection = getdbconnection()
        cursor = connection.cursor()

        query = ("SELECT sshkey FROM `users` WHERE `users`.`sub` = '{}'")
        read_cmd = query.format(session['userid'])
        cursor.execute(read_cmd)
        r = cursor.fetchone()
        if cursor.rowcount == 1:
            sshkey = r[0]
    except mysql.connector.Error as error:
        logexception("Reading user table {}".format(error))
    finally:
        if connection is not None:
            if connection.is_connected():
                if cursor is not None:
                    cursor.close()
                connection.close()

    return sshkey

@app.route('/update_ssh_key/<subject>', methods=['POST'])
def update_ssh_key(subject):
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    sshkey = request.form['sshkey']
    if str(check_ssh_key(sshkey.encode())) != "0":
        flash("Unvaild SSH public key. Please insert a correct one.", 'warning')
        return redirect(url_for('ssh_keys'))

    connection = None
    cursor = None

    # update database
    try:
        connection = getdbconnection()
        cursor = connection.cursor()
        update_query = ("UPDATE `users` SET `sshkey` = '{}' WHERE `sub` = '{}'")
        update_cmd = update_query.format(sshkey, session['userid'])
        cursor.execute(update_cmd)
        connection.commit()
    except mysql.connector.Error as error:
        logexception("updating users table {}".format(error))
    finally:
        if connection is not None:
            if connection.is_connected():
                if cursor is not None:
                    cursor.close()
                connection.close()

    return redirect(url_for('ssh_keys'))


def check_ssh_key(key):

    # credits to: https://gist.github.com/piyushbansal/5243418

    import base64,struct,sys,binascii
    array=key.split();

    # Each rsa-ssh key has 3 different strings in it, first one being
    # typeofkey second one being keystring third one being username .
    if len(array) != 3:
        return 1

    typeofkey=array[0]
    string=array[1]
    username=array[2]

    # must have only valid rsa-ssh key characters ie binascii characters 
    try :
        data=base64.decodestring(string)
    except binascii.Error:
        return 1

    a=4
    # unpack the contents of data, from data[:4] , it must be equal to 7 , property of ssh key .
    try :
        str_len = struct.unpack('>I', data[:a])[0]
    except struct.error :
        return 1

    # data[4:11] must have string which matches with the typeofkey , another ssh key property.
    if data[a:a+str_len] == typeofkey and int(str_len) == int(7): 
        return 0
    else:
        return 1


@app.route('/delete_ssh_key/<subject>')
def delete_ssh_key(subject):
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    try:
        access_token = iam_blueprint.token['access_token']

    except Exception as e:
        flash("Token expired, realod page.", 'warning')
        return redirect(url_for('home'))

    connection = None
    cursor = None

    # update database
    try:
        connection = getdbconnection()
        cursor = connection.cursor()
        update_query = ("UPDATE `users` SET `sshkey` = NULL WHERE `sub` = '{}'")
        update_cmd = update_query.format(session['userid'])
        cursor.execute(update_cmd)
        connection.commit()
    except mysql.connector.Error as error:
        logexception("updating users table {}".format(error))
    finally:
        if connection is not None:
            if connection.is_connected():
                if cursor is not None:
                    cursor.close()
                connection.close()

    privkey_key = session['userid'] + '/ssh_private_key'

    delete_secret_from_vault(access_token, privkey_key)

    return redirect(url_for('ssh_keys'))


@app.route('/create_ssh_key/<subject>')
def create_ssh_key(subject):
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    try:
        access_token = iam_blueprint.token['access_token']

    except Exception as e:
        flash("Token expired, realod page.", 'warning')
        return redirect(url_for('home'))

    privkey, pubkey = generate_ssh_key()

    privkey = privkey.decode("utf-8")

    privkey = privkey.replace("\n", "\\n")

    store_prikey_to_vault(access_token, privkey)

    connection = None
    cursor = None

    # update database
    try:
        connection = getdbconnection()
        cursor = connection.cursor()

        update_query = ("UPDATE `users` SET `sshkey` = '{}' WHERE `sub` = '{}'")
        update_cmd = update_query.format(pubkey.decode("utf-8"), session['userid'])
        cursor.execute(update_cmd)
        connection.commit()
    except mysql.connector.Error as error:
        logexception("updating users table {}".format(error))
    finally:
        if connection is not None:
            if connection.is_connected():
                if cursor is not None:
                    cursor.close()
                connection.close()

    return redirect(url_for('ssh_keys'))

def generate_ssh_key():

    from cryptography.hazmat.primitives import serialization as crypto_serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend as crypto_default_backend
    
    key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=65537,
        key_size=2048
    )
    private_key = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.PKCS8,
        crypto_serialization.NoEncryption())
    public_key = key.public_key().public_bytes(
        crypto_serialization.Encoding.OpenSSH,
        crypto_serialization.PublicFormat.OpenSSH
    )

    return private_key, public_key


def store_prikey_to_vault(access_token, privkey_value):

    vault = VaultIntegration(vault_url, iam_base_url, iam_client_id, iam_client_secret, vault_bound_audience, access_token, vault_secrets_path)

    auth_token = vault.get_auth_token()

    write_token = vault.get_token(auth_token, vault_write_policy, vault_write_token_time_duration, vault_wtite_token_renewal_time_duration)

    secret_path = session['userid'] + '/ssh_private_key'
    privkey_key = 'ssh_private_key'

    response_output = vault.write_secret(write_token, secret_path, privkey_key, privkey_value)

    vault.revoke_token(auth_token)

    return response_output


@app.route('/read_privkey_from_vault/<subject>')
def read_privkey_from_vault(subject):
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    try:
        access_token = iam_blueprint.token['access_token']

    except Exception as e:
        flash("Token expired, realod page.", 'warning')
        return redirect(url_for('home'))


    vault = VaultIntegration(vault_url, iam_base_url, iam_client_id, iam_client_secret, vault_bound_audience, access_token, vault_secrets_path)

    auth_token = vault.get_auth_token()

    read_token = vault.get_token(auth_token, vault_read_policy, vault_read_token_time_duration, vault_read_token_renewal_duration)

    secret_path = session['userid'] + '/ssh_private_key'
    privkey_key = 'ssh_private_key'

    response_output = vault.read_secret(read_token, secret_path, privkey_key)

    vault.revoke_token(auth_token)

    return response_output
