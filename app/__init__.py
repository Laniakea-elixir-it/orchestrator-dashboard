# Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2019-2020
# Copyright (c) CNR-IBIOM. 2024-2026
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
import json
import sys
import socket

from flask import Flask
from flask_alembic import Alembic
from sqlalchemy_utils import database_exists, create_database
from sqlalchemy import Table, Column, String, MetaData
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_dance.consumer import OAuth2ConsumerBlueprint
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, upgrade
from flask_caching import Cache
from flask_redis import FlaskRedis
from app.lib.tosca_info import ToscaInfo
from app.lib.Vault import Vault

import logging
import os
import yaml

# initialize SQLAlchemy
db: SQLAlchemy = SQLAlchemy()

# initialize Migrate
migrate: Migrate = Migrate()

# Intialize Alembic
alembic: Alembic = Alembic()

# initialize Vault
vaultservice: Vault = Vault()

# Map config.yml to app config parameters
# TODO move this in a separate .py
def load_mapper_config(cfg):
    core = cfg.get("core", {})
    oidc = cfg.get("oidc", {})
    iam = oidc.get("iam", {})
    keycloak = oidc.get("keycloak", {})
    paas = cfg.get("paas_orchestrator", {})
    dashboard = cfg.get("dashboard", {})
    mail = dashboard.get("mail", {})
    vault = cfg.get("vault", {})

    mapper = {
        # Core
        "CORE_URL": core.get("core_url"),
        "METADATA_FILE": core.get("metadata_file"),
        "PARAMETERS_DIR": core.get("parameters_dir"),
        "CALLBACK_URL": core.get("callback_url"),
        "SQLALCHEMY_DATABASE_URI": core.get("sqlalchemy_db_uri"),
        "REDIS_URL": core.get("redis_url"),
        # OIDC
        "IAM_CLIENT_ID": iam.get("client_id"),
        "IAM_CLIENT_SECRET": iam.get("client_secret"),
        "IAM_BASE_URL": iam.get("base_url"),
        "IAM_GROUP_MEMBERSHIP": iam.get("group_membership", []),
        "KEYCLOAK_CLIENT_ID": keycloak.get("client_id"),
        "KEYCLOAK_CLIENT_SECRET": keycloak.get("client_secret"),
        "KEYCLOAK_BASE_URL": keycloak.get("base_url"),
        "KEYCLOAK_GROUP_MEMBERSHIP": keycloak.get("group_membership", []),
        # Legacy PaaS
        "ORCHESTRATOR_URL": paas.get("orchestrator_url"),
        "IM_URL": paas.get("im_url"),
        "CMDB_URL": paas.get("cmdb_url"),
        "SLAM_URL": paas.get("slam_url"),
        "MONITORING_URL": paas.get("monitoring_url", ""),
        "TOSCA_TEMPLATES_DIR": paas.get("tosca_template_dir"),
        "SETTINGS_DIR": paas.get("settings_dir"),
        "UPLOAD_FOLDER": paas.get("upload_folder"),
        # Dashboard
        "EXTERNAL_LINKS": dashboard.get("external_links", []),
        "CONFIGURATION_PROFILE": dashboard.get("configuration_profile"),
        "ADMINS": dashboard.get("admins", []),
        "SUPPORT_EMAIL": dashboard.get("support_email"),
        "FEATURE_ADVANCED_MENU": dashboard.get("feature_advanced_menu", "no"),
        "FEATURE_S3CREDS_MENU": dashboard.get("feature_s3creds_menu", "no"),
        "FEATURE_UPDATE_DEPLOYMENT": dashboard.get("feature_update_deployment", "no"),
        "LOG_LEVEL": dashboard.get("log_level", "INFO"),
        "MAIL_SERVER": mail.get("server"),
        "MAIL_PORT": int(mail.get("port", 465)) if mail.get("port") else 465,
        "MAIL_SENDER": mail.get("sender"),
        "MAIL_USERNAME": mail.get("username"),
        "MAIL_PASSWORD": mail.get("password"),
        "MAIL_USE_TLS": mail.get("use_tls", False),
        "MAIL_USE_SSL": mail.get("use_ssl", False),
        # Vault
        "FEATURE_VAULT_INTEGRATION": vault.get("enabled", "no"),
        "VAULT_URL": vault.get("url"),
        "VAULT_ROLE": vault.get("role"),
        "VAULT_OIDC_AUDIENCE": vault.get("oidc_audience"),
        "VAULT_BOUND_AUDIENCE": vault.get("bound_audience"),
        "VAULT_SECRETS_PATH": vault.get("secrets_path"),
        "WRAPPING_TOKEN_TIME_DURATION": vault.get("wrapping_token_time_duration"),
        "READ_POLICY": vault.get("read_policy"),
        "READ_TOKEN_TIME_DURATION": vault.get("read_token_time_duration"),
        "READ_TOKEN_RENEWAL_TIME_DURATION": vault.get("read_token_renewal_time_duration"),
        "WRITE_POLICY": vault.get("write_policy"),
        "WRITE_TOKEN_TIME_DURATION": vault.get("write_token_time_duration"),
        "WRITE_TOKEN_RENEWAL_TIME_DURATION": vault.get("write_token_renewal_time_duration"),
        "DELETE_POLICY": vault.get("delete_policy"),
        "DELETE_TOKEN_TIME_DURATION": vault.get("delete_token_time_duration"),
        "DELETE_TOKEN_RENEWAL_TIME_DURATION": vault.get("delete_token_renewal_time_duration"),
    }

    return {k: v for k, v in mapper.items() if v is not None}

def load_yaml(path):
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}

app = Flask(__name__, instance_relative_config=True)
app.wsgi_app = ProxyFix(app.wsgi_app)
app.secret_key = "30bb7cf2-1fef-4d26-83f0-8096b6dcc7a3"
app.config.from_object('config.default')
config_path = os.path.join(app.instance_path, "config.yml")
yaml_cfg = load_yaml(config_path)
mapped_cfg = load_mapper_config(yaml_cfg)
app.config.update(mapped_cfg)
app.config.from_file('../config/schemas/metadata_schema.json', json.load)

# TODO REMOVE: Vault config json moved to config.yml
#if app.config.get("FEATURE_VAULT_INTEGRATION") == "yes":
#    app.config.from_file('vault-config.json', json.load)

# TODO check for AWS creds for deployments
# move to a separated file for aws and one for app creds
if app.config.get("FEATURE_S3CREDS_MENU") == "yes":
    app.config.from_file('s3-config.json', json.load)

profile = app.config.get('CONFIGURATION_PROFILE')
if profile is not None and profile != 'default':
    app.config.from_object('config.' + profile)


@app.context_processor
def inject_settings():
    return dict(
        footer_template=app.config.get('FOOTER_TEMPLATE'),
        welcome_message=app.config.get('WELCOME_MESSAGE'),
        navbar_brand_text=app.config.get('NAVBAR_BRAND_TEXT'),
        navbar_brand_icon=app.config.get('NAVBAR_BRAND_ICON'),
        favicon_path=app.config.get('FAVICON_PATH'),
        privacy_policy_url=app.config.get('PRIVACY_POLICY_URL'),
        mail_image_src=app.config.get('MAIL_IMAGE_SRC'),
        enable_vault_integration=False if app.config.get('FEATURE_VAULT_INTEGRATION').lower() == 'no' else True,
        external_links=app.config.get('EXTERNAL_LINKS') if app.config.get('EXTERNAL_LINKS') else [],
        enable_advanced_menu=app.config.get('FEATURE_ADVANCED_MENU') if app.config.get(
            'FEATURE_ADVANCED_MENU') else "no",
        enable_update_deployment=app.config.get('FEATURE_UPDATE_DEPLOYMENT') if app.config.get(
            'FEATURE_UPDATE_DEPLOYMENT') else "no",
        require_ssh_pubkey=app.config.get('FEATURE_REQUIRE_USER_SSH_PUBKEY') if app.config.get(
            'FEATURE_REQUIRE_USER_SSH_PUBKEY') else "no",
        hidden_deployment_columns=app.config.get('FEATURE_HIDDEN_DEPLOYMENT_COLUMNS') if app.config.get(
            'FEATURE_HIDDEN_DEPLOYMENT_COLUMNS') else "",
        enable_ports_request=app.config.get('FEATURE_PORTS_REQUEST') if app.config.get(
            'FEATURE_PORTS_REQUEST') else "no",
        enable_s3creds=app.config.get('FEATURE_S3CREDS_MENU') if app.config.get(
            'FEATURE_S3CREDS_MENU') else "no",
        s3_allowed_groups=app.config.get("S3_IAM_GROUPS") if app.config.get("S3_IAM_GROUPS") else [],
        enable_access_request=app.config.get("FEATURE_ACCESS_REQUEST") if app.config.get(
            'FEATURE_ACCESS_REQUEST') else "no",
        not_granted_access_tag=app.config.get("NOT_GRANTED_ACCESS_TAG"),
        enable_luks_api_integration=app.config.get('EXTRA_FEATURE_LUKS_API_INTEGRATION') if app.config.get(
            'EXTRA_FEATURE_LUKS_API_INTEGRATION') else "no",
        enable_laniakea_utils=app.config.get('EXTRA_FEATURE_LANIAKEA_UTILS_INTEGRATION') if app.config.get(
            'EXTRA_FEATURE_LANIAKEA_UTILS_INTEGRATION') else "no",
        enable_laniakea_nebula=app.config.get('EXTRA_FEATURE_LANIAKEA_NEBULA_INTEGRATION') if app.config.get(
            'EXTRA_FEATURE_LANIAKEA_NEBULA_INTEGRATION') else "no"
    )


db.init_app(app)
migrate.init_app(app, db)
alembic.init_app(app, run_mkdir=False)

app.config['CACHE_TYPE'] = 'RedisCache'
app.config['CACHE_REDIS_URL'] = app.config.get('REDIS_URL')
redis_client = FlaskRedis(app)
cache = Cache(app)

from flask_session import Session

app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis_client._redis_client
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
Session(app)

if app.config.get("FEATURE_VAULT_INTEGRATION") == "yes":
    vaultservice.init_app(app)

mail = Mail(app)

# initialize ToscaInfo
tosca: ToscaInfo = ToscaInfo(redis_client, app.config.get("TOSCA_TEMPLATES_DIR"),
                             app.config.get("SETTINGS_DIR"), app.config.get("METADATA_SCHEMA"))

from app.errors.routes import errors_bp
app.register_blueprint(errors_bp)

iam_base_url = app.config['IAM_BASE_URL']
iam_token_url = iam_base_url + '/token'
iam_refresh_url = iam_base_url + '/token'
iam_authorization_url = iam_base_url + '/authorize'

iam_blueprint = OAuth2ConsumerBlueprint(
    "iam", __name__,
    client_id=app.config['IAM_CLIENT_ID'],
    client_secret=app.config['IAM_CLIENT_SECRET'],
    base_url=iam_base_url,
    token_url=iam_token_url,
    auto_refresh_url=iam_refresh_url,
    authorization_url=iam_authorization_url,
    redirect_to='home'
)
app.register_blueprint(iam_blueprint, url_prefix="/login")

# Keycloak blueprint
keycloak_base_url = app.config['KEYCLOAK_BASE_URL']
keycloak_token_url         = keycloak_base_url + '/protocol/openid-connect/token'
keycloak_refresh_url       = keycloak_base_url + '/protocol/openid-connect/token'
keycloak_authorization_url = keycloak_base_url + '/protocol/openid-connect/auth'
keycloak_blueprint = OAuth2ConsumerBlueprint(
    "keycloak", __name__,
    client_id=app.config['KEYCLOAK_CLIENT_ID'],
    client_secret=app.config['KEYCLOAK_CLIENT_SECRET'],
    base_url=keycloak_base_url,
    token_url=keycloak_token_url,
    auto_refresh_url=keycloak_refresh_url,
    authorization_url=keycloak_authorization_url,
    scope="openid email profile offline_access",
    redirect_to='home'
)

app.register_blueprint(keycloak_blueprint, url_prefix="/login")

from app.home.routes import home_bp
app.register_blueprint(home_bp, url_prefix="/home")

from app.users.routes import users_bp
app.register_blueprint(users_bp, url_prefix="/users")

from app.deployments.routes import deployments_bp
app.register_blueprint(deployments_bp, url_prefix="/deployments")

from app.providers.routes import providers_bp
app.register_blueprint(providers_bp, url_prefix="/providers")

from app.swift.routes import swift_bp
app.register_blueprint(swift_bp, url_prefix="/swift")

from app.services.routes import services_bp
app.register_blueprint(services_bp, url_prefix="/services")

if app.config.get("FEATURE_VAULT_INTEGRATION") == "yes":
    from app.vault.routes import vault_bp
    app.register_blueprint(vault_bp, url_prefix="/vault")

if app.config.get("EXTRA_FEATURE_LUKS_API_INTEGRATION") == "yes":
    from app.extra.luks_api.routes import luks_api_bp
    app.register_blueprint(luks_api_bp, url_prefix="/luks_api")

if app.config.get("EXTRA_FEATURE_LANIAKEA_UTILS_INTEGRATION") == "yes":
    from app.extra.laniakea_utils.routes import laniakea_utils_bp
    app.register_blueprint(laniakea_utils_bp, url_prefix="/laniakea_utils")

if app.config.get("EXTRA_FEATURE_LANIAKEA_NEBULA_INTEGRATION") == "yes":
    from app.extra.laniakea_nebula.routes import laniakea_nebula_bp
    app.register_blueprint(laniakea_nebula_bp, url_prefix="/laniakea_nebula")

# logging
loglevel = app.config.get("LOG_LEVEL") if app.config.get("LOG_LEVEL") else "INFO"
numeric_level = getattr(logging, loglevel.upper(), None)
if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: %s' % loglevel)

logging.basicConfig(level=numeric_level)

# check if database exists
engine = db.get_engine(app)
if not database_exists(engine.url):  # Checks for the first time
    create_database(engine.url)  # Create new DB
    if database_exists(engine.url):
        app.logger.debug("New database created")
    else:
        app.logger.debug("Cannot create database")
        sys.exit()
else:
    # for compatibility with old non-orm version
    # check if existing db is not versioned
    if engine.dialect.has_table(engine.connect(), "deployments"):
        if not engine.dialect.has_table(engine.connect(), "alembic_version"):
            # create versioning table and assign initial release
            baseversion = app.config['SQLALCHEMY_VERSION_HEAD']
            meta = MetaData()
            alembic_version = Table(
                'alembic_version',
                meta,
                Column('version_num', String(32), primary_key=True),
            )
            meta.create_all(engine)
            ins = alembic_version.insert().values(version_num=baseversion)
            conn = engine.connect()
            result = conn.execute(ins)

# update database, run flask_migrate.upgrade()
with app.app_context():
    upgrade()

# IP of server
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    # doesn't even have to be reachable
    s.connect(('10.255.255.255', 1))
    app.ip = s.getsockname()[0]
except:
    app.ip = '127.0.0.1'
finally:
    s.close()

# add route /info
from app import info


if __name__ == "__main__":
    app.run(host='0.0.0.0')
