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

# initialize SQLAlchemy
db: SQLAlchemy = SQLAlchemy()

# initialize Migrate
migrate: Migrate = Migrate()

# Intialize Alembic
alembic: Alembic = Alembic()

# initialize Vault
vaultservice: Vault = Vault()

app = Flask(__name__, instance_relative_config=True)
app.wsgi_app = ProxyFix(app.wsgi_app)
app.secret_key = "30bb7cf2-1fef-4d26-83f0-8096b6dcc7a3"
app.config.from_object('config.default')
app.config.from_file('config.json', json.load)
app.config.from_file('../config/schemas/metadata_schema.json', json.load)

if app.config.get("FEATURE_VAULT_INTEGRATION") == "yes":
    app.config.from_file('vault-config.json', json.load)

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
        not_granted_access_tag=app.config.get("NOT_GRANTED_ACCESS_TAG")
    )


db.init_app(app)
migrate.init_app(app, db)
alembic.init_app(app, run_mkdir=False)

app.config['CACHE_TYPE'] = 'RedisCache'
app.config['CACHE_REDIS_URL'] = app.config.get('REDIS_URL')
redis_client = FlaskRedis(app)
cache = Cache(app)

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
