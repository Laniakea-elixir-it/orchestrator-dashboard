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

from flask import Blueprint, render_template, flash, request, redirect, url_for, session, json
from app import app, iam_blueprint, vaultservice
from app.lib import auth, utils, sshkey as sshkeyhelpers, settings, dbhelpers, keycloak
from app.providers import sla
from app.models.Deployment import Deployment
from app.models.User import User
import json
import requests

from app.lib.keycloak import KC_REALM_URL

laniakea_v399_bp = Blueprint('laniakea_v399_bp', __name__, template_folder='templates', static_folder='static')
