# Copyright (c) Istituto Nazionale di Fisica Nucleare (INFN). 2019-2020
# Modifications Copyright (c) CNR-IBIOM and ELIXIR-IT. 2024-2026
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

from app import app

settingsDir = app.config['SETTINGS_DIR'] + "/"
toscaDir = app.config['TOSCA_TEMPLATES_DIR'] + "/"
toscaParamsDir = app.config.get('SETTINGS_DIR') + "/tosca-parameters"
toscaMetadataDir = app.config.get('SETTINGS_DIR') + "/tosca-metadata"

# IAM
iamUrl = app.config['IAM_BASE_URL']
iamClientID = app.config.get('IAM_CLIENT_ID')
iamClientSecret = app.config.get('IAM_CLIENT_SECRET')
iamGroups = app.config.get('IAM_GROUP_MEMBERSHIP')

# Keycloak
keycloakUrl = app.config['KEYCLOAK_BASE_URL']
keycloakClientID = app.config.get('KEYCLOAK_CLIENT_ID')
keycloakClientSecret = app.config.get('KEYCLOAK_CLIENT_SECRET')
keycloakRealm = app.config.get('KEYCLOAK_REALM')
keycloakGroups = app.config.get('KEYCLOAK_GROUP_MEMBERSHIP')

tempSlamUrl = app.config.get('SLAM_URL')

orchestratorUrl = app.config['ORCHESTRATOR_URL']
###
laniakeaApiUrl = app.config.get('CORE_URL', '')
###
orchestratorConf = {
  'cmdb_url': app.config.get('CMDB_URL'),
  'slam_url': tempSlamUrl + "/rest/slam",
  'im_url': app.config.get('IM_URL'),
  'monitoring_url': app.config.get('MONITORING_URL', ''),
  'vault_url': app.config.get('VAULT_URL')
}

