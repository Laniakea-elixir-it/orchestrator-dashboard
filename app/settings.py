from app import app

toscaDir = app.config['TOSCA_TEMPLATES_DIR'] + "/"
toscaParamsDir = app.config.get('TOSCA_PARAMETERS_DIR')
toscaMetadataDir = app.config.get('TOSCA_METADATA_DIR')
orchestratorUrl = app.config['ORCHESTRATOR_URL']

iamUrl = app.config['IAM_BASE_URL']
iamClientID = app.config.get('IAM_CLIENT_ID')
iamClientSecret = app.config.get('IAM_CLIENT_SECRET')

tempSlamUrl = app.config.get('SLAM_URL') if app.config.get('SLAM_URL') else "" 

orchestratorConf = {
  'cdb_url': app.config.get('CMDB_URL'),
  'slam_url': tempSlamUrl + "/rest/slam",
  'im_url': app.config.get('IM_URL')
}

external_links = app.config.get('EXTERNAL_LINKS') if app.config.get('EXTERNAL_LINKS') else []

enable_advanced_menu = app.config.get('ENABLE_ADVANCED_MENU') if app.config.get('ENABLE_ADVANCED_MENU') else "no"

iamGroups = app.config.get('IAM_GROUP_MEMBERSHIP')
