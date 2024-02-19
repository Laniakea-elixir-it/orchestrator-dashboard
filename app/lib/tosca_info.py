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
import os
import io
from fnmatch import fnmatch
import uuid
import yaml
import jsonschema


class ToscaInfo:
    """Class to load tosca templates and metadata at application start"""

    def __init__(self, redis_client, tosca_dir, settings_dir, metadata_schema):
        """
        Initialize the flask extension
        :param tosca_dir: the dir of the tosca templates
        :param settings_dir: the dir of the params and metadata files
        """
        self.redis_client = redis_client
        self.tosca_dir = tosca_dir + '/'
        self.tosca_params_dir = settings_dir + '/tosca-parameters'
        self.tosca_metadata_dir = settings_dir + '/tosca-metadata'
        self.metadata_schema = metadata_schema

        tosca_info = {}
        tosca_gmetadata = {}
        tosca_templates = []

        tosca_templates = self._loadtoscatemplates()
        tosca_info = self._extractalltoscainfo(tosca_templates)
        tosca_gmetadata = self._loadmetadata()

        redis_client.set("tosca_templates", json.dumps(tosca_templates))
        redis_client.set("tosca_gmetadata", json.dumps(tosca_gmetadata))
        redis_client.set("tosca_info", json.dumps(tosca_info))


    def reload(self):
        tosca_templates = self._loadtoscatemplates()
        tosca_info = self._extractalltoscainfo(tosca_templates)
        tosca_gmetadata = self._loadmetadata()

        self.redis_client.set("tosca_templates", json.dumps(tosca_templates))
        self.redis_client.set("tosca_gmetadata", json.dumps(tosca_gmetadata))
        self.redis_client.set("tosca_info", json.dumps(tosca_info))

    def _loadmetadata(self):
        if os.path.isfile(self.tosca_metadata_dir + "/metadata.yml"):
            with io.open(self.tosca_metadata_dir + "/metadata.yml") as stream:
                metadata = yaml.full_load(stream)

                # validate against schema
                jsonschema.validate(metadata, self.metadata_schema, format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER)
                #tosca_gmetadata = {service["id"]: {k: v for k, v in service.items() if k != "id"} for service in metadata['services']}
                tosca_gmetadata = {str(uuid.uuid4()): service for service in metadata['services']}
                return tosca_gmetadata

    
    def _loadtoscatemplates(self):
        toscatemplates = []
        for path, subdirs, files in os.walk(self.tosca_dir):
            for name in files:
                if fnmatch(name, "*.yml") or fnmatch(name, "*.yaml"):
                    # skip hidden files
                    if name[0] != '.':
                        toscatemplates.append(os.path.relpath(os.path.join(path, name), self.tosca_dir))

        return sorted(toscatemplates)

    def _extractalltoscainfo(self, tosca_templates):
        tosca_info = {}
        for tosca in tosca_templates:
            with io.open(self.tosca_dir + tosca) as stream:
                template = yaml.full_load(stream)
                tosca_info[tosca] = self.extracttoscainfo(template, tosca)
                #info = self.extracttoscainfo(template, tosca)
                #tosca_info[info.get('id')] = info
        return tosca_info

    def extracttoscainfo(self, template, tosca):
        
        tosca_info = {
            "valid": True,
            "description": "TOSCA Template",
            "metadata": {
                "icon": "https://cdn4.iconfinder.com/data/icons/mosaicon-04/512/websettings-512.png",
                "visibility": { "type": "public" },
                "require_ssh_key": True,
                "template_type": ""
            },
            "enable_config_form": False,
            "inputs": {},
            "outputs": {},
            "node_templates": {},
            "policies": {},
            "tabs": {},
            "metadata_file": "",
            "parameters_file": ""
        }

        if 'topology_template' not in template:
            tosca_info["valid"] = False

        else:

            if 'description' in template:
                tosca_info["description"] = template['description']

            if 'metadata' in template and template['metadata'] is not None:
                for k, v in template['metadata'].items():
                    tosca_info["metadata"][k] = v

            if tosca and self.tosca_metadata_dir:
                tosca_metadata_path = self.tosca_metadata_dir + "/"
                for mpath, msubs, mnames in os.walk(tosca_metadata_path):
                    for mname in mnames:
                        fmname = os.path.relpath(os.path.join(mpath, mname), self.tosca_metadata_dir)
                        if fnmatch(fmname, os.path.splitext(tosca)[0] + '.metadata.yml') or \
                                fnmatch(fmname, os.path.splitext(tosca)[0] + '.metadata.yaml'):
                            # skip hidden files
                            if mname[0] != '.':
                                tosca_metadata_file = os.path.join(mpath, mname)
                                with io.open(tosca_metadata_file) as metadata_file:
                                    tosca_info['metadata_file'] = metadata_file.read()
                                    metadata_template = yaml.full_load(io.StringIO(tosca_info['metadata_file']))

                                    if 'metadata' in metadata_template \
                                            and metadata_template['metadata'] is not None:
                                        for k, v in metadata_template['metadata'].items():
                                            tosca_info["metadata"][k] = v

            # override description from metadata, if available
            if 'description' in tosca_info['metadata']:
                tosca_info["description"] = tosca_info['metadata']['description']

            # initialize inputs/outputs
            tosca_inputs = {}
            tosca_outputs = {}
            # get inputs/outputs from template, if provided
            if 'inputs' in template['topology_template']:
                tosca_inputs = template['topology_template']['inputs']
                tosca_info['inputs'] = tosca_inputs
            if 'outputs' in template['topology_template']:
                tosca_outputs = template['topology_template']['outputs']
                tosca_info['outputs'] = tosca_outputs

            if 'node_templates' in template['topology_template']:
                tosca_info['deployment_type'] = getdeploymenttype(template['topology_template']['node_templates'])

            if 'policies' in template['topology_template']:
                tosca_info['policies'] = template['topology_template']['policies']

            # add parameters code here
            if tosca and self.tosca_params_dir:
                tosca_pars_path = self.tosca_params_dir + "/"  # this has to be reassigned here because is local.
                for fpath, subs, fnames in os.walk(tosca_pars_path):
                    for fname in fnames:
                        ffname = os.path.relpath(os.path.join(fpath, fname), self.tosca_params_dir)
                        if fnmatch(ffname, os.path.splitext(tosca)[0] + '.parameters.yml') or \
                                fnmatch(ffname, os.path.splitext(tosca)[0] + '.parameters.yaml'):
                            # skip hidden files
                            if fname[0] != '.':
                                tosca_pars_file = os.path.join(fpath, fname)
                                with io.open(tosca_pars_file) as pars_file:
                                    tosca_info['enable_config_form'] = True
                                    tosca_info['parameters_file'] = pars_file.read()
                                    pars_data = yaml.full_load(io.StringIO(tosca_info['parameters_file']))
                                    pars_inputs = pars_data["inputs"]
                                    tosca_info['inputs'] = {**tosca_inputs, **pars_inputs}
                                    if "outputs" in pars_data:
                                        pars_outputs = pars_data["outputs"]
                                        tosca_info['outputs'] = {**tosca_outputs, **pars_outputs}
                                    if "tabs" in pars_data:
                                        tosca_info['tabs'] = pars_data["tabs"]

            updatable = updatabledeployment(tosca_info['inputs'])
            tosca_info['updatable'] = updatable
        return tosca_info

    def get(self):
        serialised_value = self.redis_client.get("tosca_templates")
        tosca_templates = json.loads(serialised_value)
        serialised_value = self.redis_client.get("tosca_gmetadata")
        tosca_gmetadata = json.loads(serialised_value)
        serialised_value = self.redis_client.get("tosca_info")
        tosca_info = json.loads(serialised_value)
        return tosca_info, tosca_templates, tosca_gmetadata


# Helper functions
def getdeploymenttype(nodes):
    deployment_type = ""
    for (j, u) in nodes.items():
        if deployment_type == "":
            for (k, v) in u.items():
                if k == "type" and v == "tosca.nodes.indigo.Compute":
                    deployment_type = "CLOUD"
                    break
                if k == "type" and v == "tosca.nodes.indigo.Container.Application.Docker.Marathon":
                    deployment_type = "MARATHON"
                    break
                if k == "type" and v == "tosca.nodes.indigo.Container.Application.Docker.Chronos":
                    deployment_type = "CHRONOS"
                    break
                if k == "type" and v == "tosca.nodes.indigo.Qcg.Job":
                    deployment_type = "QCG"
                    break
    return deployment_type


def getslapolicy(template):
    sla_id = ''
    if 'policies' in template:
        for policy in template['policies']:
            if sla_id == '':
                for (k, v) in policy.items():
                    if "type" in v \
                            and (v['type'] == 'tosca.policies.indigo.SlaPlacement'
                                 or v['type'] == 'tosca.policies.Placement'):
                        if 'properties' in v:
                            sla_id = v['properties']['sla_id'] if 'sla_id' in v['properties'] \
                                else ''
                        break
    return sla_id


def eleasticdeployment(template):
    return hasnodeoftype(template, 'tosca.nodes.indigo.ElasticCluster')


def updatabledeployment(inputs):
    updatable = False
    for key, value in inputs.items():
        if 'updatable' in value:
            if value['updatable'] == True:
                updatable = True
                break

    return updatable

def hasnodeoftype(template, nodetype):
    found = False
    if 'topology_template' in template:
        if 'node_templates' in template['topology_template']:
            for (j, u) in template['topology_template']['node_templates'].items():
                if found:
                    break
                for (k, v) in u.items():
                    if k == 'type' and nodetype in v:
                        found = True
                        break
    return found
