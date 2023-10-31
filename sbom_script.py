#!/usr/bin/python3
#
# PoC for generating an SBOM using Snyk

import requests
import json
import subprocess


snyk_sbom_api = "https://api.snyk.io/rest/orgs/"
version = '2023-09-20'
snyk_params = {'version':{version}, 'format':'cyclonedx1.4+json'} 
config_file = 'sbom_poc_config.json'

def get_config():
    try:
        with open(config_file) as config:
            config = json.load(config)
    except:
        exit(f"Unable to open config file {config_file}. Quitting")
    return config


def get_all_projects_in_org(org_id, snyk_header):
    """Retrieve all projects in a Snyk Organization
    """
    projects = []
    url = f'{snyk_sbom_api}{org_id}/projects?version={version}&limit=100'
    
    # pagination
    while True:
        response = requests.request(
            'GET',
            url,
            headers=snyk_header
            )

        response_json = json.loads(response.content)

        if 'data' in response_json:
            projects = projects + response_json['data']

        if 'next' not in response_json['links'] or response_json['links']['next'] == '':
            break
        url = f"{snyk_sbom_api}/{response_json['links']['next']}"
        

    return projects 

def mergeSBOMs(sbom_file_names):
    # merge sboms here with cyclonedx

    command = ['cyclonedx', 'merge']
    command += ['--input-files'] + sbom_file_names
    command += ['--output-file', 'org_sbom.json', '--output-format', 'json']
    subprocess.run(command)

def main():
    sbom_file_names= []
    config = get_config()
    snyk_header = {
                   'Authorization':'token ' + config['snyk_api_token'], 
                   'Content-Type': 'application/json'
                   }

    all_proj_list = get_all_projects_in_org(config['org_id'], snyk_header)

    final_proj_list = []
    for project in all_proj_list:
        if project['attributes']['type'] not in ['sast', 'cloudformationconfig', 'helmconfig', 'k8sconfig', 'terraformconfig']:
            final_proj_list.append([project['id'], project['attributes']['name']])
    
    # out_file_name = "sbom_output.json"
    
    for project_id in final_proj_list:
        result = requests.get(snyk_sbom_api + config['org_id'] + '/projects/' + project_id[0] + '/sbom', params=snyk_params, headers=snyk_header)
        
        if result.status_code != 200:
            print(f"Failed to generate SBOM for {project_id} because {result.status_code}")
        else:
            out_file_name = f"sbom_{project_id[1].split('/')[-1]}.json"
            sbom_file_names.append(out_file_name)
            results = json.dumps(result.json(), indent=4)
            with open(out_file_name,'w') as outfile:
                outfile.write(results)

    mergeSBOMs(sbom_file_names)

if __name__ == "__main__":
    main()
