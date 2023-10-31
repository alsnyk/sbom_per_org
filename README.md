# sbom_per_org
This script generates one sbom for one Snyk org

# Instructions 

1. Install Cyclonedx CLI
https://github.com/CycloneDX/cyclonedx-cli#homebrew
```brew install cyclonedx/cyclonedx/cyclonedx-cli```
2. Add `org_id` and `snyk_api_token` to sbom_poc_config.json
2. Install dependencies
```pip install -r requirements.txt```
3. Run Script 
```python3 sbom_script.py```