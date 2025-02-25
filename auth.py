import requests
from bs4 import BeautifulSoup
import json
import re

# Disable SSL warnings (since validate_certs=no in Ansible)
requests.packages.urllib3.disable_warnings()

# Configuration
base_url = "https://wuepgtovmanage.sdwan.cisco.com:443"
initial_url = f"{base_url}/j_security_check"
token_url = f"{base_url}/dataservice/client/token"
sso_username = "svc-APP2000405-prod@external.mcd.com"
username = "svc-APP2000405-prod"
password = "H2towUSt1Qi1ayij"

# Create a session to persist cookies
session = requests.Session()

# Step 1: Initial POST to j_security_check
initial_payload = {
    "j_username": sso_username,
    "j_password": password
}
response = session.post(initial_url, data=initial_payload, verify=False, allow_redirects=True)

# Step 2: Handle SAML redirect to Microsoft login
soup = BeautifulSoup(response.text, "html.parser")
if "login.microsoftonline.com" in response.url:
    # Extract form data if present (e.g., SAMLRequest, RelayState)
    form = soup.find("form")
    if form:
        action_url = form.get("action")
        if not action_url.startswith("http"):
            action_url = "https://login.microsoftonline.com" + action_url
        
        # Prepare form data
        form_data = {}
        for input_tag in form.find_all("input"):
            name = input_tag.get("name")
            value = input_tag.get("value", "")
            if name:
                form_data[name] = value
        
        # Submit the SSO username
        form_data["login"] = sso_username
        form_data["loginfmt"] = sso_username  # Sometimes required by Azure AD
        response = session.post(action_url, data=form_data, verify=False, allow_redirects=True)
        soup = BeautifulSoup(response.text, "html.parser")

    # Step 3: Handle username/password prompt
    if "password" in response.text.lower():
        # Extract the form action URL and hidden inputs
        form = soup.find("form")
        if form:
            action_url = form.get("action")
            if not action_url.startswith("http"):
                action_url = "https://login.microsoftonline.com" + action_url
            
            # Prepare credentials payload
            cred_payload = {}
            for input_tag in form.find_all("input"):
                name = input_tag.get("name")
                value = input_tag.get("value", "")
                if name:
                    cred_payload[name] = value
            
            cred_payload["username"] = username
            cred_payload["passwd"] = password
            
            # Submit credentials
            response = session.post(action_url, data=cred_payload, verify=False, allow_redirects=True)
            soup = BeautifulSoup(response.text, "html.parser")

# Step 4: Retrieve the token
token_response = session.get(token_url, verify=False)
if token_response.status_code == 200:
    print(token_response.text.strip())  # Output the token
else:
    print(f"Failed to retrieve token. Status: {token_response.status_code}, Response: {token_response.text}")
