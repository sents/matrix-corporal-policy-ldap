import re
import json
import requests
from ldap3 import Connection
from urllib.parse import urljoin

name = "matrix-corporal-policy-ldap"

userlist_endpoint = '_synapse/admin/v2/users?from=0'
username_regex = '@([a-z0-9._=\\-\\/]+):'

class Policy:
    def __init__(self, configfile):
        with open(configfile, "r") as f:
            config = json.load(f)
        self.corporal = config["corporal"]
        self.ldap = config["ldap"]
        self.user_mode = config["user_mode"]
        self.servername = config["homeserver_domain_name"]
        self.address = config["homeserver_api_endpoint"]
        self.token = config["admin_auth_token"]
        self.groups = config["groups"]
        self.users = config["users"]
        self.connection = Connection(self.ldap["url"],
                                     self.ldap["binddn"],
                                     self.ldap["binddn_pw"])
        self.user_regex = username_regex + re.escape(self.servername)

    def bind(self):
        try:
            self.connection.rebind()
        except Exception as e:
            raise RuntimeError(
                "Failed to connect to LDAP server: {}".format(e.args)
            )

    def get_matrix_users(self):
        req = requests.get(
            urljoin(self.address, userlist_endpoint),
            headers={"Authorization": "Bearer {}".format(self.token)}
        )
        if req.status_code != 200:
            raise requests.exceptions.HTTPError(
                "Failed to fetch userlist. Status: {},Reason:{}".format(req.status_code,
                                                                        req.reason))
        users = [userdic["name"] for userdic in req.json()["users"]
                 if not userdic["deactivated"]]
        users = []
