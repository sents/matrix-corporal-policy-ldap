import re
from os import path
import json
import requests
from ldap3 import Connection
from urllib.parse import urljoin, quote
from copy import deepcopy

name = "matrix-corporal-policy-ldap"

config_defaults = {
    "corporal": {
        "schema_version": 1,
        "flags": {"allowCustomUserDisplayNames": True, "allowCustomUserAvatars": True},
    },
    "deactivate_after": 180,
    "user_defaults": {"authType": "rest", "authCredential": "http://localhost:8090"},
    "user_mode": "existing",
    "ldap": {"scope": "LEVEL", "user": {"filter": None}, "group": {"prefix": None}},
}


endpoints = {
    "list_users": "/_synapse/admin/v2/users?from=0",
    "query_user": "/_synapse/admin/v2/users/",
    "create_room": "/_matrix/client/r0/createRoom",
    "create_group": "/_matrix/client/r0/create_group",
    "groups_of_room": ["/_matrix/client/r0/rooms/", "/state/m.room.related_groups/"],
    "rooms_to_group": ["/_matrix/client/r0/groups/", "/admin/rooms/"],
    "rooms_of_group": ["/_matrix/client/r0/groups/", "/rooms/"],
}
username_regex = "@([a-z0-9._=\\-\\/]+):"
preset_types = ["private_chat", "trusted_private_chat", "public_chat"]
user_modes = ["existing", "all", "list"]

days_to_milliseconds = 24 * 60 * 60 * 1000

def raise_if_no_suceed(req, message):
    if req.status_code != 200:
        raise requests.exceptions.HTTPError(
            message + " Status: {},Reason:{}".format(req.status_code, req.reason)
        )


def default_json(jdef, jin):
    jout = deepcopy(jdef)
    for key in jin:
        if key in jout:
            if type(jin[key]) == dict:
                jout[key] = default_json(jdef[key], jin[key])
            else:
                jout[key] = jin[key]
        else:
            jout[key] = jin[key]
    return jout


class MConnection:
    def __init__(self, address, servername, token):
        self.address = address
        self.servername = servername
        self.auth = token
        self.user_regex = username_regex + re.escape(servername)

    def get_matrix_users(self):
        req = requests.get(
            urljoin(self.address, endpoints["list_users"]),
            headers={"Authorization": "Bearer {}".format(self.token)},
        )
        raise_if_no_suceed(req, "Failed to fetch userlist.")
        users = [
            userdic["name"]
            for userdic in req.json()["users"]
            if not userdic["deactivated"]
        ]
        users = [re.match(user, self.user_regex).groups()[0] for user in users]
        return users

    def query_matrix_user(self, user_id):
        req = requests.get(
            urljoin(self.address, path.join(endpoints["query_user"], quote(user_id))),
            headers={"Authorization": "Bearer {}".format(self.token)},
        )
        raise_if_no_suceed(req, "Failed to query user.")
        return req.json()

    def last_seen_user(self, user_id):
        query = self.query_matrix_user(user_id)
        last_seen = max(
            [
                connection["last_seen"]
                for device in query["devices"].values()
                for session in device["sessions"]
                for connection in session["connections"].values()
            ]
        )
        return last_seen

    def get_groups_of_room(self, room_id):
        req_address = urljoin(
            self.address, path.join(endpoints["group_of_room"], quote(room_id))
        )
        req = requests.get(
            req_address, headers={"Authorization": "Bearer {}".format(self.token)}
        )
        raise_if_no_suceed(req, "Failed to get groups of room.")
        return req.json()["groups"]

    def get_rooms_of_group(self, group_id):
        req_address = urljoin(
            self.address, path.join(endpoints["rooms_of_group"], quote(group_id))
        )
        req = requests.get(
            req_address, headers={"Authorization": "Bearer {}".format(self.token)}
        )
        raise_if_no_suceed(req, "Failed to get rooms of group.")
        return [room["room_id"] for room in req.json()["chunk"]]

    def create_room(self, room_params):
        req = requests.post(
            urljoin(self.address, endpoints["create_room"]),
            headers={
                "Authorization": "Bearer {}".format(self.token),
                "Content-Type:": "application/json",
            },
            json=room_params,
        )
        raise_if_no_suceed(req, "Failed to create room.")
        return req.json()["room_id"]

    def create_group(self, group_params):
        req = requests.post(
            urljoin(self.address, endpoints["create_group"]),
            headers={
                "Authorization": "Bearer {}".format(self.token),
                "Content-Type:": "application/json",
            },
            json=group_params,
        )
        raise_if_no_suceed(req, "Failed to create group.")
        return req.json()["group_id"]

    def add_room_to_group(self, group_id, room_id, visibility):
        old_groups = self.get_groups_of_room(room_id)
        if group_id not in old_groups:
            endpoint = endpoints["groups_of_room"]
            req_address = urljoin(
                self.servername, path.join(endpoint[0], quote(room_id), endpoint[1])
            )
            data = {"groups": old_groups + [group_id]}
            req = requests.put(
                req_address,
                headers={
                    "Authorization": "Bearer {}".format(self.token),
                    "Content-Type:": "application/json",
                },
                json=data,
            )
            raise_if_no_suceed(req, "Failed to add group to room.")
        endpoint = endpoints["rooms_to_group"]
        data = {"m.visibility": {"type": visibility}}
        req_address = urljoin(
            self.servername,
            path.join(endpoint[0], quote(group_id), endpoint[1], quote(room_id)),
        )
        req = requests.put(
            req_address,
            headers={
                "Authorization": "Bearer {}".format(self.token),
                "Content-Type:": "application/json",
            },
            json=data,
        )
        raise_if_no_suceed(req, "Failed to add room to group.")


def defaults_room(room):
    oroom = {
        "topic": "",
        "preset": "private_chat",
        "creation_content": {"m.federate": False},
    }
    if type(room) == dict:
        oroom.update(name=room["room_alias_name"])
        oroom.update(**room)
    else:
        oroom.update(**{"room_alias_name": room, "name": room})
    assert oroom["preset"] in preset_types, "Invalid room preset!"
    return oroom


def defaults_group(group):
    meta = {"room_visibility": "private", "rooms": []}
    if type(group) == dict:
        data = {"profile": {}}
        data.update(localpart=group.get("localpart", group["ldap_uid"]))
        data["profile"].update(name=group.get("name", group["ldap_uid"]))
        meta.update(rooms=group.get("rooms", []))
        meta.update(room_visibility="private")
    else:
        data = {"localpart": group, "profile": {"name": group}}
    return data, meta


def create_things(mconn, groups, rooms, lookup):
    existing_rooms = lookup["rooms"]
    existing_groups = lookup["communities"]
    for room in rooms:
        room = defaults_room(room)
        if room["room_alias_name"] not in existing_rooms.keys():
            room_id = mconn.create_room(room)
            lookup.append({room["room_alias_name"]: room_id})
    for group in groups:
        group = defaults_group(group)
        data, meta = defaults_group(group)
        if data["localpart"] not in existing_groups.keys():
            group_id = mconn.create_group(data)
            lookup.append({data["localpart"]: group_id})
        else:
            group_id = existing_groups[data["localpart"]]
        rooms_in_group = mconn.get_rooms_of_group(group_id)
        for room in meta["rooms"]:
            if existing_rooms[room] not in rooms_in_group:
                mconn.add_room_to_group(
                    group_id, existing_rooms[room], meta["room_visibility"]
                )
    return lookup


def bind(connection):
    try:
        connection.rebind()
    except Exception as e:
        raise RuntimeError("Failed to connect to LDAP server: {}".format(e.args))


def get_users(user_mode, ldap, lconn, mconn, userlist):
    query = "({}=*)".format(ldap["user"]["uid"])
    if ldap["user"]["filter"] is not None:
        query = "(& {} {})".format(query, ldap["user"]["filter"])
    lconn.search(ldap["user"]["base"], query, attributes=["*"])
    users = lconn.entries
    if user_mode == "existing":
        existing_users = mconn.get_matrix_users()
        users = [user for user in users if user[ldap["user"]["id"]] in existing_users]
    elif user_mode == "list":
        users = [user for user in users if user[ldap["user"]["id"]] in userlist]
    return users

def user_policy(corporal, ldap,):
    

def make_policy(configfile):
    with open(configfile, "r") as f:
        config = json.load(f)
    config = default_json(config_defaults, config)
    corporal = config["corporal"]
    ldap = config["ldap"]
    user_mode = config["user_mode"]
    servername = config["homeserver_domain_name"]
    address = config["homeserver_api_endpoint"]
    token = config["admin_auth_token"]
    groups = config["groups"]
    users = config["users"]
    lookup_path = config["lookup_path"]
    lookup = json.load(lookup_path)
    matrix_connection = MConnection(config["homeserver_api_enpoint", ""])
    ldap_connection = Connection(ldap["url"], ldap["binddn"], ldap["binddn_pw"])
