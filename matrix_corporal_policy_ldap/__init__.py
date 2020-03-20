import re
import time
import json
import requests
from os import path
from sys import stdout
from copy import deepcopy
from ldap3 import Connection
from argparse import ArgumentParser
from urllib.parse import urljoin, quote


config_defaults = {
    "corporal": {
        "schemaVersion": 1,
        "flags": {"allowCustomUserDisplayNames": True, "allowCustomUserAvatars": True},
    },
    "deactivate_after": 180,
    "user_defaults": {"authType": "rest", "authCredential": "http://localhost:8090"},
    "user_mode": "existing",
    "ldap": {
        "scope": "LEVEL",
        "user_filter": None,
        "user_avatar_uri": None,
        "group_prefix": "",
    },
    "users": [],
}


preset_types = ["private_chat", "trusted_private_chat", "public_chat"]


def raise_if_no_suceed(req, message):
    if req.status_code == 200:
        return req
    elif req.status_code == 429 and req.json()["errcode"] == "M_LIMIT_EXCEEDED":
        time.sleep(req.json()["retry_after_ms"] / 1000)
        newreq = requests.sessions.session().send(req.request)
        newreq = raise_if_no_suceed(newreq, message)
        return newreq
    raise requests.exceptions.HTTPError(
        message + f" Status: {req.status_code},Reason:{req.reason}"
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
    endpoints = {
        "list_users": "/_synapse/admin/v2/users?from=0",
        "query_user": "/_synapse/admin/v2/users/",
        "create_room": "/_matrix/client/r0/createRoom",
        "create_group": "/_matrix/client/r0/create_group",
        "groups_of_room": "/_matrix/client/r0/rooms/{room_id}/state/m.room.related_groups/",
        "rooms_to_group": "/_matrix/client/r0/groups/{group_id}/admin/rooms/{room_id}",
        "rooms_of_group": "/_matrix/client/r0/groups/{group_id}/rooms",
    }
    username_regex = "@([a-z0-9._=\\-\\/]+):"

    def __init__(self, address, servername, token):
        self.address = address
        self.servername = servername
        self.auth_header = {"Authorization": f"Bearer {token}"}

        self.user_regex = self.username_regex + re.escape(servername)

    def user_id(self, username):
        return f"@{username}:{self.servername}"

    def group_id(self, groupname):
        return f"+{groupname}:{self.servername}"

    def get_matrix_users(self):
        req = requests.get(
            urljoin(self.address, endpoints["list_users"]), headers=self.auth_header
        )
        req = raise_if_no_suceed(req, "Failed to fetch userlist.")
        users = [
            userdic["name"]
            for userdic in req.json()["users"]
            if not userdic["deactivated"]
        ]
        users = [
            re.search(self.user_regex, user).groups()[0]
            for user in users
            if re.search(self.user_regex, user)
        ]
        return users

    def query_matrix_user(self, user_id):
        req = requests.get(
            urljoin(self.address, path.join(endpoints["query_user"], quote(user_id))),
            headers=self.auth_header,
        )
        req = raise_if_no_suceed(req, "Failed to query user.")
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
            self.address,
            path.join(
                endpoints["groups_of_room"][0],
                quote(room_id),
                endpoints["groups_of_room"][1],
            ),
        )
        req = requests.get(req_address, headers=self.auth_header)
        if req.status_code == 404:
            return []
        req = raise_if_no_suceed(req, "Failed to get groups of room.")
        return req.json()["groups"]

    def get_rooms_of_group(self, group_id):
        req_address = urljoin(
            self.address,
            path.join(
                endpoints["rooms_of_group"][0],
                quote(group_id),
                endpoints["rooms_of_group"][1],
            ),
        )
        req = requests.get(req_address, headers=self.auth_header)
        req = raise_if_no_suceed(req, "Failed to get rooms of group.")
        return [room["room_id"] for room in req.json()["chunk"]]

    def create_room(self, room_params):
        req = requests.post(
            urljoin(self.address, endpoints["create_room"]),
            headers={**self.auth_header, "Content-Type": "application/json"},
            json=room_params,
        )
        req = raise_if_no_suceed(req, "Failed to create room.")
        return req.json()["room_id"]

    def create_group(self, group_params):
        req = requests.post(
            urljoin(self.address, endpoints["create_group"]),
            headers={**self.auth_header, "Content-Type": "application/json"},
            json=group_params,
        )
        req = raise_if_no_suceed(req, "Failed to create group.")
        return req.json()["group_id"]

    def add_room_to_group(self, group_id, room_id, visibility):
        endpoint = endpoints["rooms_to_group"]
        data = {"m.visibility": {"type": visibility}}
        req_address = urljoin(
            self.address,
            path.join(endpoint[0], quote(group_id), endpoint[1], quote(room_id)),
        )
        req = requests.put(
            req_address,
            headers={**self.auth_header, "Content-Type": "application/json",},
            json=data,
        )
        req = raise_if_no_suceed(req, "Failed to add room to group.")
        old_groups = self.get_groups_of_room(room_id)
        if group_id not in old_groups:
            endpoint = endpoints["groups_of_room"]
            req_address = urljoin(
                self.address, path.join(endpoint[0], quote(room_id), endpoint[1])
            )
            data = {"groups": old_groups + [group_id]}
            req = requests.put(
                req_address,
                headers={**self.auth_header, "Content-Type": "application/json",},
                json=data,
            )
            req = raise_if_no_suceed(req, "Failed to add group to room.")


class PolicyConfig:
    @staticmethod
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

    @staticmethod
    def defaults_group(group):
        if type(group) == dict:
            data = {"profile": {}}
            data.update(localpart=group.get("localpart", group["ldap_id"]))
            data["profile"].update(name=group.get("name", group["ldap_id"]))
            ogroup = {
                "ldap_id": group["ldap_id"],
                "rooms": group.get("rooms", []),
                "room_visibility": group.get("room_visibility", "private"),
                "localpart": data["localpart"],
            }
        else:
            ogroup = {
                "ldap_id": group,
                "localpart": group,
                "room_visibility": "private",
                "rooms": [],
            }
            data = {"localpart": group, "profile": {"name": group}}
            ogroup["data"] = data
            return ogroup

    def __init__(self, config):
        config = default_json(config_defaults, config)
        self.corporal = config["corporal"]
        self.ldap = config["ldap"]
        self.user_mode = config["user_mode"]
        self.groups = [self.defaults_group(group) for group in config["communities"]]
        self.rooms = [self.defaults_room(room) for room in config["rooms"]]
        self.user_defaults = config["user_defaults"]
        self.users = config["users"]
        self.lookup_path = config["lookup_path"]
        if not path.exists(self.lookup_path):
            with open(self.lookup_path, "w") as f:
                json.dump({"rooms": {}, "groups": {}}, f)
        with open(self.lookup_path) as f:
            self.lookup = json.load(f)
        self.matrix_connection = MConnection(
            config["homeserver_api_endpoint"],
            config["homeserver_domain_name"],
            config["admin_auth_token"],
        )
        self.ldap_connection = Connection(
            self.ldap["url"], self.ldap["binddn"], self.ldap["binddn_pw"]
        )

    def rebind_ldap(self):
        if not self.ldap_connection.bound:
            try:
                self.ldap_connection.rebind()
            except Exception as e:
                raise RuntimeError(
                    "Failed to connect to LDAP server: {}".format(e.args)
                )

    def create_things(self):
        existing_rooms = self.lookup["rooms"]
        existing_groups = self.lookup["groups"]
        try:
            for room in self.rooms:
                if room["room_alias_name"] not in existing_rooms.keys():
                    room_id = self.matrix_connection.create_room(room)
                    existing_rooms.update({room["room_alias_name"]: room_id})
            for group in self.groups:
                data = group["data"]
                if data["localpart"] not in existing_groups.keys():
                    group_id = self.matrix_connection.create_group(data)
                    existing_groups.update({data["localpart"]: group_id})
                else:
                    group_id = existing_groups[data["localpart"]]
                rooms_in_group = self.matrix_connection.get_rooms_of_group(group_id)
                for room in group["rooms"]:
                    if existing_rooms[room] not in rooms_in_group:
                        self.matrix_connection.add_room_to_group(
                            group_id, existing_rooms[room], group["room_visibility"]
                        )
        except Exception as e:
            raise e
        finally:
            self.lookup["rooms"].update(existing_rooms)
            self.lookup["groups"].update(existing_groups)
            self.save_lookup()

    def get_users(self):
        query = "({}=*)".format(self.ldap["user_id"])
        if self.ldap["user_filter"] is not None:
            query = "(& {} {})".format(query, self.ldap["user_filter"])
        self.rebind_ldap()
        self.ldap_connection.search(
            self.ldap["user_base"],
            query,
            attributes=["*"],
            search_scope=self.ldap["scope"],
        )
        users = self.ldap_connection.entries
        if self.user_mode == "existing":
            existing_users = self.matrix_connection.get_matrix_users()
            users = [
                user for user in users if user[self.ldap["user_id"]] in existing_users
            ]
        elif self.user_mode == "list":
            users = [user for user in users if user[self.ldap["user_id"]] in self.users]
        return users

    def user_policy(self, user_result):
        policy = {**self.user_defaults}
        username = user_result[self.ldap["user_id"]].value
        display_name = user_result[
            self.ldap.get("user_displayname", self.ldap["user_id"])
        ].value
        if self.ldap["user_avatar_uri"] is None:
            avatar_uri = ""
        else:
            avatar_uri = user_result[self.user["avatarUri"]]
        user_id = self.matrix_connection.user_id(username)
        groups_and_rooms = [
            (
                self.lookup["groups"][group["localpart"]],
                [self.lookup["rooms"][room] for room in group["rooms"]],
            )
            for group in self.groups
            if "{}={}{},{}".format(
                self.ldap["group_id"],
                self.ldap["group_prefix"],
                group["ldap_id"],
                group.get("ldap_base", self.ldap["group_base"]),
            )
            in user_result.memberof
        ]
        if groups_and_rooms:
            groups, roomlist = zip(*groups_and_rooms)
            rooms = list(set(room for group_rooms in roomlist for room in group_rooms))
            groups = list(groups)
        else:
            groups, rooms = [], []
        policy.update(
            {
                "id": user_id,
                "active": True,
                "displayName": display_name,
                "avatarUri": avatar_uri,
                "joinedCommunityIds": groups,
                "joinedRoomIds": rooms,
            }
        )
        return policy

    def generate_policy(self):
        policy = deepcopy(self.corporal)
        users = self.get_users()
        user_policies = [self.user_policy(user) for user in users]
        room_ids = list(self.lookup["rooms"].values())
        group_ids = list(self.lookup["groups"].values())
        policy.update(
            {
                "managedCommunityIds": group_ids,
                "managedRoomIds": room_ids,
                "users": user_policies,
            }
        )
        return policy

    def save_lookup(self):
        with open(self.lookup_path, "w") as f:
            json.dump(self.lookup, f)


def main():
    parser = ArgumentParser(
        description="Generate policy for matrix-corporal from ldap."
    )
    parser.add_argument("configfile", help="config json")
    parser.add_argument(
        "-r",
        "--repeat",
        type=int,
        default=None,
        help="""Minute interval in which the policy will get updated.
                If not specified the policy will get generated once.
                The config file will only be read on startup.""",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="Output path of the generated policy. Defaults to standard output.",
    )
    args = parser.parse_args()
    with open(args.configfile, "r") as f:
        config = json.load(f)
    policy_config = PolicyConfig(config)
    policy_config.create_things()
    while True:
        policy = policy_config.generate_policy()
        if args.output is None:
            json.dump(policy, stdout)
        else:
            with open(args.output, "r") as f:
                oldpolicy = json.load(f)
            if policy != oldpolicy:
                with open(args.output, "w") as f:
                    json.dump(policy, f)
        if args.repeat is None:
            break
        else:
            time.sleep(args.repeat * 60)


if __name__ == "__main__":
    main()
