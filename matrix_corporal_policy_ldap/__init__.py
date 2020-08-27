import re
import time
import json
import sys

import requests

from os.path import exists
from copy import deepcopy
from argparse import ArgumentParser
from urllib.parse import quote as _quote

from ldap3 import Connection
from requests_toolbelt import sessions


def quote(string):
    return _quote(string, safe="@")


def merge_json(jdefault, jin):
    jout = deepcopy(jdefault)
    for key in jin:
        if key in jout and isinstance(jin[key], dict):
            jout[key] = merge_json(jdefault[key], jin[key])
        else:
            jout[key] = jin[key]
    return jout


class MatrixCorporalPolicyLdapError(Exception):
    pass


class MatrixRequestError(Exception):
    def __init__(self, http_error, message):
        super(MatrixRequestError, self).__init__(message)
        self.http_error = http_error


class MConnection:
    endpoints = {
        "list_users": "/_synapse/admin/v2/users?from={from_user}&limit={limit}&guests=false",
        "query_user": "/_synapse/admin/v2/users/{user_id}",
        "create_room": "/_matrix/client/r0/createRoom",
        "create_group": "/_matrix/client/r0/create_group",
        "groups_of_room": "/_matrix/client/r0/rooms/{room_id}/state/m.room.related_groups/",
        "rooms_to_group": "/_matrix/client/r0/groups/{group_id}/admin/rooms/{room_id}",
        "rooms_of_group": "/_matrix/client/r0/groups/{group_id}/rooms",
    }
    username_regex = r"@(?P<username>[a-z0-9._=\-\/]+):"

    def __init__(self, address, servername, token, *, maxretries=5):
        self.address = address
        self.servername = servername
        self.auth_header = {"Authorization": f"Bearer {token}"}
        self._maxretries = maxretries

        self.user_regex = re.compile(self.username_regex + re.escape(servername))

        # set a default base for the url
        self.session = sessions.BaseUrlSession(base_url=address)
        # set auth_header as default
        self.session.headers.update(self.auth_header)
        # check non 4XX or 5XX status code on each response
        self.session.hooks["response"] = [
            lambda response, *args, **kwargs: response.raise_for_status()
        ]

    def _get(self, endpoint, message, *args, **kwargs):
        for i in range(self._maxretries):
            try:
                req = self.session.get(endpoint, *args, **kwargs)
                break
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    time.sleep(e.response.json()["retry_after_ms"] / 1000)
                else:
                    raise MatrixRequestError(
                        e,
                        message
                        + f" Status: {e.response.status_code},Reason:{e.response.reason}",
                    )
        return req

    def _post(self, endpoint, message, *args, **kwargs):
        for i in range(self._maxretries):
            try:
                req = self.session.post(endpoint, *args, **kwargs)
                break
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    time.sleep(e.response.json()["retry_after_ms"] / 1000)
                else:
                    raise MatrixRequestError(
                        e,
                        message
                        + f" Status: {e.response.status_code},Reason:{e.response.reason}",
                    )
        return req

    def _put(self, endpoint, message, *args, **kwargs):
        for i in range(self._maxretries):
            try:
                req = self.session.put(endpoint, *args, **kwargs)
                break
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    time.sleep(e.response.json()["retry_after_ms"] / 1000)
                else:
                    raise MatrixRequestError(
                        e,
                        message
                        + f" Status: {e.response.status_code},Reason:{e.response.reason}",
                    )
        return req

    def user_id(self, username):
        return f"@{username}:{self.servername}"

    def group_id(self, groupname):
        return f"+{groupname}:{self.servername}"

    def get_matrix_users(self, limit=100):
        users = []
        from_value = 0
        while True:
            req = self._get(
                self.endpoints["list_users"].format(from_user=from_value, limit=limit),
                "Failed to fetch userlist.",
            )
            from_value += limit
            user_ids = [
                userdic["name"]
                for userdic in req.json()["users"]
                if not userdic["deactivated"]
            ]

            for user_id in user_ids:
                match = self.user_regex.search(user_id)
                if match:
                    users.append(match.group("username"))

            if not req.json().get("next_token"):
                break
        return users

    def query_matrix_user(self, user_id):
        req = self._get(
            self.endpoints["query_user"].format(user_id=quote(user_id)),
            "Failed to query user.",
        )
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
        try:
            req = self._get(
                self.endpoints["groups_of_room"].format(room_id=quote(room_id)),
                "Failed to get groups of room.",
            )
            return req.json()["groups"]
        except MatrixRequestError as e:
            if e.http_error.response.status_code == 404:
                return []
            else:
                raise MatrixRequestError(
                    e,
                    f"Failed to get groups of room. Status: {e.request.status_code}, Reason:{e.request.reason}",
                )

    def get_rooms_of_group(self, group_id):
        req = self._get(
            self.endpoints["rooms_of_group"].format(group_id=quote(group_id)),
            "Failed to get rooms of group.",
        )
        return [room["room_id"] for room in req.json()["chunk"]]

    def create_room(self, room_params):
        req = self._post(
            self.endpoints["create_room"],
            "Failed to create room.",
            headers={"Content-Type": "application/json"},
            json=room_params,
        )
        return req.json()["room_id"]

    def create_group(self, group_params):
        req = self._post(
            self.endpoints["create_group"],
            "Failed to create group.",
            headers={"Content-Type": "application/json"},
            json=group_params,
        )
        return req.json()["group_id"]

    def add_room_to_group(self, group_id, room_id, visibility):
        req = self._put(
            self.endpoints["rooms_to_group"].format(
                group_id=quote(group_id), room_id=quote(room_id),
            ),
            "Failed to add room to group.",
            headers={**self.auth_header, "Content-Type": "application/json",},
            json={"m.visibility": {"type": visibility}},
        )

        old_groups = self.get_groups_of_room(room_id)
        if group_id not in old_groups:
            req = self._put(
                self.endpoints["groups_of_room"].format(room_id=quote(room_id)),
                "Failed to add group to room.",
                headers={**self.auth_header, "Content-Type": "application/json",},
                json={"groups": old_groups + [group_id]},
            )


class PolicyConfig:
    @staticmethod
    def defaults_config(config):
        oconfig = {
            "corporal": {
                "schemaVersion": 1,
                "flags": {
                    "allowCustomUserDisplayNames": True,
                    "allowCustomUserAvatars": True,
                },
            },
            "deactivate_after": 180,
            "user_defaults": {
                "authType": "rest",
                "authCredential": "http://localhost:8090",
            },
            "user_mode": "existing",
            "ldap": {
                "scope": "LEVEL",
                "user_filter": None,
                "user_avatar_uri": None,
                "group_prefix": "",
            },
            "users": [],
        }
        return merge_json(oconfig, config)

    @staticmethod
    def defaults_room(room):
        preset_types = ("private_chat", "trusted_private_chat", "public_chat")

        oroom = {
            "topic": "",
            "preset": "private_chat",
            "creation_content": {"m.federate": False},
            "managed": True,
        }
        if isinstance(room, dict):
            oroom.update(name=room["room_alias_name"])
            oroom.update(room)
        else:
            oroom.update({"room_alias_name": room, "name": room})

        assert oroom["preset"] in preset_types, "Invalid room preset!"
        return oroom

    @staticmethod
    def defaults_group(group):
        if isinstance(group, dict):
            localpart = group.get("localpart", group["ldap_id"])
            ogroup = {
                "ldap_id": group["ldap_id"],
                "rooms": group.get("rooms", []),
                "room_visibility": group.get("room_visibility", "private"),
                "localpart": localpart,
                "managed": group.get("managed", True),
                "data": {
                    "localpart": localpart,
                    "profile": {"name": group.get("name", group["ldap_id"])},
                },
            }
        else:
            ogroup = {
                "ldap_id": group,
                "localpart": group,
                "room_visibility": "private",
                "rooms": [],
                "data": {"localpart": group, "profile": {"name": group}},
                "managed": True,
            }
        return ogroup

    def __init__(self, config):
        config = self.defaults_config(config)
        self.corporal = config["corporal"]
        self.ldap = config["ldap"]
        self.user_mode = config["user_mode"]
        self.groups = [self.defaults_group(group) for group in config["communities"]]
        self.rooms = [self.defaults_room(room) for room in config["rooms"]]
        self.user_defaults = config["user_defaults"]
        self.users = config["users"]
        self.lookup_path = config["lookup_path"]

        try:
            f = open(self.lookup_path)
            self.lookup = json.load(f)
        except FileNotFoundError:
            f = open(self.lookup_path, "w")
            self.lookup = {"rooms": {}, "groups": {}}
            json.dump(self.lookup, f)
        finally:
            f.close()

        self.matrix_connection = MConnection(
            config["homeserver_api_endpoint"],
            config["homeserver_domain_name"],
            config["admin_auth_token"],
        )
        self.ldap_connection = Connection(
            self.ldap["url"], self.ldap["binddn"], self.ldap["binddn_pw"]
        )

    def managed_room_ids(self):
        return [
            self.lookup["rooms"][room["room_alias_name"]]
            for room in self.rooms
            if room["managed"]
        ]

    def managed_group_ids(self):
        return [
            self.lookup["groups"][group["localpart"]]
            for group in self.groups
            if group["managed"]
        ]

    def rebind_ldap(self):
        if not self.ldap_connection.bound:
            try:
                self.ldap_connection.rebind()
            except Exception as e:
                raise MatrixCorporalPolicyLdapError(
                    f"Failed to connect to LDAP server: {e.args}"
                )

    def create_missing_rooms_and_groups(self):
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
        finally:
            self.lookup["rooms"].update(existing_rooms)
            self.lookup["groups"].update(existing_groups)
            self.save_lookup()

    def get_users(self):
        query = "({}=*)".format(self.ldap["user_id"])
        if self.ldap["user_filter"] is not None:
            query = "(& {} {})".format(query, self.ldap["user_filter"])
        self.rebind_ldap()
        searchparams = {
            "search_base": self.ldap["user_base"],
            "search_filter": query,
            "attributes": ["+","*"],
            "search_scope": self.ldap["scope"],
            "paged_size": 500,
        }
        users = []
        while True:
            self.ldap_connection.search(**searchparams)
            users.extend(self.ldap_connection.entries)
            cookie = self.ldap_connection.result["controls"]["1.2.840.113556.1.4.319"][
                "value"
            ]["cookie"]
            if cookie:
                searchparams["paged_cookie"] = cookie
            else:
                break
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
        displayname = user_result[
            self.ldap.get("user_displayname", self.ldap["user_displayname"])
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
                "displayName": displayname,
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
        room_ids = self.managed_room_ids()
        group_ids = self.managed_group_ids()
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
    policy_config.create_missing_rooms_and_groups()
    while True:
        policy = policy_config.generate_policy()
        if args.output is None:
            json.dump(policy, sys.stdout)
        else:
            if exists(args.output):
                with open(args.output, "r") as f:
                    oldpolicy = json.load(f)
                    update = True if policy != oldpolicy else False
            else:
                update = True
            if update:
                with open(args.output, "w") as f:
                    json.dump(policy, f)
        if args.repeat is None:
            break
        else:
            time.sleep(args.repeat * 60)


if __name__ == "__main__":
    main()
