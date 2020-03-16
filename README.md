# Matrix Policy Generator for LDAP
This script will connect to an LDAP instance and create a matrix corporal policy
that can be fed to [matrix-corporal](https://github.com/devture/matrix-corporal).

Configuration is done by a json file, which contains general settings and a list of
settings for individual groups/rooms.

Groups and rooms that are specified will be created upon running and saved in a lookup
json to keep track of the rooms/groups which were already created.

The options for the config file are:

* corporal: Dictionary with default configuration for matrix corporal
* user_defaults: Default entries for user entries in the generated policy
* user_mode: Either "existing", "list" or "all"
  + existing: Generate Policy for users already existing on the matrix-synapse.
  + list: Take configuration option "users" as a list of users to generate a policy for.
  + all: Generate Policy for all users found in LDAP.
* homeserver_domain_name: matrix servernamer; The domain.org in the user id
  @user:domain.org
* homeserver_api_endpoint: url of the matrix server
* admin_auth_token: auth token of an admin user
* lookup_path: path for the lookup file
* ldap: Settings for ldap
  + url: url of the ldapserver
  + binddn: binddn of the user used to access the ldap
  + binddn_pw: password of that user
  + filter: statement to filter the result of the ldap query
  + scope: Scope of the ldap query; Can be "LEVEL", "SUBTREE", etc.
  + user_base: Base directory for users
  + user_id: ID attribute of a user which is used to construct the matrix ID
  + user_displayname: Attribute of the user to determine the displayname. Defaults to user_id
  + user_avatar_uri: Attribute of the user that holds an uri to a avatar image
  + group_base: Base directory for groups that is used if it is not specified for the
    individual group
  + group_id: ID attribute that is used to construct the matrix ID for groups
  + group_prefix: Prefix to strip from the group_id in the matrix ID
* rooms: List of dicts to specify rooms that are set to be managed in the policy
  + room_alias_name: matrix alias name for the room
  + topic: Topic to be set for the room
* communities: List of dicts to specify the groups which are set to be managed in the
  policy
  + ldap_id: Value of the attribute specified in ldap.group_id
  + name: name to be used in matrix for the group
  + rooms: List of rooms that are to be added to the group
  + room_visibility: Default visibility of the rooms for non-members of the group
