# coding: utf-8

# (C) Copyright IBM Corp. 2019.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Swagger for the IBM Cloud Private for Data offerings - with Data Governance and Analytics
API's
"""

from __future__ import absolute_import

import json
from .common import get_sdk_headers
from ibm_cloud_sdk_core import BaseService
from os.path import basename

##############################################################################
# Service
##############################################################################

class IcpdV1(BaseService):
    """The ICPD V1 service."""

    default_url = 'https://gateway.watsonplatform.net/icp4d-api/'

    def __init__(self,
                 url=default_url,
                 authentication_type=None,
                ):
        """
        Construct a new client for the ICPD service.

        :param str url: The base url to use when contacting the service (e.g.
               "https://gateway.watsonplatform.net/icp4d-api//icp4d-api").
               The base url may differ between IBM Cloud regions.

        :param str authentication_type: Specifies the authentication pattern to use. Values that it
               takes are basic, iam or icp4d.
        """

        BaseService.__init__(self,
            vcap_services_name='icpd',
            url=url,
            use_vcap_services=True,
            display_name='ICPD',
            authentication_type=authentication_type)

    #########################
    # Authorization
    #########################

    def get_authorization_token(self, password, username, **kwargs):
        """
        Get authorization token.

        Provide icp4d login credentials to receive authorization bearer token.

        :param str password:
        :param str username:
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if password is None:
            raise ValueError('password must be provided')
        if username is None:
            raise ValueError('username must be provided')

        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'get_authorization_token')
        headers.update(sdk_headers)

        data = {
            'password': password,
            'username': username
        }

        url = '/v1/authorize'
        response = self.request(method='POST',
                                url=url,
                                headers=headers,
                                json=data,
                                accept_json=True)
        return response


    #########################
    # User Management
    #########################

    def get_all_users(self, **kwargs):
        """
        Get all users.

        Get all users from the cluster.

        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """


        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'get_all_users')
        headers.update(sdk_headers)

        url = '/v1/users'
        response = self.request(method='GET',
                                url=url,
                                headers=headers,
                                accept_json=False)
        return response


    def create_user(self, display_name, email, user_name, user_roles, **kwargs):
        """
        Create user.

        Create a new user for the cluster.

        :param str display_name: Display Name for the user e.g. Admin.
        :param str email: Email for the user e.g. admin@user.net.
        :param str user_name: User name e.g. admin.
        :param list[str] user_roles: List of user roles.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """


        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'create_user')
        headers.update(sdk_headers)

        data = {
            'displayName': display_name,
            'email': email,
            'user_name': user_name,
            'user_roles': user_roles
        }

        url = '/v1/users'
        response = self.request(method='POST',
                                url=url,
                                headers=headers,
                                json=data,
                                accept_json=True)
        return response


    def get_user(self, user_name, **kwargs):
        """
        Get user information.

        Get existing user information.

        :param str user_name: User name.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if user_name is None:
            raise ValueError('user_name must be provided')

        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'get_user')
        headers.update(sdk_headers)

        url = '/v1/users/{0}'.format(*self._encode_path_vars(user_name))
        response = self.request(method='GET',
                                url=url,
                                headers=headers,
                                accept_json=False)
        return response


    def update_user(self, user_name, approval_status=None, display_name=None, email=None, user_roles=None, **kwargs):
        """
        Update user details.

        Update an existing user information.

        :param str user_name: User name.
        :param str approval_status: (optional) Approval status for the user, can be
               either 'pending' or 'approved'.
        :param str display_name: (optional) Display Name for the user e.g. Admin.
        :param str email: (optional) Email for the user e.g. admin@user.net.
        :param list[str] user_roles: (optional) List of user roles.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if user_name is None:
            raise ValueError('user_name must be provided')

        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'update_user')
        headers.update(sdk_headers)

        data = {
            'approval_status': approval_status,
            'displayName': display_name,
            'email': email,
            'user_roles': user_roles
        }

        url = '/v1/users/{0}'.format(*self._encode_path_vars(user_name))
        response = self.request(method='PUT',
                                url=url,
                                headers=headers,
                                json=data,
                                accept_json=True)
        return response


    def delete_user(self, user_name, **kwargs):
        """
        Delete user.

        Delete user from the cluster.

        :param str user_name: User name.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if user_name is None:
            raise ValueError('user_name must be provided')

        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'delete_user')
        headers.update(sdk_headers)

        url = '/v1/users/{0}'.format(*self._encode_path_vars(user_name))
        response = self.request(method='DELETE',
                                url=url,
                                headers=headers,
                                accept_json=False)
        return response


    #########################
    # Role Management
    #########################

    def get_all_roles(self, **kwargs):
        """
        List all roles.

        Get all roles from the cluster.

        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """


        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'get_all_roles')
        headers.update(sdk_headers)

        url = '/v1/roles'
        response = self.request(method='GET',
                                url=url,
                                headers=headers,
                                accept_json=False)
        return response


    def create_role(self, permissions, role_name, description=None, **kwargs):
        """
        Create new role.

        Create a new role for the cluster.

        :param list[str] permissions: List of permissions e.g. administrator.
        :param str role_name: Role name e.g. admin.
        :param str description: (optional) Role description e.g. Administrator
               role.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """


        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'create_role')
        headers.update(sdk_headers)

        data = {
            'permissions': permissions,
            'role_name': role_name,
            'description': description
        }

        url = '/v1/roles'
        response = self.request(method='POST',
                                url=url,
                                headers=headers,
                                json=data,
                                accept_json=True)
        return response


    def get_all_permissions(self, **kwargs):
        """
        List all permissions.

        Get all defined permissions.

        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """


        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'get_all_permissions')
        headers.update(sdk_headers)

        url = '/v1/roles/permissions'
        response = self.request(method='GET',
                                url=url,
                                headers=headers,
                                accept_json=False)
        return response


    def get_role(self, role_name, **kwargs):
        """
        Get role information.

        Get existing role information.

        :param str role_name: existing role.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if role_name is None:
            raise ValueError('role_name must be provided')

        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'get_role')
        headers.update(sdk_headers)

        url = '/v1/roles/{0}'.format(*self._encode_path_vars(role_name))
        response = self.request(method='GET',
                                url=url,
                                headers=headers,
                                accept_json=False)
        return response


    def update_role(self, role_name, permissions, description=None, **kwargs):
        """
        Update role.

        Update an existing role.

        :param str role_name: existing role.
        :param list[str] permissions: List of permissions e.g. administrator.
        :param str description: (optional) Role description e.g. Admin.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if role_name is None:
            raise ValueError('role_name must be provided')

        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'update_role')
        headers.update(sdk_headers)

        data = {
            'permissions': permissions,
            'description': description
        }

        url = '/v1/roles/{0}'.format(*self._encode_path_vars(role_name))
        response = self.request(method='PUT',
                                url=url,
                                headers=headers,
                                json=data,
                                accept_json=True)
        return response


    def delete_role(self, role_name, **kwargs):
        """
        Delete role.

        Delete role from the cluster.

        :param str role_name: existing role.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if role_name is None:
            raise ValueError('role_name must be provided')

        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'delete_role')
        headers.update(sdk_headers)

        url = '/v1/roles/{0}'.format(*self._encode_path_vars(role_name))
        response = self.request(method='DELETE',
                                url=url,
                                headers=headers,
                                accept_json=False)
        return response


    #########################
    # Account Management
    #########################

    def change_password(self, password, **kwargs):
        """
        Change my password.

        Change password for the logged in user.

        :param str password: New Password.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if password is None:
            raise ValueError('password must be provided')

        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'change_password')
        headers.update(sdk_headers)

        form_data = {}
        form_data['password'] = (None, password, 'text/plain')

        url = '/v1/changepassword'
        response = self.request(method='POST',
                                url=url,
                                headers=headers,
                                files=form_data,
                                accept_json=True)
        return response


    def get_me(self, **kwargs):
        """
        Get my account information.

        Get logged in user information.

        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """


        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'get_me')
        headers.update(sdk_headers)

        url = '/v1/me'
        response = self.request(method='GET',
                                url=url,
                                headers=headers,
                                accept_json=False)
        return response


    def update_me(self, display_name=None, email=None, **kwargs):
        """
        Update my information.

        Update my user information.

        :param str display_name: (optional) Display Name for the user e.g. Admin.
        :param str email: (optional) Email for the user e.g. admin@user.net.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """


        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'update_me')
        headers.update(sdk_headers)

        data = {
            'displayName': display_name,
            'email': email
        }

        url = '/v1/me'
        response = self.request(method='PUT',
                                url=url,
                                headers=headers,
                                json=data,
                                accept_json=True)
        return response


    #########################
    # Catalog Asset Bundles
    #########################

    def get_all_asset_bundles(self, **kwargs):
        """
        Get the list of registered asset bundles.

        Provides a list of registered asset bundles.

        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """


        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'get_all_asset_bundles')
        headers.update(sdk_headers)

        url = '/v1/assetBundles'
        response = self.request(method='GET',
                                url=url,
                                headers=headers,
                                accept_json=True)
        return response


    def update_asset_bundle(self, file, file_content_type=None, **kwargs):
        """
        Update a previously registered asset bundle.

        Updates previously registered asset bundle. Upload the zip file with updated
        bundle definition.

        :param file file: File.
        :param str file_content_type: (optional) The content type of file.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if file is None:
            raise ValueError('file must be provided')

        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'update_asset_bundle')
        headers.update(sdk_headers)

        form_data = {}
        form_data['file'] = (None, file, file_content_type or 'application/octet-stream')

        url = '/v1/assetBundles'
        response = self.request(method='PUT',
                                url=url,
                                headers=headers,
                                files=form_data,
                                accept_json=True)
        return response


    def create_asset_bundle(self, file, file_content_type=None, **kwargs):
        """
        Register a new Asset bundle.

        Registers a new Asset bundle. Upload the zip file with the bundle definition and
        the properties. More information on how to construct the zip file can be found
        [here](https://github.com/IBM-ICP4D/icp4d-apis/tree/master/custom-bundle-utility).

        :param file file: File.
        :param str file_content_type: (optional) The content type of file.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if file is None:
            raise ValueError('file must be provided')

        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'create_asset_bundle')
        headers.update(sdk_headers)

        form_data = {}
        form_data['file'] = (None, file, file_content_type or 'application/octet-stream')

        url = '/v1/assetBundles'
        response = self.request(method='POST',
                                url=url,
                                headers=headers,
                                files=form_data,
                                accept_json=True)
        return response


    def get_asset_bundle(self, asset_id, **kwargs):
        """
        Download a registered bundle as a zip file.

        Outputs the bundle definition zip file, needing the Asset bundle ID to process the
        request.

        :param str asset_id: Asset Bundle ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if asset_id is None:
            raise ValueError('asset_id must be provided')

        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'get_asset_bundle')
        headers.update(sdk_headers)

        url = '/v1/assetBundles/{0}'.format(*self._encode_path_vars(asset_id))
        response = self.request(method='GET',
                                url=url,
                                headers=headers,
                                accept_json=False)
        return response


    def delete_asset_bundle(self, asset_id, **kwargs):
        """
        Delete an asset bundle.

        Delete the asset bundle, needing the asset bundle ID as input.

        :param str asset_id: Asset Bundle ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if asset_id is None:
            raise ValueError('asset_id must be provided')

        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'delete_asset_bundle')
        headers.update(sdk_headers)

        url = '/v1/assetBundles/{0}'.format(*self._encode_path_vars(asset_id))
        response = self.request(method='DELETE',
                                url=url,
                                headers=headers,
                                accept_json=True)
        return response


    #########################
    # Catalog Assets
    #########################

    def get_asset(self, asset_type, asset_property, asset_value, **kwargs):
        """
        Get an asset.

        Provides information about an asset type. For custom asset, please provide the
        asset type as {asset_family_name}-{asset_type}.

        :param str asset_type: Functional area name Ex- category.
        :param str asset_property: Property name to search by, as an example we
               might want to search for all assets with a given name. Ex- name.
        :param str asset_value: What property value are we searching by? Ex-
               Logical Area.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if asset_type is None:
            raise ValueError('asset_type must be provided')
        if asset_property is None:
            raise ValueError('asset_property must be provided')
        if asset_value is None:
            raise ValueError('asset_value must be provided')

        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'get_asset')
        headers.update(sdk_headers)

        params = {
            'asset_type': asset_type,
            'asset_property': asset_property,
            'asset_value': asset_value
        }

        url = '/v1/assets'
        response = self.request(method='GET',
                                url=url,
                                headers=headers,
                                params=params,
                                accept_json=True)
        return response


    def create_asset(self, asset_name, asset_type, is_custom, asset_family=None, custom_properties=None, parent_asset_name=None, parent_asset_type=None, **kwargs):
        """
        Create an asset.

        Create custom and pre-defined assets using this endpoint. For term asset types,
        provide category_name under custom_properties. For custom asset types, provide the
        asset_family_name and the parent asset information, if asset not the top element.

        :param str asset_name: Functional area name.
        :param str asset_type: Asset type. Non custom asset supported types are
               term, category, information_governance_policy, information_governance_rule,
               collection, label and data_class.
        :param bool is_custom: Is this a custom asset type? If yes, asset family
               name is required as well.
        :param str asset_family: (optional) Custom Application Name.
        :param dict custom_properties: (optional) JSON payload of attributes,
               values.
        :param str parent_asset_name: (optional) If top level asset type this will
               be NA, if not it will be the parent asset name.
        :param str parent_asset_type: (optional) If top level asset type this will
               be NA, if not it will be the parent asset type.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """


        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'create_asset')
        headers.update(sdk_headers)

        data = {
            'asset_name': asset_name,
            'asset_type': asset_type,
            'is_custom': is_custom,
            'asset_family': asset_family,
            'custom_properties': custom_properties,
            'parent_asset_name': parent_asset_name,
            'parent_asset_type': parent_asset_type
        }

        url = '/v1/assets'
        response = self.request(method='POST',
                                url=url,
                                headers=headers,
                                json=data,
                                accept_json=True)
        return response


    def delete_asset(self, asset_property, asset_type, asset_value, **kwargs):
        """
        Delete Asset.

        Delete asset. For custom asset type, provide asset_type as
        {asset_family_name}-{asset_type}.

        :param str asset_property: Property name to search by, can search for all
               assets with a given name to delete. Ex- name.
        :param str asset_type: Functional area name. Ex- term.
        :param str asset_value: Property value to search by. Ex- TermOne.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """


        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'delete_asset')
        headers.update(sdk_headers)

        data = {
            'asset_property': asset_property,
            'asset_type': asset_type,
            'asset_value': asset_value
        }

        url = '/v1/assets'
        response = self.request(method='DELETE',
                                url=url,
                                headers=headers,
                                json=data,
                                accept_json=True)
        return response


    def get_asset_by_id(self, asset_id, **kwargs):
        """
        Get an asset by id.

        Retrieve information on an asset based on asset ID.

        :param str asset_id: Asset ID.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if asset_id is None:
            raise ValueError('asset_id must be provided')

        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'get_asset_by_id')
        headers.update(sdk_headers)

        url = '/v1/assets/{0}'.format(*self._encode_path_vars(asset_id))
        response = self.request(method='GET',
                                url=url,
                                headers=headers,
                                accept_json=True)
        return response


    def get_types(self, **kwargs):
        """
        Get all asset types.

        Retrieves all available asset types.

        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """


        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'get_types')
        headers.update(sdk_headers)

        url = '/v1/types'
        response = self.request(method='GET',
                                url=url,
                                headers=headers,
                                accept_json=True)
        return response


    def get_type_info(self, type_name, show_edit_properties=None, show_view_properties=None, show_create_properties=None, **kwargs):
        """
        Get type metadata.

        Get information about an asset type.

        :param str type_name: Asset type.
        :param bool show_edit_properties: (optional) List the properties that can
               be edited.
        :param bool show_view_properties: (optional) List the properties that can
               be viewed.
        :param bool show_create_properties: (optional) List the properties that can
               be defined when the asset is created.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if type_name is None:
            raise ValueError('type_name must be provided')

        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'get_type_info')
        headers.update(sdk_headers)

        params = {
            'show_edit_properties': show_edit_properties,
            'show_view_properties': show_view_properties,
            'show_create_properties': show_create_properties
        }

        url = '/v1/types/{0}'.format(*self._encode_path_vars(type_name))
        response = self.request(method='GET',
                                url=url,
                                headers=headers,
                                params=params,
                                accept_json=True)
        return response


    def get_type_assets(self, type_name, **kwargs):
        """
        Get assets of a particular type.

        Retrieves all available asset of a particular type.

        :param str type_name: Asset type.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if type_name is None:
            raise ValueError('type_name must be provided')

        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'get_type_assets')
        headers.update(sdk_headers)

        url = '/v1/types/{0}/assets'.format(*self._encode_path_vars(type_name))
        response = self.request(method='GET',
                                url=url,
                                headers=headers,
                                accept_json=True)
        return response


    #########################
    # Related Catalog Assets
    #########################

    def get_related_asset(self, asset_type, asset_name, **kwargs):
        """
        Find related assets.

        Outputs assets related to the provided asset.

        :param str asset_type: Functional area name Ex- category.
        :param str asset_name: Asset name.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """

        if asset_type is None:
            raise ValueError('asset_type must be provided')
        if asset_name is None:
            raise ValueError('asset_name must be provided')

        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'get_related_asset')
        headers.update(sdk_headers)

        params = {
            'asset_type': asset_type,
            'asset_name': asset_name
        }

        url = '/v1/relatedAssets'
        response = self.request(method='GET',
                                url=url,
                                headers=headers,
                                params=params,
                                accept_json=True)
        return response


    def create_related_asset(self, asset_name, asset_type, related_asset_name, related_asset_type, **kwargs):
        """
        Relate with other assets.

        Associate metadata about two related assets that are existing in the governance
        catalog. For example, add category asset association to a term asset.

        :param str asset_name: Functional area instance name. Ex- TermOne.
        :param str asset_type: Functional area name. Ex- term.
        :param str related_asset_name: Functional area instance name. Ex-
               CategoryOne.
        :param str related_asset_type: Functional area name from this Asset Family
               or could be an asset class name unrelated to this Asset Family. Ex-
               category.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """


        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'create_related_asset')
        headers.update(sdk_headers)

        data = {
            'asset_name': asset_name,
            'asset_type': asset_type,
            'related_asset_name': related_asset_name,
            'related_asset_type': related_asset_type
        }

        url = '/v1/relatedAssets'
        response = self.request(method='POST',
                                url=url,
                                headers=headers,
                                json=data,
                                accept_json=True)
        return response


    def delete_related_asset(self, asset_name, asset_type, related_asset_name, related_asset_type, **kwargs):
        """
        Remove related asset.

        Remove existing asset's association.

        :param str asset_name: Functional area instance name. Ex- TermOne.
        :param str asset_type: Functional area name. Ex- term.
        :param str related_asset_name: Functional area instance name. Ex-
               CategoryOne.
        :param str related_asset_type: Functional area name from this Asset Family
               or could be an asset class name unrelated to this Asset Family. Ex-
               category.
        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """


        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'delete_related_asset')
        headers.update(sdk_headers)

        data = {
            'asset_name': asset_name,
            'asset_type': asset_type,
            'related_asset_name': related_asset_name,
            'related_asset_type': related_asset_type
        }

        url = '/v1/relatedAssets'
        response = self.request(method='DELETE',
                                url=url,
                                headers=headers,
                                json=data,
                                accept_json=True)
        return response


    #########################
    # Monitor
    #########################

    def get_monitor(self, **kwargs):
        """
        Check server status.

        Provides basic heartbeat endpoint to check if the icp4d open api server is
        running.

        :param dict headers: A `dict` containing the request headers
        :return: A `DetailedResponse` containing the result, headers and HTTP status code.
        :rtype: DetailedResponse
        """


        headers = {
        }
        if 'headers' in kwargs:
            headers.update(kwargs.get('headers'))
        sdk_headers = get_sdk_headers('icpd', 'V1', 'get_monitor')
        headers.update(sdk_headers)

        url = '/v1/monitor'
        response = self.request(method='GET',
                                url=url,
                                headers=headers,
                                accept_json=False)
        return response



##############################################################################
# Models
##############################################################################


class AssetBundlesGetSuccessResponse(object):
    """
    AssetBundlesGetSuccessResponse.

    :attr str message_code: (optional) message code.
    :attr str message: (optional) message.
    :attr list[str] asset_bundles: (optional)
    """

    def __init__(self, message_code=None, message=None, asset_bundles=None):
        """
        Initialize a AssetBundlesGetSuccessResponse object.

        :param str message_code: (optional) message code.
        :param str message: (optional) message.
        :param list[str] asset_bundles: (optional)
        """
        self.message_code = message_code
        self.message = message
        self.asset_bundles = asset_bundles

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a AssetBundlesGetSuccessResponse object from a json dictionary."""
        args = {}
        validKeys = ['message_code', '_messageCode_', 'message', 'asset_bundles', 'AssetBundles']
        badKeys = set(_dict.keys()) - set(validKeys)
        if badKeys:
            raise ValueError('Unrecognized keys detected in dictionary for class AssetBundlesGetSuccessResponse: ' + ', '.join(badKeys))
        if '_messageCode_' in _dict:
            args['message_code'] = _dict.get('_messageCode_')
        if 'message' in _dict:
            args['message'] = _dict.get('message')
        if 'AssetBundles' in _dict:
            args['asset_bundles'] = _dict.get('AssetBundles')
        return cls(**args)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'message_code') and self.message_code is not None:
            _dict['_messageCode_'] = self.message_code
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        if hasattr(self, 'asset_bundles') and self.asset_bundles is not None:
            _dict['AssetBundles'] = self.asset_bundles
        return _dict

    def __str__(self):
        """Return a `str` version of this AssetBundlesGetSuccessResponse object."""
        return json.dumps(self._to_dict(), indent=2)

    def __eq__(self, other):
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class AssetDetailsSuccessResponse(object):
    """
    AssetDetailsSuccessResponse.

    :attr str message_code: (optional) message code.
    :attr str message: (optional) message.
    :attr object asset_details: (optional)
    """

    def __init__(self, message_code=None, message=None, asset_details=None):
        """
        Initialize a AssetDetailsSuccessResponse object.

        :param str message_code: (optional) message code.
        :param str message: (optional) message.
        :param object asset_details: (optional)
        """
        self.message_code = message_code
        self.message = message
        self.asset_details = asset_details

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a AssetDetailsSuccessResponse object from a json dictionary."""
        args = {}
        validKeys = ['message_code', '_messageCode_', 'message', 'asset_details']
        badKeys = set(_dict.keys()) - set(validKeys)
        if badKeys:
            raise ValueError('Unrecognized keys detected in dictionary for class AssetDetailsSuccessResponse: ' + ', '.join(badKeys))
        if '_messageCode_' in _dict:
            args['message_code'] = _dict.get('_messageCode_')
        if 'message' in _dict:
            args['message'] = _dict.get('message')
        if 'asset_details' in _dict:
            args['asset_details'] = _dict.get('asset_details')
        return cls(**args)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'message_code') and self.message_code is not None:
            _dict['_messageCode_'] = self.message_code
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        if hasattr(self, 'asset_details') and self.asset_details is not None:
            _dict['asset_details'] = self.asset_details
        return _dict

    def __str__(self):
        """Return a `str` version of this AssetDetailsSuccessResponse object."""
        return json.dumps(self._to_dict(), indent=2)

    def __eq__(self, other):
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CreateUserSuccessResponse(object):
    """
    CreateUserSuccessResponse.

    :attr str message_code: (optional) message code.
    :attr str message: (optional) message.
    :attr CreateUserSuccessResponseAllOf1User user: (optional)
    """

    def __init__(self, message_code=None, message=None, user=None):
        """
        Initialize a CreateUserSuccessResponse object.

        :param str message_code: (optional) message code.
        :param str message: (optional) message.
        :param CreateUserSuccessResponseAllOf1User user: (optional)
        """
        self.message_code = message_code
        self.message = message
        self.user = user

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateUserSuccessResponse object from a json dictionary."""
        args = {}
        validKeys = ['message_code', '_messageCode_', 'message', 'user', 'User']
        badKeys = set(_dict.keys()) - set(validKeys)
        if badKeys:
            raise ValueError('Unrecognized keys detected in dictionary for class CreateUserSuccessResponse: ' + ', '.join(badKeys))
        if '_messageCode_' in _dict:
            args['message_code'] = _dict.get('_messageCode_')
        if 'message' in _dict:
            args['message'] = _dict.get('message')
        if 'User' in _dict:
            args['user'] = CreateUserSuccessResponseAllOf1User._from_dict(_dict.get('User'))
        return cls(**args)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'message_code') and self.message_code is not None:
            _dict['_messageCode_'] = self.message_code
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        if hasattr(self, 'user') and self.user is not None:
            _dict['User'] = self.user._to_dict()
        return _dict

    def __str__(self):
        """Return a `str` version of this CreateUserSuccessResponse object."""
        return json.dumps(self._to_dict(), indent=2)

    def __eq__(self, other):
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class CreateUserSuccessResponseAllOf1User(object):
    """
    CreateUserSuccessResponseAllOf1User.

    :attr str ID: (optional) user name.
    :attr str password: (optional) Auto generated password for the new user.
    """

    def __init__(self, ID=None, password=None):
        """
        Initialize a CreateUserSuccessResponseAllOf1User object.

        :param str ID: (optional) user name.
        :param str password: (optional) Auto generated password for the new user.
        """
        self.ID = ID
        self.password = password

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a CreateUserSuccessResponseAllOf1User object from a json dictionary."""
        args = {}
        validKeys = ['ID', 'password']
        badKeys = set(_dict.keys()) - set(validKeys)
        if badKeys:
            raise ValueError('Unrecognized keys detected in dictionary for class CreateUserSuccessResponseAllOf1User: ' + ', '.join(badKeys))
        if 'ID' in _dict:
            args['ID'] = _dict.get('ID')
        if 'password' in _dict:
            args['password'] = _dict.get('password')
        return cls(**args)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'ID') and self.ID is not None:
            _dict['ID'] = self.ID
        if hasattr(self, 'password') and self.password is not None:
            _dict['password'] = self.password
        return _dict

    def __str__(self):
        """Return a `str` version of this CreateUserSuccessResponseAllOf1User object."""
        return json.dumps(self._to_dict(), indent=2)

    def __eq__(self, other):
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetAllRolesResponse(object):
    """
    GetAllRolesResponse.

    :attr str message_code: (optional) message code.
    :attr str message: (optional) message.
    :attr list[GetAllRolesResponseAllOf1RolesItems] roles: (optional)
    """

    def __init__(self, message_code=None, message=None, roles=None):
        """
        Initialize a GetAllRolesResponse object.

        :param str message_code: (optional) message code.
        :param str message: (optional) message.
        :param list[GetAllRolesResponseAllOf1RolesItems] roles: (optional)
        """
        self.message_code = message_code
        self.message = message
        self.roles = roles

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetAllRolesResponse object from a json dictionary."""
        args = {}
        validKeys = ['message_code', '_messageCode_', 'message', 'roles', 'Roles']
        badKeys = set(_dict.keys()) - set(validKeys)
        if badKeys:
            raise ValueError('Unrecognized keys detected in dictionary for class GetAllRolesResponse: ' + ', '.join(badKeys))
        if '_messageCode_' in _dict:
            args['message_code'] = _dict.get('_messageCode_')
        if 'message' in _dict:
            args['message'] = _dict.get('message')
        if 'Roles' in _dict:
            args['roles'] = [GetAllRolesResponseAllOf1RolesItems._from_dict(x) for x in (_dict.get('Roles') )]
        return cls(**args)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'message_code') and self.message_code is not None:
            _dict['_messageCode_'] = self.message_code
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        if hasattr(self, 'roles') and self.roles is not None:
            _dict['Roles'] = [x._to_dict() for x in self.roles]
        return _dict

    def __str__(self):
        """Return a `str` version of this GetAllRolesResponse object."""
        return json.dumps(self._to_dict(), indent=2)

    def __eq__(self, other):
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetAllRolesResponseAllOf1RolesItems(object):
    """
    GetAllRolesResponseAllOf1RolesItems.

    :attr str ID: (optional) Role ID.
    :attr str description: (optional) Role description.
    :attr list[str] permissions: (optional) List of role permissions.
    :attr str role_name: (optional) Role name.
    """

    def __init__(self, ID=None, description=None, permissions=None, role_name=None):
        """
        Initialize a GetAllRolesResponseAllOf1RolesItems object.

        :param str ID: (optional) Role ID.
        :param str description: (optional) Role description.
        :param list[str] permissions: (optional) List of role permissions.
        :param str role_name: (optional) Role name.
        """
        self.ID = ID
        self.description = description
        self.permissions = permissions
        self.role_name = role_name

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetAllRolesResponseAllOf1RolesItems object from a json dictionary."""
        args = {}
        validKeys = ['ID', 'description', 'permissions', 'role_name']
        badKeys = set(_dict.keys()) - set(validKeys)
        if badKeys:
            raise ValueError('Unrecognized keys detected in dictionary for class GetAllRolesResponseAllOf1RolesItems: ' + ', '.join(badKeys))
        if 'ID' in _dict:
            args['ID'] = _dict.get('ID')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'permissions' in _dict:
            args['permissions'] = _dict.get('permissions')
        if 'role_name' in _dict:
            args['role_name'] = _dict.get('role_name')
        return cls(**args)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'ID') and self.ID is not None:
            _dict['ID'] = self.ID
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'permissions') and self.permissions is not None:
            _dict['permissions'] = self.permissions
        if hasattr(self, 'role_name') and self.role_name is not None:
            _dict['role_name'] = self.role_name
        return _dict

    def __str__(self):
        """Return a `str` version of this GetAllRolesResponseAllOf1RolesItems object."""
        return json.dumps(self._to_dict(), indent=2)

    def __eq__(self, other):
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetAllUsersResponse(object):
    """
    GetAllUsersResponse.

    :attr str message_code: (optional) message code.
    :attr str message: (optional) message.
    :attr list[GetAllUsersResponseAllOf1UsersInfoItems] users_info: (optional)
    """

    def __init__(self, message_code=None, message=None, users_info=None):
        """
        Initialize a GetAllUsersResponse object.

        :param str message_code: (optional) message code.
        :param str message: (optional) message.
        :param list[GetAllUsersResponseAllOf1UsersInfoItems] users_info: (optional)
        """
        self.message_code = message_code
        self.message = message
        self.users_info = users_info

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetAllUsersResponse object from a json dictionary."""
        args = {}
        validKeys = ['message_code', '_messageCode_', 'message', 'users_info', 'UsersInfo']
        badKeys = set(_dict.keys()) - set(validKeys)
        if badKeys:
            raise ValueError('Unrecognized keys detected in dictionary for class GetAllUsersResponse: ' + ', '.join(badKeys))
        if '_messageCode_' in _dict:
            args['message_code'] = _dict.get('_messageCode_')
        if 'message' in _dict:
            args['message'] = _dict.get('message')
        if 'UsersInfo' in _dict:
            args['users_info'] = [GetAllUsersResponseAllOf1UsersInfoItems._from_dict(x) for x in (_dict.get('UsersInfo') )]
        return cls(**args)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'message_code') and self.message_code is not None:
            _dict['_messageCode_'] = self.message_code
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        if hasattr(self, 'users_info') and self.users_info is not None:
            _dict['UsersInfo'] = [x._to_dict() for x in self.users_info]
        return _dict

    def __str__(self):
        """Return a `str` version of this GetAllUsersResponse object."""
        return json.dumps(self._to_dict(), indent=2)

    def __eq__(self, other):
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetAllUsersResponseAllOf1UsersInfoItems(object):
    """
    GetAllUsersResponseAllOf1UsersInfoItems.

    :attr str approval_status: (optional) Approval status of user.
    :attr str authenticator: (optional) User authenticator.
    :attr str created_timestamp: (optional) Timestamp of creation.
    :attr str current_account_status: (optional) User current account status.
    :attr str display_name: (optional) User display name.
    :attr str email: (optional) User email.
    :attr str last_modified_timestamp: (optional) Timestamp of last modification.
    :attr list[str] permissions: (optional) List of user permissions.
    :attr str role: (optional) User role.
    :attr str uid: (optional) User ID.
    :attr list[str] user_roles: (optional) List of user roles.
    :attr str username: (optional) User Name.
    """

    def __init__(self, approval_status=None, authenticator=None, created_timestamp=None, current_account_status=None, display_name=None, email=None, last_modified_timestamp=None, permissions=None, role=None, uid=None, user_roles=None, username=None):
        """
        Initialize a GetAllUsersResponseAllOf1UsersInfoItems object.

        :param str approval_status: (optional) Approval status of user.
        :param str authenticator: (optional) User authenticator.
        :param str created_timestamp: (optional) Timestamp of creation.
        :param str current_account_status: (optional) User current account status.
        :param str display_name: (optional) User display name.
        :param str email: (optional) User email.
        :param str last_modified_timestamp: (optional) Timestamp of last
               modification.
        :param list[str] permissions: (optional) List of user permissions.
        :param str role: (optional) User role.
        :param str uid: (optional) User ID.
        :param list[str] user_roles: (optional) List of user roles.
        :param str username: (optional) User Name.
        """
        self.approval_status = approval_status
        self.authenticator = authenticator
        self.created_timestamp = created_timestamp
        self.current_account_status = current_account_status
        self.display_name = display_name
        self.email = email
        self.last_modified_timestamp = last_modified_timestamp
        self.permissions = permissions
        self.role = role
        self.uid = uid
        self.user_roles = user_roles
        self.username = username

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetAllUsersResponseAllOf1UsersInfoItems object from a json dictionary."""
        args = {}
        validKeys = ['approval_status', 'authenticator', 'created_timestamp', 'current_account_status', 'display_name', 'displayName', 'email', 'last_modified_timestamp', 'permissions', 'role', 'uid', 'user_roles', 'username']
        badKeys = set(_dict.keys()) - set(validKeys)
        if badKeys:
            raise ValueError('Unrecognized keys detected in dictionary for class GetAllUsersResponseAllOf1UsersInfoItems: ' + ', '.join(badKeys))
        if 'approval_status' in _dict:
            args['approval_status'] = _dict.get('approval_status')
        if 'authenticator' in _dict:
            args['authenticator'] = _dict.get('authenticator')
        if 'created_timestamp' in _dict:
            args['created_timestamp'] = _dict.get('created_timestamp')
        if 'current_account_status' in _dict:
            args['current_account_status'] = _dict.get('current_account_status')
        if 'displayName' in _dict:
            args['display_name'] = _dict.get('displayName')
        if 'email' in _dict:
            args['email'] = _dict.get('email')
        if 'last_modified_timestamp' in _dict:
            args['last_modified_timestamp'] = _dict.get('last_modified_timestamp')
        if 'permissions' in _dict:
            args['permissions'] = _dict.get('permissions')
        if 'role' in _dict:
            args['role'] = _dict.get('role')
        if 'uid' in _dict:
            args['uid'] = _dict.get('uid')
        if 'user_roles' in _dict:
            args['user_roles'] = _dict.get('user_roles')
        if 'username' in _dict:
            args['username'] = _dict.get('username')
        return cls(**args)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'approval_status') and self.approval_status is not None:
            _dict['approval_status'] = self.approval_status
        if hasattr(self, 'authenticator') and self.authenticator is not None:
            _dict['authenticator'] = self.authenticator
        if hasattr(self, 'created_timestamp') and self.created_timestamp is not None:
            _dict['created_timestamp'] = self.created_timestamp
        if hasattr(self, 'current_account_status') and self.current_account_status is not None:
            _dict['current_account_status'] = self.current_account_status
        if hasattr(self, 'display_name') and self.display_name is not None:
            _dict['displayName'] = self.display_name
        if hasattr(self, 'email') and self.email is not None:
            _dict['email'] = self.email
        if hasattr(self, 'last_modified_timestamp') and self.last_modified_timestamp is not None:
            _dict['last_modified_timestamp'] = self.last_modified_timestamp
        if hasattr(self, 'permissions') and self.permissions is not None:
            _dict['permissions'] = self.permissions
        if hasattr(self, 'role') and self.role is not None:
            _dict['role'] = self.role
        if hasattr(self, 'uid') and self.uid is not None:
            _dict['uid'] = self.uid
        if hasattr(self, 'user_roles') and self.user_roles is not None:
            _dict['user_roles'] = self.user_roles
        if hasattr(self, 'username') and self.username is not None:
            _dict['username'] = self.username
        return _dict

    def __str__(self):
        """Return a `str` version of this GetAllUsersResponseAllOf1UsersInfoItems object."""
        return json.dumps(self._to_dict(), indent=2)

    def __eq__(self, other):
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetMeResponse(object):
    """
    GetMeResponse.

    :attr str message_code: (optional) message code.
    :attr str message: (optional) message.
    :attr GetMeResponseAllOf1UserInfo user_info: (optional)
    """

    def __init__(self, message_code=None, message=None, user_info=None):
        """
        Initialize a GetMeResponse object.

        :param str message_code: (optional) message code.
        :param str message: (optional) message.
        :param GetMeResponseAllOf1UserInfo user_info: (optional)
        """
        self.message_code = message_code
        self.message = message
        self.user_info = user_info

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetMeResponse object from a json dictionary."""
        args = {}
        validKeys = ['message_code', '_messageCode_', 'message', 'user_info', 'UserInfo']
        badKeys = set(_dict.keys()) - set(validKeys)
        if badKeys:
            raise ValueError('Unrecognized keys detected in dictionary for class GetMeResponse: ' + ', '.join(badKeys))
        if '_messageCode_' in _dict:
            args['message_code'] = _dict.get('_messageCode_')
        if 'message' in _dict:
            args['message'] = _dict.get('message')
        if 'UserInfo' in _dict:
            args['user_info'] = GetMeResponseAllOf1UserInfo._from_dict(_dict.get('UserInfo'))
        return cls(**args)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'message_code') and self.message_code is not None:
            _dict['_messageCode_'] = self.message_code
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        if hasattr(self, 'user_info') and self.user_info is not None:
            _dict['UserInfo'] = self.user_info._to_dict()
        return _dict

    def __str__(self):
        """Return a `str` version of this GetMeResponse object."""
        return json.dumps(self._to_dict(), indent=2)

    def __eq__(self, other):
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetMeResponseAllOf1UserInfo(object):
    """
    GetMeResponseAllOf1UserInfo.

    :attr str display_name: (optional) User display name.
    :attr str email: (optional) User email.
    :attr list[str] permissions: (optional) List of user permissions.
    :attr str role: (optional) User role.
    :attr str uid: (optional) User ID.
    :attr str username: (optional) User Name.
    """

    def __init__(self, display_name=None, email=None, permissions=None, role=None, uid=None, username=None):
        """
        Initialize a GetMeResponseAllOf1UserInfo object.

        :param str display_name: (optional) User display name.
        :param str email: (optional) User email.
        :param list[str] permissions: (optional) List of user permissions.
        :param str role: (optional) User role.
        :param str uid: (optional) User ID.
        :param str username: (optional) User Name.
        """
        self.display_name = display_name
        self.email = email
        self.permissions = permissions
        self.role = role
        self.uid = uid
        self.username = username

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetMeResponseAllOf1UserInfo object from a json dictionary."""
        args = {}
        validKeys = ['display_name', 'displayName', 'email', 'permissions', 'role', 'uid', 'username']
        badKeys = set(_dict.keys()) - set(validKeys)
        if badKeys:
            raise ValueError('Unrecognized keys detected in dictionary for class GetMeResponseAllOf1UserInfo: ' + ', '.join(badKeys))
        if 'displayName' in _dict:
            args['display_name'] = _dict.get('displayName')
        if 'email' in _dict:
            args['email'] = _dict.get('email')
        if 'permissions' in _dict:
            args['permissions'] = _dict.get('permissions')
        if 'role' in _dict:
            args['role'] = _dict.get('role')
        if 'uid' in _dict:
            args['uid'] = _dict.get('uid')
        if 'username' in _dict:
            args['username'] = _dict.get('username')
        return cls(**args)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'display_name') and self.display_name is not None:
            _dict['displayName'] = self.display_name
        if hasattr(self, 'email') and self.email is not None:
            _dict['email'] = self.email
        if hasattr(self, 'permissions') and self.permissions is not None:
            _dict['permissions'] = self.permissions
        if hasattr(self, 'role') and self.role is not None:
            _dict['role'] = self.role
        if hasattr(self, 'uid') and self.uid is not None:
            _dict['uid'] = self.uid
        if hasattr(self, 'username') and self.username is not None:
            _dict['username'] = self.username
        return _dict

    def __str__(self):
        """Return a `str` version of this GetMeResponseAllOf1UserInfo object."""
        return json.dumps(self._to_dict(), indent=2)

    def __eq__(self, other):
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetPermissionsResponse(object):
    """
    GetPermissionsResponse.

    :attr str message_code: (optional) message code.
    :attr str message: (optional) message.
    :attr list[str] permissions: (optional)
    """

    def __init__(self, message_code=None, message=None, permissions=None):
        """
        Initialize a GetPermissionsResponse object.

        :param str message_code: (optional) message code.
        :param str message: (optional) message.
        :param list[str] permissions: (optional)
        """
        self.message_code = message_code
        self.message = message
        self.permissions = permissions

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetPermissionsResponse object from a json dictionary."""
        args = {}
        validKeys = ['message_code', '_messageCode_', 'message', 'permissions', 'Permissions']
        badKeys = set(_dict.keys()) - set(validKeys)
        if badKeys:
            raise ValueError('Unrecognized keys detected in dictionary for class GetPermissionsResponse: ' + ', '.join(badKeys))
        if '_messageCode_' in _dict:
            args['message_code'] = _dict.get('_messageCode_')
        if 'message' in _dict:
            args['message'] = _dict.get('message')
        if 'Permissions' in _dict:
            args['permissions'] = _dict.get('Permissions')
        return cls(**args)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'message_code') and self.message_code is not None:
            _dict['_messageCode_'] = self.message_code
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        if hasattr(self, 'permissions') and self.permissions is not None:
            _dict['Permissions'] = self.permissions
        return _dict

    def __str__(self):
        """Return a `str` version of this GetPermissionsResponse object."""
        return json.dumps(self._to_dict(), indent=2)

    def __eq__(self, other):
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetRoleResponse(object):
    """
    GetRoleResponse.

    :attr str message_code: (optional) message code.
    :attr str message: (optional) message.
    :attr GetRoleResponseAllOf1RoleInfo role_info: (optional)
    """

    def __init__(self, message_code=None, message=None, role_info=None):
        """
        Initialize a GetRoleResponse object.

        :param str message_code: (optional) message code.
        :param str message: (optional) message.
        :param GetRoleResponseAllOf1RoleInfo role_info: (optional)
        """
        self.message_code = message_code
        self.message = message
        self.role_info = role_info

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetRoleResponse object from a json dictionary."""
        args = {}
        validKeys = ['message_code', '_messageCode_', 'message', 'role_info', 'RoleInfo']
        badKeys = set(_dict.keys()) - set(validKeys)
        if badKeys:
            raise ValueError('Unrecognized keys detected in dictionary for class GetRoleResponse: ' + ', '.join(badKeys))
        if '_messageCode_' in _dict:
            args['message_code'] = _dict.get('_messageCode_')
        if 'message' in _dict:
            args['message'] = _dict.get('message')
        if 'RoleInfo' in _dict:
            args['role_info'] = GetRoleResponseAllOf1RoleInfo._from_dict(_dict.get('RoleInfo'))
        return cls(**args)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'message_code') and self.message_code is not None:
            _dict['_messageCode_'] = self.message_code
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        if hasattr(self, 'role_info') and self.role_info is not None:
            _dict['RoleInfo'] = self.role_info._to_dict()
        return _dict

    def __str__(self):
        """Return a `str` version of this GetRoleResponse object."""
        return json.dumps(self._to_dict(), indent=2)

    def __eq__(self, other):
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetRoleResponseAllOf1RoleInfo(object):
    """
    GetRoleResponseAllOf1RoleInfo.

    :attr str ID: (optional) Role ID.
    :attr str description: (optional) Role description.
    :attr list[str] permissions: (optional) List of role permissions.
    :attr str role_name: (optional) Role name.
    """

    def __init__(self, ID=None, description=None, permissions=None, role_name=None):
        """
        Initialize a GetRoleResponseAllOf1RoleInfo object.

        :param str ID: (optional) Role ID.
        :param str description: (optional) Role description.
        :param list[str] permissions: (optional) List of role permissions.
        :param str role_name: (optional) Role name.
        """
        self.ID = ID
        self.description = description
        self.permissions = permissions
        self.role_name = role_name

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetRoleResponseAllOf1RoleInfo object from a json dictionary."""
        args = {}
        validKeys = ['ID', 'description', 'permissions', 'role_name']
        badKeys = set(_dict.keys()) - set(validKeys)
        if badKeys:
            raise ValueError('Unrecognized keys detected in dictionary for class GetRoleResponseAllOf1RoleInfo: ' + ', '.join(badKeys))
        if 'ID' in _dict:
            args['ID'] = _dict.get('ID')
        if 'description' in _dict:
            args['description'] = _dict.get('description')
        if 'permissions' in _dict:
            args['permissions'] = _dict.get('permissions')
        if 'role_name' in _dict:
            args['role_name'] = _dict.get('role_name')
        return cls(**args)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'ID') and self.ID is not None:
            _dict['ID'] = self.ID
        if hasattr(self, 'description') and self.description is not None:
            _dict['description'] = self.description
        if hasattr(self, 'permissions') and self.permissions is not None:
            _dict['permissions'] = self.permissions
        if hasattr(self, 'role_name') and self.role_name is not None:
            _dict['role_name'] = self.role_name
        return _dict

    def __str__(self):
        """Return a `str` version of this GetRoleResponseAllOf1RoleInfo object."""
        return json.dumps(self._to_dict(), indent=2)

    def __eq__(self, other):
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetUserResponse(object):
    """
    GetUserResponse.

    :attr str message_code: (optional) message code.
    :attr str message: (optional) message.
    :attr GetUserResponseAllOf1UserInfo user_info: (optional)
    """

    def __init__(self, message_code=None, message=None, user_info=None):
        """
        Initialize a GetUserResponse object.

        :param str message_code: (optional) message code.
        :param str message: (optional) message.
        :param GetUserResponseAllOf1UserInfo user_info: (optional)
        """
        self.message_code = message_code
        self.message = message
        self.user_info = user_info

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetUserResponse object from a json dictionary."""
        args = {}
        validKeys = ['message_code', '_messageCode_', 'message', 'user_info', 'UserInfo']
        badKeys = set(_dict.keys()) - set(validKeys)
        if badKeys:
            raise ValueError('Unrecognized keys detected in dictionary for class GetUserResponse: ' + ', '.join(badKeys))
        if '_messageCode_' in _dict:
            args['message_code'] = _dict.get('_messageCode_')
        if 'message' in _dict:
            args['message'] = _dict.get('message')
        if 'UserInfo' in _dict:
            args['user_info'] = GetUserResponseAllOf1UserInfo._from_dict(_dict.get('UserInfo'))
        return cls(**args)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'message_code') and self.message_code is not None:
            _dict['_messageCode_'] = self.message_code
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        if hasattr(self, 'user_info') and self.user_info is not None:
            _dict['UserInfo'] = self.user_info._to_dict()
        return _dict

    def __str__(self):
        """Return a `str` version of this GetUserResponse object."""
        return json.dumps(self._to_dict(), indent=2)

    def __eq__(self, other):
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class GetUserResponseAllOf1UserInfo(object):
    """
    GetUserResponseAllOf1UserInfo.

    :attr str approval_status: (optional) Approval status of user.
    :attr str authenticator: (optional) User authenticator.
    :attr str created_timestamp: (optional) Timestamp of creation.
    :attr str current_account_status: (optional) User current account status.
    :attr str display_name: (optional) User display name.
    :attr str email: (optional) User email.
    :attr str first_failed_attempt_timestamp: (optional) Timestamp of first failed
          attempt.
    :attr str last_modified_timestamp: (optional) Timestamp of last modification.
    :attr list[str] permissions: (optional) List of user permissions.
    :attr float recent_number_of_failed_attempts: (optional) Recent number of failed
          attempts.
    :attr str release_lock_at_timestamp: (optional) Release lock at timestamp.
    :attr str role: (optional) User role.
    :attr str uid: (optional) User ID.
    :attr list[str] user_roles: (optional) List of user roles.
    :attr str username: (optional) User Name.
    """

    def __init__(self, approval_status=None, authenticator=None, created_timestamp=None, current_account_status=None, display_name=None, email=None, first_failed_attempt_timestamp=None, last_modified_timestamp=None, permissions=None, recent_number_of_failed_attempts=None, release_lock_at_timestamp=None, role=None, uid=None, user_roles=None, username=None):
        """
        Initialize a GetUserResponseAllOf1UserInfo object.

        :param str approval_status: (optional) Approval status of user.
        :param str authenticator: (optional) User authenticator.
        :param str created_timestamp: (optional) Timestamp of creation.
        :param str current_account_status: (optional) User current account status.
        :param str display_name: (optional) User display name.
        :param str email: (optional) User email.
        :param str first_failed_attempt_timestamp: (optional) Timestamp of first
               failed attempt.
        :param str last_modified_timestamp: (optional) Timestamp of last
               modification.
        :param list[str] permissions: (optional) List of user permissions.
        :param float recent_number_of_failed_attempts: (optional) Recent number of
               failed attempts.
        :param str release_lock_at_timestamp: (optional) Release lock at timestamp.
        :param str role: (optional) User role.
        :param str uid: (optional) User ID.
        :param list[str] user_roles: (optional) List of user roles.
        :param str username: (optional) User Name.
        """
        self.approval_status = approval_status
        self.authenticator = authenticator
        self.created_timestamp = created_timestamp
        self.current_account_status = current_account_status
        self.display_name = display_name
        self.email = email
        self.first_failed_attempt_timestamp = first_failed_attempt_timestamp
        self.last_modified_timestamp = last_modified_timestamp
        self.permissions = permissions
        self.recent_number_of_failed_attempts = recent_number_of_failed_attempts
        self.release_lock_at_timestamp = release_lock_at_timestamp
        self.role = role
        self.uid = uid
        self.user_roles = user_roles
        self.username = username

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a GetUserResponseAllOf1UserInfo object from a json dictionary."""
        args = {}
        validKeys = ['approval_status', 'authenticator', 'created_timestamp', 'current_account_status', 'display_name', 'displayName', 'email', 'first_failed_attempt_timestamp', 'last_modified_timestamp', 'permissions', 'recent_number_of_failed_attempts', 'release_lock_at_timestamp', 'role', 'uid', 'user_roles', 'username']
        badKeys = set(_dict.keys()) - set(validKeys)
        if badKeys:
            raise ValueError('Unrecognized keys detected in dictionary for class GetUserResponseAllOf1UserInfo: ' + ', '.join(badKeys))
        if 'approval_status' in _dict:
            args['approval_status'] = _dict.get('approval_status')
        if 'authenticator' in _dict:
            args['authenticator'] = _dict.get('authenticator')
        if 'created_timestamp' in _dict:
            args['created_timestamp'] = _dict.get('created_timestamp')
        if 'current_account_status' in _dict:
            args['current_account_status'] = _dict.get('current_account_status')
        if 'displayName' in _dict:
            args['display_name'] = _dict.get('displayName')
        if 'email' in _dict:
            args['email'] = _dict.get('email')
        if 'first_failed_attempt_timestamp' in _dict:
            args['first_failed_attempt_timestamp'] = _dict.get('first_failed_attempt_timestamp')
        if 'last_modified_timestamp' in _dict:
            args['last_modified_timestamp'] = _dict.get('last_modified_timestamp')
        if 'permissions' in _dict:
            args['permissions'] = _dict.get('permissions')
        if 'recent_number_of_failed_attempts' in _dict:
            args['recent_number_of_failed_attempts'] = _dict.get('recent_number_of_failed_attempts')
        if 'release_lock_at_timestamp' in _dict:
            args['release_lock_at_timestamp'] = _dict.get('release_lock_at_timestamp')
        if 'role' in _dict:
            args['role'] = _dict.get('role')
        if 'uid' in _dict:
            args['uid'] = _dict.get('uid')
        if 'user_roles' in _dict:
            args['user_roles'] = _dict.get('user_roles')
        if 'username' in _dict:
            args['username'] = _dict.get('username')
        return cls(**args)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'approval_status') and self.approval_status is not None:
            _dict['approval_status'] = self.approval_status
        if hasattr(self, 'authenticator') and self.authenticator is not None:
            _dict['authenticator'] = self.authenticator
        if hasattr(self, 'created_timestamp') and self.created_timestamp is not None:
            _dict['created_timestamp'] = self.created_timestamp
        if hasattr(self, 'current_account_status') and self.current_account_status is not None:
            _dict['current_account_status'] = self.current_account_status
        if hasattr(self, 'display_name') and self.display_name is not None:
            _dict['displayName'] = self.display_name
        if hasattr(self, 'email') and self.email is not None:
            _dict['email'] = self.email
        if hasattr(self, 'first_failed_attempt_timestamp') and self.first_failed_attempt_timestamp is not None:
            _dict['first_failed_attempt_timestamp'] = self.first_failed_attempt_timestamp
        if hasattr(self, 'last_modified_timestamp') and self.last_modified_timestamp is not None:
            _dict['last_modified_timestamp'] = self.last_modified_timestamp
        if hasattr(self, 'permissions') and self.permissions is not None:
            _dict['permissions'] = self.permissions
        if hasattr(self, 'recent_number_of_failed_attempts') and self.recent_number_of_failed_attempts is not None:
            _dict['recent_number_of_failed_attempts'] = self.recent_number_of_failed_attempts
        if hasattr(self, 'release_lock_at_timestamp') and self.release_lock_at_timestamp is not None:
            _dict['release_lock_at_timestamp'] = self.release_lock_at_timestamp
        if hasattr(self, 'role') and self.role is not None:
            _dict['role'] = self.role
        if hasattr(self, 'uid') and self.uid is not None:
            _dict['uid'] = self.uid
        if hasattr(self, 'user_roles') and self.user_roles is not None:
            _dict['user_roles'] = self.user_roles
        if hasattr(self, 'username') and self.username is not None:
            _dict['username'] = self.username
        return _dict

    def __str__(self):
        """Return a `str` version of this GetUserResponseAllOf1UserInfo object."""
        return json.dumps(self._to_dict(), indent=2)

    def __eq__(self, other):
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class LoginResponse(object):
    """
    LoginResponse.

    :attr str message_code: (optional) message code.
    :attr str message: (optional) message.
    :attr str token: (optional) Authorization bearer token used for accessing api.
    """

    def __init__(self, message_code=None, message=None, token=None):
        """
        Initialize a LoginResponse object.

        :param str message_code: (optional) message code.
        :param str message: (optional) message.
        :param str token: (optional) Authorization bearer token used for accessing
               api.
        """
        self.message_code = message_code
        self.message = message
        self.token = token

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a LoginResponse object from a json dictionary."""
        args = {}
        validKeys = ['message_code', '_messageCode_', 'message', 'token']
        badKeys = set(_dict.keys()) - set(validKeys)
        if badKeys:
            raise ValueError('Unrecognized keys detected in dictionary for class LoginResponse: ' + ', '.join(badKeys))
        if '_messageCode_' in _dict:
            args['message_code'] = _dict.get('_messageCode_')
        if 'message' in _dict:
            args['message'] = _dict.get('message')
        if 'token' in _dict:
            args['token'] = _dict.get('token')
        return cls(**args)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'message_code') and self.message_code is not None:
            _dict['_messageCode_'] = self.message_code
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        if hasattr(self, 'token') and self.token is not None:
            _dict['token'] = self.token
        return _dict

    def __str__(self):
        """Return a `str` version of this LoginResponse object."""
        return json.dumps(self._to_dict(), indent=2)

    def __eq__(self, other):
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class RelatedAssetsFindSuccessResponse(object):
    """
    RelatedAssetsFindSuccessResponse.

    :attr str message_code: (optional) message code.
    :attr str message: (optional) message.
    :attr list[RelatedAssetsFindSuccessResponseAllOf1RelatedAssetsItems]
          related_assets: (optional)
    """

    def __init__(self, message_code=None, message=None, related_assets=None):
        """
        Initialize a RelatedAssetsFindSuccessResponse object.

        :param str message_code: (optional) message code.
        :param str message: (optional) message.
        :param list[RelatedAssetsFindSuccessResponseAllOf1RelatedAssetsItems]
               related_assets: (optional)
        """
        self.message_code = message_code
        self.message = message
        self.related_assets = related_assets

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RelatedAssetsFindSuccessResponse object from a json dictionary."""
        args = {}
        validKeys = ['message_code', '_messageCode_', 'message', 'related_assets', 'relatedAssets']
        badKeys = set(_dict.keys()) - set(validKeys)
        if badKeys:
            raise ValueError('Unrecognized keys detected in dictionary for class RelatedAssetsFindSuccessResponse: ' + ', '.join(badKeys))
        if '_messageCode_' in _dict:
            args['message_code'] = _dict.get('_messageCode_')
        if 'message' in _dict:
            args['message'] = _dict.get('message')
        if 'relatedAssets' in _dict:
            args['related_assets'] = [RelatedAssetsFindSuccessResponseAllOf1RelatedAssetsItems._from_dict(x) for x in (_dict.get('relatedAssets') )]
        return cls(**args)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'message_code') and self.message_code is not None:
            _dict['_messageCode_'] = self.message_code
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        if hasattr(self, 'related_assets') and self.related_assets is not None:
            _dict['relatedAssets'] = [x._to_dict() for x in self.related_assets]
        return _dict

    def __str__(self):
        """Return a `str` version of this RelatedAssetsFindSuccessResponse object."""
        return json.dumps(self._to_dict(), indent=2)

    def __eq__(self, other):
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class RelatedAssetsFindSuccessResponseAllOf1RelatedAssetsItems(object):
    """
    RelatedAssetsFindSuccessResponseAllOf1RelatedAssetsItems.

    :attr str name: (optional) asset_name.
    :attr str type: (optional) asset_type.
    """

    def __init__(self, name=None, type=None):
        """
        Initialize a RelatedAssetsFindSuccessResponseAllOf1RelatedAssetsItems object.

        :param str name: (optional) asset_name.
        :param str type: (optional) asset_type.
        """
        self.name = name
        self.type = type

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a RelatedAssetsFindSuccessResponseAllOf1RelatedAssetsItems object from a json dictionary."""
        args = {}
        validKeys = ['name', '_name', 'type', '_type']
        badKeys = set(_dict.keys()) - set(validKeys)
        if badKeys:
            raise ValueError('Unrecognized keys detected in dictionary for class RelatedAssetsFindSuccessResponseAllOf1RelatedAssetsItems: ' + ', '.join(badKeys))
        if '_name' in _dict:
            args['name'] = _dict.get('_name')
        if '_type' in _dict:
            args['type'] = _dict.get('_type')
        return cls(**args)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'name') and self.name is not None:
            _dict['_name'] = self.name
        if hasattr(self, 'type') and self.type is not None:
            _dict['_type'] = self.type
        return _dict

    def __str__(self):
        """Return a `str` version of this RelatedAssetsFindSuccessResponseAllOf1RelatedAssetsItems object."""
        return json.dumps(self._to_dict(), indent=2)

    def __eq__(self, other):
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class SuccessResponse(object):
    """
    SuccessResponse.

    :attr str message_code: (optional) message code.
    :attr str message: (optional) message.
    """

    def __init__(self, message_code=None, message=None):
        """
        Initialize a SuccessResponse object.

        :param str message_code: (optional) message code.
        :param str message: (optional) message.
        """
        self.message_code = message_code
        self.message = message

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a SuccessResponse object from a json dictionary."""
        args = {}
        validKeys = ['message_code', '_messageCode_', 'message']
        badKeys = set(_dict.keys()) - set(validKeys)
        if badKeys:
            raise ValueError('Unrecognized keys detected in dictionary for class SuccessResponse: ' + ', '.join(badKeys))
        if '_messageCode_' in _dict:
            args['message_code'] = _dict.get('_messageCode_')
        if 'message' in _dict:
            args['message'] = _dict.get('message')
        return cls(**args)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'message_code') and self.message_code is not None:
            _dict['_messageCode_'] = self.message_code
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        return _dict

    def __str__(self):
        """Return a `str` version of this SuccessResponse object."""
        return json.dumps(self._to_dict(), indent=2)

    def __eq__(self, other):
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


class TypesSuccessResponse(object):
    """
    TypesSuccessResponse.

    :attr str message_code: (optional) message code.
    :attr str message: (optional) message.
    :attr list[object] types: (optional)
    """

    def __init__(self, message_code=None, message=None, types=None):
        """
        Initialize a TypesSuccessResponse object.

        :param str message_code: (optional) message code.
        :param str message: (optional) message.
        :param list[object] types: (optional)
        """
        self.message_code = message_code
        self.message = message
        self.types = types

    @classmethod
    def _from_dict(cls, _dict):
        """Initialize a TypesSuccessResponse object from a json dictionary."""
        args = {}
        validKeys = ['message_code', '_messageCode_', 'message', 'types', 'Types']
        badKeys = set(_dict.keys()) - set(validKeys)
        if badKeys:
            raise ValueError('Unrecognized keys detected in dictionary for class TypesSuccessResponse: ' + ', '.join(badKeys))
        if '_messageCode_' in _dict:
            args['message_code'] = _dict.get('_messageCode_')
        if 'message' in _dict:
            args['message'] = _dict.get('message')
        if 'Types' in _dict:
            args['types'] = _dict.get('Types')
        return cls(**args)

    def _to_dict(self):
        """Return a json dictionary representing this model."""
        _dict = {}
        if hasattr(self, 'message_code') and self.message_code is not None:
            _dict['_messageCode_'] = self.message_code
        if hasattr(self, 'message') and self.message is not None:
            _dict['message'] = self.message
        if hasattr(self, 'types') and self.types is not None:
            _dict['Types'] = self.types
        return _dict

    def __str__(self):
        """Return a `str` version of this TypesSuccessResponse object."""
        return json.dumps(self._to_dict(), indent=2)

    def __eq__(self, other):
        """Return `true` when self and other are equal, false otherwise."""
        if not isinstance(other, self.__class__):
            return False
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Return `true` when self and other are not equal, false otherwise."""
        return not self == other


