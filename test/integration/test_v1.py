# coding: utf-8

# Copyright 2019 IBM All Rights Reserved.
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
Test methods in the icpd_v1 module
"""
import unittest
import os
import json
import logging
from mysdk import icpd_v1


class Icp4dSDKTest(unittest.TestCase):
    """
    Test methods in the icpd_v1 module
    """
    logging.basicConfig(level=logging.DEBUG)

    def __init__(self, *args, **kwargs):
        super(Icp4dSDKTest, self).__init__(*args, **kwargs)
        """
        Test the get_authorization_token method
        """
        VCAP_SERVICES = '{"icpd": [{"credentials": {"url": "https://i493-master-1.fyre.ibm.com:31843/icp4d-api", "icp4d_url": "https://i493-master-1.fyre.ibm.com:31843/icp4d-api", "username": "admin","password": "password"},"label": "icpd","name": "icpd","plan": "standard"}]}'
        os.environ['VCAP_SERVICES'] = VCAP_SERVICES
        # setup instance of service class
        self.service = icpd_v1.IcpdV1('i493-master-1.fyre.ibm.com:31843/icp4d-api', 'basic')
        self.service.disable_SSL_verification()
        # get auth bearer token
        auth_token = self.service.get_authorization_token('password', 'admin')
        token = auth_token.get_result()['token']
        # set bearer token for icp4d access token
        self.service.set_icp4d_access_token(token)

    # test user info
    user_info = {
        'display_name': 'Jane Doe',
        'email': 'string',
        'user_name': 'jane_test',
        'user_roles': ['Data Engineer'],
        'approval_status': 'approved',
        'password': 'password',
    }

    role = {
        'permission': ['administrator', 'access_catalog'],
        'role_name': 'SDK_API_TEST',
        'description': 'test for sdk api (update)',
    }

    def test_get_all_users(self):
        res = self.service.get_all_users()
        # print(res)
        text = res.get_result().text
        print(text)
        self.assertIsNotNone(text, None)
        self.assertEqual(res.status_code, 200)

    def test_create_user(self):
        res = self.service.create_user(self.user_info['display_name'], self.user_info['email'],
                                       self.user_info['user_name'],
                                       self.user_info['user_roles'])
        self.assertIsNotNone(res)
        self.assertEqual(res.status_code, 200)

    def test_update_user(self):
        res = self.service.update_user(self.user_info['user_name'], self.user_info['approval_status'],
                                       self.user_info['display_name'],
                                       self.user_info['email'],
                                       self.user_info['user_roles'])
        self.assertIsNotNone(res)
        self.assertEqual(res.status_code, 200)

    def test_get_user(self):
        res = self.service.get_user(self.user_info['user_name'])
        # print(res)
        text = res.get_result().text
        print(text)
        self.assertIsNotNone(res)
        self.assertEqual(res.status_code, 200)


    def test_list_all_roles(self):
        res = self.service.get_all_roles()
        text = res.get_result().text
        print(text)
        self.assertIsNotNone(res)
        self.assertEqual(res.status_code, 200)


    def test_create_new_role(self):
        res = self.service.create_role(self.role['permission'], self.role['role_name'])
        self.assertIsNotNone(res, None)
        self.assertEqual(res.status_code, 200)

    def test_get_all_permissions(self):
        res = self.service.get_all_permissions()
        text = res.get_result().text
        print(text)
        self.assertIsNotNone(res, None)
        self.assertEqual(res.status_code, 200)

    def test_get_role(self):
        res = self.service.get_role(self.role['role_name'])
        text = res.get_result().text
        print(text)
        self.assertIsNotNone(res, None)
        self.assertEqual(res.status_code, 200)

    def test_update_role(self):
        res = self.service.update_role(self.role['role_name'], self.role['permission'], self.role['description'])
        self.assertIsNotNone(res, None)
        self.assertEqual(res.status_code, 200)

    # def test_change_password(self):
    #     res = self.service.change_password('password')
    #     self.assertIsNotNone(res, None)
    #     self.assertEqual(res.status_code, 200)

    def test_get_me(self):
        res = self.service.get_me()
        text = res.get_result().text
        print(text)
        self.assertIsNotNone(res, None)
        self.assertEqual(res.status_code, 200)

    def test_update_me(self):
        res = self.service.update_me()
        self.assertIsNotNone(res, None)
        self.assertEqual(res.status_code, 200)


    # delete

    # def test_delete_user(self):
    #     res = self.service.delete_user(self.user_info['user_name'])
    #     text = res.get_result().text
    #     print(text)
    #     self.assertIsNotNone(res)
    #     self.assertEqual(res.status_code, 200)
    #
    #
    # def test_delete_role(self):
    #     res = self.service.delete_role(self.role['role_name'])
    #     text = res.get_result().text
    #     print(text)
    #     self.assertIsNotNone(res)
    #     self.assertEqual(res.status_code, 200)


if __name__ == '__main__':
    unittest.main()
