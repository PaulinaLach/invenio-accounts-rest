# -*- coding: utf-8 -*-
#
# This file is part of Invenio.
# Copyright (C) 2016 CERN.
#
# Invenio is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# Invenio is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Invenio; if not, write to the
# Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA 02111-1307, USA.
#
# In applying this license, CERN does not
# waive the privileges and immunities granted to it by virtue of its status
# as an Intergovernmental Organization or submit itself to any jurisdiction.


"""Test module's REST API."""

from __future__ import absolute_import, print_function

import json

import pytest
from flask import url_for
from flask_security.utils import verify_password
from invenio_access.models import ActionUsers
from invenio_access.permissions import ParameterizedActionNeed
from invenio_db import db
from invenio_accounts.models import Role, User


# from invenio_accounts_rest.views import AssignRoleResource, \
#     RolesListResource, RoleResource, UnassignRoleResource, \
#     UserAccountResource, UserListResource, UserRolesListResource

from invenio_accounts_rest.views import RoleResource

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch


# def test_list_roles(app, users, create_roles, roles_data):
#     """Test listing all existing roles."""
#     with app.app_context():
#         with app.test_client() as client:
#             headers = [('Content-Type', 'application/json'),
#                        ('Accept', 'application/json')]
#
#             r1 = Role.query.filter_by(name=roles_data[0]['name']).one()
#             r2 = Role.query.filter_by(name=roles_data[1]['name']).one()
#
#             res = client.get(
#                 url_for(
#                     'invenio_accounts_rest.list_roles',
#                     page=1,
#                     size=2
#                 ),
#                 headers=headers
#             )
#
#             assert res.status_code == 200
#             response_data = json.loads(res.get_data(as_text=True))
#
#             assert len(response_data['hits']['hits']) == 2
#             assert response_data['total'] == 2
#             assert response_data['hits']['hits'][0] == {
#                 'links': {
#                     'self': url_for(
#                         'invenio_accounts_rest.role',
#                         role_id=users['user1'].roles[0].id,
#                         _external=True,
#                     )
#                 },
#                 'role': {
#                     'description': users['user1'].roles[0].description,
#                     'name': users['user1'].roles[0].name,
#                     'role_id': users['user1'].roles[0].id
#                 }
#             }
#
#
# @pytest.yield_fixture()
# def test_list_roles_permissions_mock(users):
#     return_value = {
#         'hits': {
#             'total': 1,
#             'hits': [
#                 {
#                     'links': {
#                         'self': url_for(
#                             'invenio_accounts_rest.role',
#                             role_id=users['user1'].roles[0].id,
#                             _external=True
#                         )
#                     },
#                     'role': {
#                         'description': users['user1'].roles[0].description,
#                         'name': users['user1'].roles[0].name,
#                         'id': users['user1'].roles[0].id
#                     }
#                 }
#             ]
#         }
#     }
#
#     with patch.object(
#             RolesListResource,
#             'get',
#             side_effect=[
#                 {'data': return_value, 'code': 401},
#                 {'data': return_value, 'code': 200},
#             ]
#     ):
#         yield
#
#
# def test_list_roles_permissions(app, users, test_list_roles_permissions_mock):
#     """Test permissions for listing roles.
#
#     This is testing the default permission factory.
#     Anonymous user cannot read roles.
#     Authenticated users can read roles.
#     """
#     headers = [('Content-Type', 'application/json'),
#                ('Accept', 'application/json')]
#
#     other_user = users['user2']
#
#     def get_test(access_token, expected_code):
#         with app.test_client() as client:
#             res = client.get(
#                 url_for(
#                     'invenio_accounts_rest.list_roles',
#                     access_token=access_token,
#                 ),
#                 headers=headers
#             )
#
#         assert res.status_code == expected_code
#
#     get_test(None, 401)  # anonymous user
#     get_test(other_user.allowed_token, 200)
#     # create access_token without user_write scope for each user and check
#     # that the returned code is 403
#
#
# def test_get_role(app, create_roles, roles_data):
#     """Test getting a role."""
#     with app.app_context():
#         with app.test_client() as client:
#             headers = [('Content-Type', 'application/json'),
#                        ('Accept', 'application/json')]
#
#             r1 = Role.query.filter_by(name=roles_data[0]['name']).one()
#
#             res = client.get(
#                 url_for(
#                     'invenio_accounts_rest.role',
#                     role_id=r1.id
#                 ),
#                 headers=headers
#             )
#
#             assert res.status_code == 200
#             response_data = json.loads(res.get_data(as_text=True))
#
#             assert response_data == {
#                 'links': {
#                     'self': url_for(
#                         'invenio_accounts_rest.role',
#                         role_id=r1.id,
#                         _external=True
#                     )
#                 },
#                 'role': {
#                     'description': r1.description,
#                     'name': r1.name,
#                     'role_id': r1.id
#                 }
#             }

#
# def test_get_role_permissions(app, users, create_roles, roles_data,
#                               role_permission_factory):
def test_read_role_permissions(app, users, create_roles,  roles_data):
    """Test permissions for getting a role.

    This is testing the default permission factory.
    Anonymous user cannot read roles.
    Authenticated users can read roles.
    """

    headers = [('Content-Type', 'application/json'),
               ('Accept', 'application/json')]

    def get_test(user, expected_code):
        with app.app_context():
            r1 = Role.query.filter_by(name=roles_data[0]['name']).one().id

        with app.test_client() as client:
            access_token=user.allowed_token if user else None

            url = url_for(
                'invenio_accounts_rest.role',
                role_id=r1,
                access_token=access_token,
            )
            res = client.get(
                url,
                headers=headers
            )

        assert res.status_code == expected_code

    with app.app_context():
        get_test(None, 401)  # anonymous user
    with app.app_context():
        get_test(users['user1'], 403)

        # allow the user
        # role_permission_factory['allowed_users'][user.id] = [user.id]
        # get_test(user.allowed_token, 200)


# def test_create_role(app, create_roles, roles_data):
#     """Test creating a role."""
#     with app.app_context():
#         with app.test_client() as client:
#             headers = [('Content-Type', 'application/json'),
#                        ('Accept', 'application/json')]
#
#             res = client.post(
#                 url_for('invenio_accounts_rest.list_roles'),
#                 data=json.dumps(
#                     {'name': 'role', 'description': 'desc'}
#                 ),
#                 headers=headers
#             )
#
#             assert res.status_code == 201
#             response_data = json.loads(res.get_data(as_text=True))
#
#             role_id = response_data['role']['role_id']
#             assert response_data == {
#                 'links': {
#                     'self': url_for(
#                         'invenio_accounts_rest.role',
#                         role_id=role_id,
#                         _external=True
#                     )
#                 },
#                 'role': {
#                     'description': 'desc',
#                     'name': 'role',
#                     'role_id': role_id
#                 }
#             }
#
#
# @pytest.yield_fixture()
# def test_create_role_permissions_mock():
#     role_id = 2
#     return_value = {
#         'links': {
#             'self': url_for(
#                 'invenio_accounts_rest.role',
#                 role_id=role_id,
#                 _external=True
#             )
#         },
#         'role': {
#             'description': 'desc',
#             'name': 'role',
#             'role_id': role_id
#         }
#     }
#
#     with patch.object(
#             RolesListResource,
#             'post',
#             side_effect=[
#                 {'data': return_value, 'code': 401},
#                 {'data': return_value, 'code': 200},
#                 {'data': return_value, 'code': 403},
#                 {'data': return_value, 'code': 200}
#             ]
#     ):
#         yield
#
#
# def test_create_role_permissions(app, users, create_roles, roles_data):
#     """Test creating a role permissions.
#
#     This is testing the default permission factory.
#     Anonymous user cannot create a role.
#     Allowed user and admin can create a role.
#     Authenticated users cannot create roles.
#     """
#     headers = [('Content-Type', 'application/json'),
#                ('Accept', 'application/json')]
#
#     allowed_user = users['user1']
#     non_allowed_user = users['user2']
#     admin = users['admin']
#
#     r1 = Role.query.filter_by(name=roles_data[0]['name']).one()
#
#     def post_test(access_token, expected_code):
#         with app.test_client() as client:
#             res = client.post(
#                 url_for(
#                     'invenio_accounts_rest.list_roles',
#                     access_token=access_token,
#                 ),
#                 data=json.dumps(
#                     {'name': 'role', 'description': 'desc'}
#                 ),
#                 headers=headers
#             )
#
#         assert res.status_code == expected_code
#
#     db.session.add(ActionUsers.allow(
#         ParameterizedActionNeed(
#             "accounts_create_role",
#             str(r1.id)
#         ),
#         user=allowed_user,
#     ))
#     post_test(None, 401)
#     post_test(allowed_user.allowed_token, 200)
#     post_test(non_allowed_user.allowed_token, 403)
#     post_test(admin.allowed_token, 200)
#     # create access_token without user_write scope for each user and check
#     # that the returned code is 403
#
#
# def test_delete_role(app, create_roles, roles_data):
#     """Test deleting a role."""
#     with app.app_context():
#         with app.test_client() as client:
#             headers = [('Content-Type', 'application/json'),
#                        ('Accept', 'application/json')]
#
#             r1 = Role.query.filter_by(name=roles_data[0]['name']).one()
#
#             res = client.delete(
#                 url_for(
#                     'invenio_accounts_rest.role',
#                     role_id=r1.id
#                 ),
#                 headers=headers
#             )
#             assert res.status_code == 204
#
#             res = client.get(
#                 url_for(
#                     'invenio_accounts_rest.role',
#                     role_id=r1.id
#                 ),
#                 headers=headers
#             )
#             assert res.status_code == 404
#
#


def test_delete_role_permissions(app, users, create_roles, roles_data,
                                 role_permission_factory):
    """Test permissions for deleting a role.

    This is testing the default permission factory.
    Anonymous user cannot delete a role.
    Allowed user and admin can delete a role.
    Authenticated users cannot delete roles.
    """
    headers = [('Content-Type', 'application/json'),
                ('Accept', 'application/json')]

    def delete_test(user, expected_code):
        with app.app_context():
            r1 = Role.query.filter_by(name=roles_data[0]['name']).one()

        with app.test_client() as client:
            access_token = user.allowed_token if user else None

            res = client.delete(
                url_for(
                    'invenio_accounts_rest.role',
                    role_id=r1.id,
                    access_token=access_token,
                ),
                headers=headers
            )

        assert res.status_code == expected_code

    # db.session.add(ActionUsers.allow(
    #     ParameterizedActionNeed(
    #         "accounts_delete_role",
    #         str(r1.id)
    #     ),
    #     user=allowed_user,
    # ))

    with app.app_context():
        delete_test(None, 401)

    with app.app_context():
        # role is still in database as unauthenticated user cannot delete it
        allowed_user = users['user1']
        role_permission_factory['allowed_users']['delete_role'][allowed_user.id] = [roles_data[0].id]

        delete_test(allowed_user, 204)

    with app.app_context():
        # role is no more in database, so user cannot delete it
        with pytest.raises(ValueError):
            allowed_user = users['user1']
            # import ipdb
            # ipdb.set_trace()
            # r1 = Role.query.filter_by(name=roles_data[0]['name']).one()
            role_permission_factory['allowed_users']['delete_role'][allowed_user.id] = [roles_data[0].id]

            delete_test(allowed_user, 204)

    with app.app_context():
        # role is being added to database again, but non-allowed user cannot delete it
        ds = app.extensions['invenio-accounts'].datastore

        non_allowed_user = users['admin']
        readded_role = ds.create_role(roles_data[0])
        db.session.add(readded_role)
        db.session.commit()

        delete_test(non_allowed_user, 403)

    # FIXME the role does not exist anymore
    # delete_test(admin.allowed_token, 204)
    # create access_token without user_write scope for each user and check
    # that the returned code is 403
#
#
# def test_assign_role(app, users, create_roles, roles_data):
#     """Test assigning role to user."""
#     with app.app_context():
#         with app.test_client() as client:
#             headers = [('Content-Type', 'application/json'),
#                        ('Accept', 'application/json')]
#
#             res = client.put(
#                 url_for(
#                     'invenio_accounts_rest.assign_role',
#                     user_id=users['user2'].id,
#                     role_id=users['user1'].roles[0].id
#                 ),
#                 headers=headers
#             )
#             assert res.status_code == 200
#
#             res = client.get(
#                 url_for(
#                     'invenio_accounts_rest.user_roles_list',
#                     user_id=users['user2'].id
#                 ),
#                 headers=headers
#             )
#             response_data = json.loads(res.get_data(as_text=True))
#             assert users['user1'].roles[0].id in map(
#                 lambda x: x['role']['role_id'],
#                 response_data['hits']['hits']
#             )
#
#
# @pytest.yield_fixture()
# def test_assign_role_permissions_mock():
#     with patch.object(
#             AssignRoleResource,
#             'put',
#             side_effect=[
#                 {'data': {}, 'code': 401},
#                 {'data': {}, 'code': 200},
#                 {'data': {}, 'code': 403},
#                 {'data': {}, 'code': 200}
#             ]
#     ):
#         yield
#
#
# def test_assign_role_permissions(app, users,
#                                  test_assign_role_permissions_mock):
#     """Test permissions for assigning a role to a user.
#
#     The call is idempotent (it is expected to succeed even when the user has
#     the role already assigned).
#
#     This is testing the default permission factory.
#     Anonymous user cannot assign a role.
#     Allowed user and admin can assign a role.
#     Authenticated users cannot assign roles.
#     """
#     headers = [('Content-Type', 'application/json'),
#                ('Accept', 'application/json')]
#
#     allowed_user = users['user1']
#     other_user = users['user2']
#     admin = users['admin']
#
#     def put_test(access_token, expected_code):
#         with app.test_client() as client:
#             res = client.put(
#                 url_for(
#                     'invenio_accounts_rest.assign_role',
#                     user_id=other_user.id,
#                     role_id=allowed_user.roles[0].id,
#                     access_token=access_token,
#                 ),
#                 headers=headers
#             )
#
#         assert res.status_code == expected_code
#
#     db.session.add(ActionUsers.allow(
#         ParameterizedActionNeed(
#             "accounts_assign_role",
#             [other_user.id, allowed_user.roles[0].id]
#         ),
#         user=allowed_user,
#     ))
#
#     put_test(None, 401)
#     put_test(allowed_user.allowed_token, 200)
#     put_test(other_user.allowed_token, 403)
#     put_test(admin.allowed_token, 200)
#     # create access_token without user_write scope for each user and check
#     # that the returned code is 403
#
#
# def test_unassign_role(app, users, create_roles, roles_data):
#     """Test unassigning role from user."""
#     with app.app_context():
#         with app.test_client() as client:
#             headers = [('Content-Type', 'application/json'),
#                        ('Accept', 'application/json')]
#
#         role = users['user1'].roles[0]
#
#         res = client.delete(
#             url_for(
#                 'invenio_accounts_rest.unassign_role',
#                 user_id=users['user1'].id,
#                 role_id=role.id,
#             ),
#             headers=headers
#         )
#         assert res.status_code == 204
#
#         res = client.get(
#             url_for(
#                 'invenio_accounts_rest.user_roles_list',
#                 user_id=users['user1'].id
#             ),
#             headers=headers
#         )
#         response_data = json.loads(res.get_data(as_text=True))
#         assert role.id not in map(
#             lambda x: x['role']['role_id'],
#             response_data['hits']['hits']
#         )
#
#
# @pytest.yield_fixture()
# def test_unassign_role_permissions_mock():
#     with patch.object(
#             UnassignRoleResource,
#             'delete',
#             side_effect=[
#                 {'data': {}, 'code': 401},
#                 {'data': {}, 'code': 200},
#                 {'data': {}, 'code': 403},
#                 {'data': {}, 'code': 200}
#             ]
#     ):
#         yield
#
#
# def test_unassign_role_permissions(app, users,
#                                    test_unassign_role_permissions_mock):
#     """Test permissions for unassigning a role from a user.
#
#     The call is idempotent (it is expected to succeed even when the user has
#     the role already unassigned).
#
#     This is testing the default permission factory.
#     Anonymous user cannot unassign a role.
#     Allowed user and admin can unassign a role.
#     Authenticated users cannot unassign roles.
#     """
#     headers = [('Content-Type', 'application/json'),
#                ('Accept', 'application/json')]
#
#     allowed_user = users['user1']
#     other_user = users['user2']
#     admin = users['admin']
#     role = users['user1'].roles[0]
#
#     def delete_test(access_token, expected_code):
#         with app.test_client() as client:
#             res = client.delete(
#                 url_for(
#                     'invenio_accounts_rest.unassign_role',
#                     user_id=allowed_user.id,
#                     role_id=allowed_user.roles[0].id,
#                     access_token=access_token,
#                 ),
#                 headers=headers
#             )
#
#         assert res.status_code == expected_code
#
#     db.session.add(ActionUsers.allow(
#         ParameterizedActionNeed(
#             "accounts_unassign_role",
#             [other_user.id, allowed_user.roles[0].id]
#         ),
#         user=allowed_user,
#     ))
#
#     delete_test(None, 401)
#     delete_test(allowed_user.allowed_token, 200)
#     delete_test(other_user.allowed_token, 403)
#     delete_test(admin.allowed_token, 200)
#     # create access_token without user_write scope for each user and check
#     # that the returned code is 403
#
#
# def test_update_role(app, create_roles, roles_data):
#     """Test updating a role."""
#     with app.app_context():
#         with app.test_client() as client:
#             headers = [('Content-Type', 'application/json'),
#                        ('Accept', 'application/json-patch+json')]
#
#             r1 = Role.query.filter_by(name=roles_data[0]['name']).one()
#
#             res = client.patch(
#                 url_for(
#                     'invenio_accounts_rest.role',
#                     role_id=r1.id
#                 ),
#                 data=json.dumps([{
#                     'op': 'replace',
#                     'path': '/name',
#                     'value': 'new_name'
#                 }]),
#                 headers=headers
#             )
#
#             assert res.status_code == 200
#             response_data = json.loads(res.get_data(as_text=True))
#             assert response_data == {
#                 'links': {
#                     'self': url_for(
#                         'invenio_accounts_rest.role',
#                         role_id=r1.id,
#                         _external=True
#                     )
#                 },
#                 'role': {
#                     'description': 'desc1',
#                     'name': 'new_name',
#                     'role_id': r1.id
#                 }
#             }
#
#

def test_update_role_permissions(app, users, create_roles, roles_data,
                                 role_permission_factory):
    """Test permissions for updating a role.

    This is testing the default permission factory.
    Anonymous user cannot update a role.
    Allowed user and admin can update a role.
    Authenticated users cannot update roles.
    """
    headers = [('Content-Type', 'application/json'),
                ('Accept', 'application/json-patch+json')]

    def patch_test(user, expected_code):
        with app.app_context():
            r1 = Role.query.filter_by(name=roles_data[0]['name']).one()

        with app.test_client() as client:
            # import ipdb
            # ipdb.set_trace()
            access_token = user.allowed_token if user else None

            res = client.patch(
                url_for(
                    'invenio_accounts_rest.role',
                    role_id=r1.id,
                    access_token=access_token,
                ),
                data=json.dumps([{
                    'op': 'replace',
                    'path': '/name',
                    'value': 'new_name'
                }]),
                headers=headers
            )

        assert res.status_code == expected_code

    # with app.app_context():
    #     r1 = Role.query.filter_by(name=roles_data[0]['name']).one()
    #     allowed_user = users['user1']

        # db.session.add(ActionUsers.allow(
        #     ParameterizedActionNeed(
        #         "accounts_update_role",
        #         str(r1.id)
        #     ),
        #     user=allowed_user,
        # ))

    with app.app_context():
        patch_test(None, 401)

    with app.app_context():
        other_user = users['user2']
        patch_test(other_user, 403)

    with app.app_context():
        allowed_user = users['user1']
        r1 = Role.query.filter_by(name=roles_data[0]['name']).one()

        role_permission_factory['allowed_users']['update_role'][allowed_user.id] = [r1.id]
        # import ipdb
        # ipdb.set_trace()
        # import ipdb
        # ipdb.set_trace()
        patch_test(allowed_user, 200)


    # with app.app_context():
    #     admin = users['admin']
    #     patch_test(admin, 200)
    # create access_token without user_write scope for each user and check
    # that the returned code is 403
#
#
# def test_get_user_roles(app, users, create_roles, roles_data):
#     """Test listing all users roles."""
#     with app.app_context():
#         with app.test_client() as client:
#             headers = [('Content-Type', 'application/json'),
#                        ('Accept', 'application/json')]
#
#             u1 = User.query.filter_by(id=users['user1'].id).one()
#
#             res = client.get(
#                 url_for(
#                     'invenio_accounts_rest.user_roles_list',
#                     user_id=u1.id
#                 ),
#                 headers=headers
#             )
#
#             assert res.status_code == 200
#             response_data = json.loads(res.get_data(as_text=True))
#             # import ipdb
#             # ipdb.set_trace()
#             assert response_data == {
#                 'hits': {
#                     'hits': [{
#                         'links': {
#                             'self': url_for(
#                                 'invenio_accounts_rest.role',
#                                 role_id=users['user1'].roles[0].id,
#                                 _external=True
#                             )
#                         },
#                         'role': {
#                             'description': users['user1'].roles[0].description,
#                             'name': users['user1'].roles[0].name,
#                             'role_id': users['user1'].roles[0].id
#                         },
#                     }],
#                 },
#                 'total': 1,
#             }
#
#
# @pytest.yield_fixture()
# def test_get_user_roles_permissions_mock():
#     return_value = {
#         'roles': [{
#             'name': 'name',
#             'description': 'description'
#         }]
#     }
#
#     with patch.object(
#             UserRolesListResource,
#             'get',
#             side_effect=[
#                 {'data': return_value, 'code': 401},
#                 {'data': return_value, 'code': 200},
#                 {'data': return_value, 'code': 403},
#                 {'data': return_value, 'code': 200}
#             ]
#     ):
#         yield
#
#
# def test_get_user_roles_permissions(app, users,
#                                     test_get_user_roles_permissions_mock):
#     """Test permissions for getting an user's roles.
#
#     This is testing the default permission factory.
#     Anonymous user cannot get a role.
#     Allowed user and admin can get a role.
#     Authenticated users cannot get role.
#     """
#     headers = [('Content-Type', 'application/json'),
#                ('Accept', 'application/json')]
#
#     allowed_user = users['user1']
#     other_user = users['user2']
#     admin = users['admin']
#
#     def get_test(access_token, expected_code):
#         with app.test_client() as client:
#             res = client.get(
#                 url_for(
#                     'invenio_accounts_rest.user_roles_list',
#                     user_id=allowed_user.id,
#                     access_token=access_token,
#                 ),
#                 headers=headers
#             )
#
#         assert res.status_code == expected_code
#
#     db.session.add(ActionUsers.allow(
#         ParameterizedActionNeed(
#             "accounts_get_user_roles",
#             str(allowed_user.id)
#         ),
#         user=allowed_user,
#     ))
#
#     get_test(None, 401)
#     get_test(allowed_user.allowed_token, 200)
#     get_test(other_user.allowed_token, 403)
#     get_test(admin.allowed_token, 200)
#     # create access_token without user_write scope for each user and check
#     # that the returned code is 403
#
#
# def test_get_user_properties(app, users, create_roles, roles_data):
#     """Test listing all user's properties."""
#     with app.app_context():
#         with app.test_client() as client:
#             headers = [('Content-Type', 'application/json'),
#                        ('Accept', 'application/json')]
#
#             res = client.get(
#                 url_for(
#                     'invenio_accounts_rest.user',
#                     user_id=users['user1'].id
#                 ),
#                 headers=headers
#             )
#
#             assert res.status_code == 200
#             response_data = json.loads(res.get_data(as_text=True))
#             assert response_data == {
#                 'user': {
#                     'user_id': users['user1'].id,
#                     'email': 'user1@inveniosoftware.org',
#                     'active': True,
#                     'profile': {
#                         'full_name': 'full_name',
#                         'username': 'username'
#                     }
#                 },
#                 'links': {
#                     'self': url_for(
#                         'invenio_accounts_rest.user',
#                         user_id=users['user1'].id,
#                         _external=True
#                     )
#                 }
#             }
#
#
# @pytest.yield_fixture()
# def test_get_user_properties_permissions_mock(users):
#     return_value = {
#         'user': {
#             'id': users['user1'].id,
#             'email': 'test_email@email.com',
#             'active': True,
#             'profile': {
#                 'full_name': 'full_name',
#                 'username': 'username'
#             }
#         },
#         'links': {
#             'self': url_for(
#                 'invenio_accounts_rest.user',
#                 user_id=users['user1'].id,
#                 _external=True
#             )
#         }
#     }
#
#     with patch.object(
#             UserAccountResource,
#             'get',
#             side_effect=[
#                 {'data': return_value, 'code': 401},
#                 {'data': return_value, 'code': 200},
#                 {'data': return_value, 'code': 403},
#                 {'data': return_value, 'code': 200},
#                 {'data': return_value, 'code': 200}
#             ]
#     ):
#         yield
#
#
# def test_get_user_properties_permissions(
#         app, users, test_get_user_properties_permissions_mock
# ):
#     """Test permissions for getting a user account's properties.
#
#     This is testing the default permission factory.
#     Anonymous user cannot get user's properties.
#     Allowed user and admin can get user's properties.
#     Authenticated users cannot get user's properties.
#     """
#     headers = [('Content-Type', 'application/json'),
#                ('Accept', 'application/json')]
#
#     allowed_user = users['user1']
#     other_user = users['user2']
#     admin = users['admin']
#
#     def get_test(access_token, expected_code):
#         with app.test_client() as client:
#             res = client.get(
#                 url_for(
#                     'invenio_accounts_rest.user',
#                     user_id=allowed_user.id,
#                     access_token=access_token
#                 ),
#                 headers=headers
#             )
#
#         assert res.status_code == expected_code
#
#     get_test(None, 401)
#     get_test(allowed_user.allowed_token, 200)
#     get_test(other_user.allowed_token, 403)
#     get_test(admin.allowed_token, 200)
#     # create access_token without user_write scope for each user and check
#     # that the returned code is 403
#
#     db.session.add(ActionUsers.allow(
#         ParameterizedActionNeed(
#             "accounts_get_user_properties",
#             str(allowed_user.id)
#         ),
#         user=other_user,
#     ))
#
#     get_test(other_user.allowed_token, 200)
#
#
# def test_modify_user_properties(app, users):
#     """Test modifying user's properties."""
#     with app.app_context():
#         with app.test_client() as client:
#             headers = [('Content-Type', 'application/json'),
#                        ('Accept', 'application/json')]
#
#             res = client.patch(
#                 url_for(
#                     'invenio_accounts_rest.user',
#                     user_id=users['user1'].id
#                 ),
#                 data=json.dumps({
#                     'email': 'other@email.com',
#                     'full_name': 'other_full_name'
#                 }),
#                 headers=headers
#             )
#
#             assert res.status_code == 200
#             response_data = json.loads(res.get_data(as_text=True))
#             assert response_data == {
#                 'user': {
#                     'user_id': users['user1'].id,
#                     'email': 'other@email.com',
#                     'active': True,
#                     'profile': {
#                         'full_name': 'other_full_name',
#                         'username': 'username'
#                     }
#                 },
#                 'links': {
#                     'self': url_for(
#                         'invenio_accounts_rest.user',
#                         user_id=users['user1'].id,
#                         _external=True
#                     )
#                 }
#             }
#
#
# @pytest.yield_fixture()
# def test_modify_user_properties_permissions_mock(users):
#     return_value = {
#         'user': {
#             'id': users['user1'].id,
#             'email': 'other@email.com',
#             'active': True,
#             'profile': {
#                 'full_name': 'full_name'
#             }
#         },
#         'links': {
#             'self': url_for(
#                 'invenio_accounts_rest.user',
#                 user_id=users['user1'].id,
#                 _external=True
#             )
#         }
#     }
#
#     with patch.object(
#             UserAccountResource,
#             'patch',
#             side_effect=[
#                 {'data': return_value, 'code': 401},
#                 {'data': return_value, 'code': 200},
#                 {'data': return_value, 'code': 403},
#                 {'data': return_value, 'code': 200},
#                 {'data': return_value, 'code': 200}
#             ]
#     ):
#         yield
#
#
# def test_modify_user_properties_permissions(
#         app, users, test_modify_user_properties_permissions_mock
# ):
#     """Test permissions for modifying a user account's properties.
#
#     This is testing the default permission factory.
#     Anonymous user cannot modify user's properties.
#     Allowed user and admin can modify user's properties.
#     Authenticated users cannot modify user's properties.
#     """
#     headers = [('Content-Type', 'application/json'),
#                ('Accept', 'application/json')]
#
#     modified_user = users['user1']
#     other_user = users['user2']
#     admin = users['admin']
#
#     def patch_test(access_token, expected_code):
#         with app.test_client() as client:
#             res = client.patch(
#                 url_for(
#                     'invenio_accounts_rest.user',
#                     user_id=modified_user.id,
#                     access_token=access_token,
#                 ),
#                 data=json.dumps({'email': 'other@email.com'}),
#                 headers=headers
#             )
#         assert res.status_code == expected_code
#         response_data = json.loads(res.get_data(as_text=True))
#         assert response_data['user']['active'] is True
#
#     patch_test(None, 401)
#     patch_test(modified_user.allowed_token, 200)
#     patch_test(other_user.allowed_token, 403)
#     patch_test(admin.allowed_token, 200)
#     # create access_token without user_write scope for each user and check
#     # that the returned code is 403
#
#     db.session.add(ActionUsers.allow(
#         ParameterizedActionNeed(
#             "accounts_modify_user_properties",
#             str(modified_user.id)
#         ),
#         user=other_user,
#     ))
#
#     patch_test(other_user.allowed_token, 200)
#
#
# def test_change_user_password(app, users):
#     """Test changing user's password."""
#     with app.app_context():
#         with app.test_client() as client:
#             headers = [('Content-Type', 'application/json'),
#                        ('Accept', 'application/json')]
#
#             res = client.patch(
#                 url_for(
#                     'invenio_accounts_rest.user',
#                     user_id=users['user1'].id
#                 ),
#                 data=json.dumps({
#                     'email': 'other@email.com',
#                     'old_password': 'pass1',
#                     'password': 'other_pass',
#                 }),
#                 headers=headers
#             )
#
#             assert res.status_code == 200
#             response_data = json.loads(res.get_data(as_text=True))
#             # assert users['user1'].password == encrypt_password('other_pass')
#             # import ipdb
#             # ipdb.set_trace()
#             assert verify_password('other_pass', users['user1'].password) is True
#
#
# # def test_list_users(app, users, create_roles, roles_data):
# #     """Test listing all existing users."""
# #     with app.app_context():
# #         with app.test_client() as client:
# #             headers = [('Content-Type', 'application/json'),
# #                       ('Accept', 'application/json')]
#
# #             res = client.get(
# #                 url_for(
# #                     'invenio_accounts_rest.users_list'
# #                 ),
# #                 headers=headers
# #             )
#
# #         assert res.status_code == 200
# #         response_data = json.loads(res.get_data(as_text=True))
# #         assert len(response_data['hits']['hits']) == 4
#
#
# @pytest.yield_fixture()
# def test_list_users_permissions_mock(users):
#     return_value = {
#         'hits': {
#             'total': 2,
#             'hits': [
#                 {
#                     'links': {
#                         'self': url_for(
#                             'invenio_accounts_rest.users_list',
#                             _external=True,
#                             next='2'
#                         )
#                     },
#                     'email': 'user1@inveniosoftware.org',
#                     'active': True,
#                     'id': users['user1'].id
#                 },
#                 {
#                     'links': {
#                         'self': url_for(
#                             'invenio_accounts_rest.users_list',
#                             _external=True,
#                             next='2'
#                         )
#                     },
#                     'email': 'user1@inveniosoftware.org',
#                     'active': True,
#                     'id': users['user2'].id
#                 }
#             ]
#         }
#     }
#
#     with patch.object(
#             UserListResource,
#             'get',
#             side_effect=[
#                 {'data': return_value, 'code': 401},
#                 {'data': return_value, 'code': 200},
#                 {'data': return_value, 'code': 403},
#                 {'data': return_value, 'code': 200}
#             ]
#     ):
#         yield
#
#
# def test_list_users_permissions(app, users,
#                                 test_list_users_permissions_mock):
#     headers = [('Content-Type', 'application/json'),
#                ('Accept', 'application/json')]
#     """Test permissions for listing users.
#
#     This is testing the default permission factory.
#     Anonymous user cannot list users.
#     Allowed user and admin can list users.
#     Authenticated users cannot list users.
#     """
#     allowed_user = users['user1']
#     not_allowed_user = users['user2']
#     admin = users['admin']
#
#     def get_test(access_token, expected_code):
#         with app.test_client() as client:
#             res = client.get(
#                 url_for(
#                     'invenio_accounts_rest.users_list',
#                     access_token=access_token,
#                 ),
#                 headers=headers,
#             )
#
#         assert res.status_code == expected_code
#
#     db.session.add(ActionUsers.allow(
#         ParameterizedActionNeed(
#             "accounts_list_users",
#             None
#         ),
#         user=allowed_user,
#     ))
#
#     get_test(None, 401)
#     get_test(allowed_user.allowed_token, 200)
#     get_test(not_allowed_user.allowed_token, 403)
#     get_test(admin.allowed_token, 200)
#     # create access_token without user_write scope for each user and check
#     # that the returned code is 403
#
#
# # @pytest.yield_fixture()
# # def test_search_user_mock():
# #     with patch.object(
# #         UserListResource,
# #         'get',
# #         side_effect=[
# #             {'data': {}, 'code': 401},
# #             {'data': {}, 'code': 200},
# #             {'data': {}, 'code': 200},
# #             {'data': {}, 'code': 200}
# #         ]
# #     ):
# #         yield
#
#
# def test_user_search(app, users):
#     """Test REST API for circulation specific user search."""
#     user = User.query.all()[0]
#     headers = [('Content-Type', 'application/json'),
#                ('Accept', 'application/json')]
#
#     modified_user = users['user1']
#     other_user = users['user2']
#     admin = users['admin']
#
#     # with app.test_request_context():
#     #     with app.test_client() as client:
#
#     def get_test(query, access_token, expected_code):
#         with app.test_client() as client:
#             url = url_for(
#                 'invenio_accounts_rest.users_list',
#                 q=query,
#                 access_token=access_token
#             )
#             res = client.get(url)
#         # import ipdb
#         # ipdb.set_trace()
#
#         assert res.status_code == expected_code
#
#     # Search while not being authorized
#     get_test(str(user.id + 1), None, 401)
#     # Search for non existing user
#     get_test(str(user.id + 1000), other_user.allowed_token.access_token, 404)
#     # Search for existing user
#     get_test(str(user.id), other_user.allowed_token.access_token, 200)
#     # Search for all
#     get_test(None, other_user.allowed_token.access_token, 200)
#
#             # Search while not being authorized
#             # import ipdb
#             # ipdb.set_trace()
#             # get_test(
#             #     query=user.id + 1,
#             #     access_token='foo',
#             #     expected_code=401
#             # )
#             # url = url_for(
#             #     'invenio_accounts_rest.users_list',
#             #     q=str(user.id + 1),
#             #     access_token='foo'
#             # )
#             # # import ipdb
#             # # ipdb.set_trace()
#             # res = client.get(url)
#
#             # assert res.status_code == 401
#
#             # Search for non existing user
#             # get_test(
#             #     query=user.id + 1,
#             #     access_token=access_token,
#             #     expected_code=200
#             # )
#             # url = url_for(
#             #     'invenio_accounts_rest.users_list',
#             #     q=str(user.id + 1),
#             #     access_token=user.allowed_token
#             # )
#             # res = client.get(url, headers=headers)
#
#             # assert res.status_code == 200
#             # import ipdb
#             # ipdb.set_trace()
#             # response_data = json.loads(res.get_data(as_text=True))
#             # assert len(response_data['hits']['hits']) == 0
#             # assert len(res.data.decode('utf-8')['hits']['hits']) == 0
#             # assert len(json.loads(res.data.decode('utf-8'))) == 0  # FIXME: add
#
#             # Search for existing user
#             # get_test(
#             #     query=user.id,
#             #     access_token=access_token,
#             #     expected_code=200
#             # )
#             # url = url_for(
#             #     'invenio_accounts_rest.users_list',
#             #     q=str(user.id),
#             #     access_token=user.allowed_token
#             # )
#             # res = client.get(url, headers=headers)
#
#             # assert res.status_code == 200
#             # response_data = json.loads(res.get_data(as_text=True))
#             # assert len(response_data['hits']['hits']) == 1
#             # assert len(json.loads(res.data.decode('utf-8'))) == 1  # FIXME: add
#
#             # Search for all
#             # get_test(
#             #     access_token=access_token,
#             #     expected_code=200
#             # )
#             # url = url_for(
#             #     'invenio_accounts_rest.users_list',
#             #     access_token=user.allowed_token
#             # )
#             # res = client.get(url, headers=headers)
#
#             # assert res.status_code == 200
#             # response_data = json.loads(res.get_data(as_text=True))
#             # assert len(response_data['hits']['hits']) == 1
#             # assert len(json.loads(res.data.decode('utf-8'))) == 1  # FIXME: add
#
#
# # def test_search_users(app, users, create_roles, roles_data):
# #     """Test searching users."""
# #     with app.app_context():
# #         with app.test_client() as client:
# #             headers = [('Content-Type', 'application/json'),
# #                       ('Accept', 'application/json')]
#
# #             res = client.get(
# #                 url_for(
# #                     'invenio_accounts_rest.users_list',
# #                 ),
# #                 q=dict(
# #                     active=True,
# #                 ),
# #                 headers=headers
# #             )
# #             assert res.status_code == 200
# #             response_data = json.loads(res.get_data(as_text=True))
# #             assert response_data['hits']['total'] == 3
#
#
# def test_reactivate_user(app, users, create_roles, roles_data):
#     """Test reactivating user."""
#     with app.app_context():
#         with app.test_client() as client:
#             headers = [('Content-Type', 'application/json'),
#                        ('Accept', 'application/json')]
#
#             res = client.patch(
#                 url_for(
#                     'invenio_accounts_rest.user',
#                     user_id=users['inactive'].id,
#                 ),
#                 data=json.dumps({'active': True}),
#                 headers=headers
#             )
#             assert res.status_code == 200
#
#             res = client.get(
#                 url_for(
#                     'invenio_accounts_rest.user',
#                     user_id=users['inactive'].id
#                 ),
#
#                 headers=headers
#             )
#             response_data = json.loads(res.get_data(as_text=True))
#             assert response_data['user']['active'] is True
#
#
# @pytest.yield_fixture()
# def test_reactivate_user_permissions_mock():
#     with patch.object(
#             UserAccountResource,
#             'patch',
#             side_effect=[
#                 {'data': {}, 'code': 401},
#                 {'data': {}, 'code': 200},
#                 {'data': {}, 'code': 403},
#                 {'data': {}, 'code': 200}
#             ]
#     ):
#         yield
#
#
# def test_reactivate_user_permissions(app, users,
#                                      test_reactivate_user_permissions_mock):
#     """Test permissions for reactivating a user.
#
#     This is testing the default permission factory.
#     Anonymous user cannot reactivate user.
#     Allowed user and admin can reactivate user.
#     Authenticated users cannot reactivate user.
#     """
#     headers = [('Content-Type', 'application/json'),
#                ('Accept', 'application/json-patch+json')]
#
#     modified_user = users['user1']
#     other_user = users['user2']
#     admin = users['admin']
#
#     def patch_test(access_token, expected_code):
#         with app.test_client() as client:
#             res = client.patch(
#                 url_for(
#                     'invenio_accounts_rest.user',
#                     user_id=admin.id,
#                     access_token=access_token,
#                 ),
#                 data=json.dumps({'active': True}),
#                 headers=headers
#             )
#
#         assert res.status_code == expected_code
#
#     patch_test(None, 401)
#     patch_test(modified_user.allowed_token, 200)
#     patch_test(other_user.allowed_token, 403)
#     patch_test(admin.allowed_token, 200)
#     # create access_token without user_write scope for each user and check
#     # that the returned code is 403
#
#
# def test_deactivate_user(app, users, create_roles, roles_data):
#     """Test deactivating user."""
#     with app.app_context():
#         with app.test_client() as client:
#             headers = [('Content-Type', 'application/json'),
#                        ('Accept', 'application/json')]
#
#             res = client.patch(
#                 url_for(
#                     'invenio_accounts_rest.user',
#                     user_id=users['user2'].id,
#                 ),
#                 data=json.dumps({'active': False}),
#                 headers=headers
#             )
#
#             assert res.status_code == 200
#
#             headers = [('Content-Type', 'application/json'),
#                        ('Accept', 'application/json')]
#
#             res = client.get(
#                 url_for(
#                     'invenio_accounts_rest.user',
#                     user_id=users['user2'].id
#                 ),
#                 headers=headers
#             )
#
#             response_data = json.loads(res.get_data(as_text=True))
#             assert response_data['user']['active'] is False
#
#
# @pytest.yield_fixture()
# def test_deactivate_user_permissions_mock():
#     with patch.object(
#             UserAccountResource,
#             'patch',
#             side_effect=[
#                 {'data': {}, 'code': 401},
#                 {'data': {}, 'code': 200}
#             ]
#     ):
#         yield
#
#
# def test_deactivate_user_permissions(app, users,
#                                      test_reactivate_user_permissions_mock):
#     """Test permissions for deactivating a user.
#
#     This is testing the default permission factory.
#     Anonymous user cannot deactivate user.
#     Admin can reactivate user.
#     """
#     headers = [('Content-Type', 'application/json'),
#                ('Accept', 'application/json-patch+json')]
#
#     other_user = users['user2']
#     admin = users['admin']
#
#     def patch_test(access_token, expected_code):
#         with app.test_client() as client:
#             res = client.patch(
#                 url_for(
#                     'invenio_accounts_rest.user',
#                     user_id=users['user2'].id
#                 ),
#                 data=json.dumps({'active': False}),
#                 headers=headers
#             )
#
#         assert res.status_code == expected_code
#
#     patch_test(None, 401)
#     patch_test(admin.allowed_token, 200)
#     # create access_token without user_write scope for each user and check
#     # that the returned code is 403
