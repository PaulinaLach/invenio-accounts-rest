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

"""Invenio modules that adds accounts REST API."""

from __future__ import absolute_import, print_function

from collections import deque
from functools import partial, wraps

from flask import Blueprint, abort, jsonify, request, current_app, url_for
from flask_security.changeable import change_user_password, encrypt_password
from flask_security.utils import verify_password
from flask_security.signals import password_changed
from invenio_accounts.models import User, Role
from invenio_accounts_rest.errors import MaxResultWindowRESTError
from invenio_accounts_rest.proxies import current_accounts_rest
from invenio_db import db
from invenio_oauth2server import require_api_auth
from invenio_rest import ContentNegotiatedMethodView
import json
from jsonpatch import apply_patch
from sqlalchemy import String, cast, orm
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.local import LocalProxy
import six

from invenio_accounts_rest.loaders import default_loader_with_profile, \
    default_loader_without_profile

from invenio_accounts_rest.serializers import role_serializer, \
    status_code_serializer, roles_list_serializer, \
    user_serializer, user_with_profile_serializer, \
    users_list_serializer, users_with_profile_list_serializer

blueprint = Blueprint(
    'invenio_accounts_rest',
    __name__,
)

_datastore = LocalProxy(lambda: current_app.extensions['security'].datastore)


# def pass_role(f):
#     """Decorator to retrieve a role."""
#     @wraps(f)
#     def inner(self, role_id, *args, **kwargs):
#         role = Role.query.filter(Role.id == role_id).one_or_none()
#         # import ipdb
#         # ipdb.set_trace()
#         if role is None:
#             abort(404)
#         return f(self, role=role, *args, **kwargs)
#     return inner



def pass_role(f):
    """Decorator to retrieve a role."""
    @wraps(f)
    def inner(self, role_id, *args, **kwargs):
        role = Role.query.filter(Role.id == role_id).one_or_none()
        # import ipdb
        # ipdb.set_trace()
        if role is None:
            abort(404)
        return f(self, role=role, *args, **kwargs)
    return inner




# def verify_role_permission(permission_factory, role):
#     """Check that the current user has the required permissions on role.
#     In case the permission check fails, an Flask abort is launched.
#     If the user was previously logged-in, a HTTP error 403 is returned.
#     Otherwise, is returned a HTTP error 401.
#     :param permission_factory: permission factory used to check permissions.
#     :param record: record whose access is limited.
#     """
#     # Note, cannot be done in one line due overloading of boolean
#     # operations permission object.
#     with current_app.app_context():
#         # import ipdb
#         # ipdb.set_trace()
#         if not permission_factory(role=role).can():
#             from flask_login import current_user
#             # import ipdb
#             # ipdb.set_trace()
#             if not current_user.is_authenticated:
#                 abort(401)
#             abort(403)



def verify_role_permission(permission_factory, role):
    """Check that the current user has the required permissions on role.
    In case the permission check fails, an Flask abort is launched.
    If the user was previously logged-in, a HTTP error 403 is returned.
    Otherwise, is returned a HTTP error 401.
    :param permission_factory: permission factory used to check permissions.
    :param record: record whose access is limited.
    """
    # Note, cannot be done in one line due overloading of boolean
    # operations permission object.
    with current_app.app_context():
        # import ipdb
        # ipdb.set_trace()
        if not permission_factory(role=role).can():
            from flask_login import current_user
            # import ipdb
            # ipdb.set_trace()
            if not current_user.is_authenticated:
                abort(401)
            abort(403)




def need_role_permission(factory_name):
    """Decorator checking that the user has the required permissions on role.
    :param factory_name: name of the factory to retrieve.
    """
    def need_role_permission_builder(f):
        @wraps(f)
        def need_role_permission_decorator(self, role=None, *args,
                                             **kwargs):
            # import ipdb
            # ipdb.set_trace()
            permission_factory = getattr(current_accounts_rest,
                                         factory_name)()

            request._methodview = self

            if permission_factory:
                # import ipdb
                # ipdb.set_trace()
                verify_role_permission(permission_factory, role)
            # import ipdb
            # ipdb.set_trace()
            # role = Role.query.filter(Role.id == role_id).one_or_none()
            return f(self, role=role, *args, **kwargs)
        return need_role_permission_decorator
    return need_role_permission_builder





# def need_role_permission(factory_name):
#     """Decorator checking that the user has the required permissions on role.
#     :param factory_name: name of the factory to retrieve.
#     """
#     def need_role_permission_builder(f):
#         @wraps(f)
#         def need_role_permission_decorator(self, role=None, *args,
#                                              **kwargs):
#             # import ipdb
#             # ipdb.set_trace()
#             permission_factory = getattr(current_accounts_rest,
#                                          factory_name)()

#             request._methodview = self

#             if permission_factory:
#                 # import ipdb
#                 # ipdb.set_trace()
#                 verify_role_permission(permission_factory, role)
#             return f(self, role=role, *args, **kwargs)
#         return need_role_permission_decorator
#     return need_role_permission_builder


# @blueprint.record_once
# def init(state):
#     """Sets the identity loader and saver for the current application."""
#     principal = state.app.extensions['security'].principal
#     principal.identity_loaders = deque([identity_loader_session])
#     principal.identity_savers = deque([identity_saver_session])


# def identity_loader_session():
#     """Load the identity from the session."""
#     import ipdb
#     ipdb.set_trace()
#     pass


# def identity_saver_session(identity):
#     """Save identity to the session."""
#     import ipdb
#     ipdb.set_trace()
#     pass


# class RolesListResource(ContentNegotiatedMethodView):
#     view_name = 'list_roles'
#
#     def __init__(self, max_result_window=None, **kwargs):
#         """Constructor."""
#         super(RolesListResource, self).__init__(
#             method_serializers={
#                 'POST': {
#                     'application/json': role_serializer,
#                 },
#                 'GET': {
#                     'application/json': roles_list_serializer,
#                 }
#             },
#             default_media_type='application/json',
#             **kwargs
#         )
#         self.max_result_window = max_result_window or 10000
#
#     def get(self):
#         """Get a list of all roles."""
#         page = request.values.get('page', 1, type=int)
#         size = request.values.get('size', 10, type=int)
#         if page * size >= self.max_result_window:
#             raise MaxResultWindowRESTError()
#
#         query_string = request.args.get('q')
#         if query_string is not None:
#             roles = [Role.query.filter(
#                 (Role.name.like(query_string))
#             ).all()]
#             if not roles[0]:
#                 abort(404)
#         else:
#             roles = Role.query.all()
#
#         paginated_roles = self.paginate_roles(roles, page, size)
#         result = self.make_response(
#             roles=paginated_roles['hits'],
#             links=paginated_roles['links'],
#             total=len(paginated_roles['hits']),
#             code=200,
#         )
#
#         return result
#
#     def paginate_roles(self, roles, page_number, page_size):
#         """Return paginated list of roles."""
#         result_roles = roles[
#             (page_number - 1) * page_size:page_number * page_size
#         ]
#         endpoint = 'invenio_accounts_rest.list_roles'
#         result_links = dict(self=url_for(endpoint, page=page_number))
#         if page_number > 1:
#             result_links['prev'] = url_for(endpoint, page=page_number - 1)
#
#         if page_size * page_number < len(roles) and \
#                     page_size * page_number < self.max_result_window:
#             result_links['next'] = url_for(endpoint, page=page_number + 1)
#
#         return {
#             'hits': result_roles,
#             'links': result_links,
#         }
#
#     def post(self):
#         """Create a new role."""
#         posted_role = _datastore.create_role(**request.get_json())
#         db.session.commit()
#         return self.make_response(posted_role, 201)


class RoleResource(ContentNegotiatedMethodView):
    view_name = 'role'

    # def __init__(self, get_role_permission_factory=None,
    #              update_role_permission_factory=None,
    #              delete_role_permission_factory=None, **kwargs):
    def __init__(self, **kwargs):
        """Constructor."""
        super(RoleResource, self).__init__(
            method_serializers={
                'GET': {
                    'application/json': role_serializer,
                },
                'DELETE': {
                    'application/json': role_serializer,
                },
                'PATCH': {
                    'application/json-patch+json': role_serializer,
                }
            },
            serializers={
                'application/json': role_serializer
            },
            default_media_type='application/json',
            **kwargs
        )
        # self.get_role_permission_factory = current_app.config.get(
        #     'ACCOUNTS_REST_GET_ROLE_PERMISSION_FACTORY')
        # self.update_role_permission_factory = current_app.config.get(
        #     'ACCOUNTS_REST_UPDATE_ROLE_PERMISSION_FACTORY')
        # self.delete_role_permission_factory = current_app.config.get(
        #     'ACCOUNTS_REST_DELETE_ROLE_PERMISSION_FACTORY')

    @pass_role
    @need_role_permission('read_role_permission_factory')
    def get(self, role):
        """Get a role with a given id."""
        from flask_login import current_user
        # import ipdb
        # ipdb.set_trace()
        return self.make_response(role, 200)

    @pass_role
    @need_role_permission('update_role_permission_factory')
    def patch(self, role):
        """Update a role with a json-patch."""
        # role = Role.query.filter_by(id=role_id).one()
        data = request.get_json(force=True)

        data = apply_patch({'name': role.name}, data, True)
        with db.session.begin_nested():
            for key, value in data.items():
                setattr(role, key, value)
            db.session.merge(role)

        db.session.commit()
        return self.make_response(role, 200)

    @pass_role
    @need_role_permission('delete_role_permission_factory')
    def delete(self, role):
        """Delete a role."""
        role_to_delete_id = role.id
        if Role.query.filter_by(id=role_to_delete_id).one():
            db.session.delete(role)
            db.session.commit()
            return self.make_response(role, 204)
        else:
            raise ValueError(_("Cannot find role."))


# class AssignRoleResource(ContentNegotiatedMethodView):
#     view_name = 'assign_role'
#
#     def __init__(self, **kwargs):
#         """Constructor."""
#         super(AssignRoleResource, self).__init__(
#             serializers={
#                 'application/json': status_code_serializer
#             },
#             default_media_type='application/json',
#             **kwargs
#         )
#
#     def put(self, user_id, role_id):
#         """Assign role to an user."""
#         role = Role.query.filter_by(id=role_id).one()
#         user = User.query.filter_by(id=user_id).one()
#
#         _datastore.add_role_to_user(user, role)
#
#         return self.make_response(200)
#
#
# class UnassignRoleResource(ContentNegotiatedMethodView):
#     view_name = 'unassign_role'
#
#     def __init__(self, **kwargs):
#         """Constructor."""
#         super(UnassignRoleResource, self).__init__(
#             serializers={
#                 'application/json': status_code_serializer
#             },
#             default_media_type='application/json',
#             **kwargs
#         )
#
#     def delete(self, user_id, role_id):
#         """Remove role from a user."""
#         role = Role.query.filter_by(id=role_id).one()
#         user = User.query.filter_by(id=user_id).one()
#
#         _datastore.remove_role_from_user(user, role)
#
#         return self.make_response(204)
#
#
# class UserRolesListResource(ContentNegotiatedMethodView):
#     view_name = 'user_roles_list'
#
#     def __init__(self, max_result_window=None, **kwargs):
#         """Constructor."""
#         super(UserRolesListResource, self).__init__(
#             serializers={
#                 'application/json': roles_list_serializer
#             },
#             default_media_type='application/json',
#             **kwargs
#         )
#         self.max_result_window = max_result_window or 10000
#
#     def get(self, user_id):
#         """Get a list of the user's roles."""
#         page = request.values.get('page', 1, type=int)
#         size = request.values.get('size', 10, type=int)
#         if page * size >= self.max_result_window:
#             raise MaxResultWindowRESTError()
#
#         roles = User.query.filter_by(id=user_id).one().roles
#         query_string = request.args.get('q')
#         if query_string is not None:
#             roles.filter(Role.name.like(query_string))
#             if not roles[0]:
#                 abort(404)
#
#         paginated_roles = self.paginate_roles(user_id, roles, page, size)
#         result = self.make_response(
#             roles=paginated_roles['hits'],
#             links=paginated_roles['links'],
#             total=len(paginated_roles['hits']),
#             code=200,
#         )
#
#         return result
#
#     def paginate_roles(self, user_id, roles, page_number, page_size):
#         """Return paginated list of user's roles."""
#         result_roles = roles[
#             (page_number - 1) * page_size:page_number * page_size
#         ]
#         endpoint = 'invenio_accounts_rest.user_roles_list'
#         result_links = dict(self=url_for(endpoint, user_id=user_id, page=page_number))
#         if page_number > 1:
#             result_links['prev'] = url_for(endpoint, page=page_number - 1)
#
#         if page_size * page_number < len(roles) and \
#                     page_size * page_number < self.max_result_window:
#             result_links['next'] = url_for(endpoint, page=page_number + 1)
#
#         return {
#             'hits': result_roles,
#             'links': result_links,
#         }
#
#
# class UserAccountResource(ContentNegotiatedMethodView):
#     view_name = 'user'
#
#     def __init__(self, **kwargs):
#         """Constructor."""
#         self.loaders = kwargs.get(
#             'loaders',
#             current_app.config.get(
#                 'ACCOUNTS_REST_ACCOUNT_LOADERS', {
#                     'application/json': default_loader_without_profile
#                 } if 'invenio-userprofiles' not in current_app.extensions else {
#                     'application/json': default_loader_with_profile
#                 }
#             )
#         )
#         kwargs.setdefault(
#             'serializers',
#             current_app.config.get(
#                 'ACCOUNTS_REST_ACCOUNT_SERIALIZERS', {
#                     'application/json': user_serializer
#                 } if 'invenio-userprofiles' not in current_app.extensions else {
#                     'application/json': user_with_profile_serializer
#                 }
#             )
#         )
#         kwargs.setdefault('default_media_type', 'application/json')
#         super(UserAccountResource, self).__init__(
#             **kwargs
#         )
#
#     def patch(self, user_id):
#         """Update a user's properties."""
#         content_type = request.headers.get('Content-Type')
#
#         loader = self.loaders.get(content_type)
#         if loader is None:
#             abort(406)
#         data = loader()
#
#         user = User.query.filter_by(id=user_id).one()
#         if data.get('password'):
#             old_password = data['old_password']
#             updated_password = data['password']
#             if verify_password(data['old_password'], user.password):
#                 user.password = encrypt_password(updated_password)
#                 db.session.commit()
#                 _datastore.put(user)
#                 password_changed.send(current_app._get_current_object(),user=user)
#             del data['password']
#             del data['old_password']
#         user = User(id=user_id, **data)
#
#         user = db.session.merge(user)
#         db.session.commit()
#         return self.make_response(user, 200)
#
#     def get(self, user_id):
#         """Get a user's properties."""
#         user = _datastore.get_user(user_id)
#         db.session.commit()
#         return self.make_response(user, 200)
#
#
# class UserListResource(ContentNegotiatedMethodView):
#     view_name = 'users_list'
#
#     def __init__(self, max_result_window=None, **kwargs):
#         """Constructor."""
#         kwargs.setdefault(
#             'serializers',
#             current_app.config.get(
#                 'ACCOUNTS_REST_ACCOUNT_SERIALIZERS', {
#                     'application/json': users_list_serializer
#                 } if 'invenio-userprofiles' not in current_app.extensions else {
#                     'application/json': users_with_profile_list_serializer
#                 }
#             )
#         )
#         kwargs.setdefault('default_media_type', 'application/json')
#         super(UserListResource, self).__init__(
#             **kwargs
#         )
#         self.max_result_window = max_result_window or 10000
#
#     @require_api_auth()
#     def get(self):
#         """Get accounts/users/?q=."""
#         page = request.values.get('page', 1, type=int)
#         size = request.values.get('size', 10, type=int)
#         if page * size >= self.max_result_window:
#             raise MaxResultWindowRESTError()
#
#         query_string = request.args.get('q')
#         if query_string is not None:
#             # users = [User.query.filter(
#             #     (User.email.like(query_string)) |
#             #     (cast(User.id, String) == query_string)
#             # ).all()]
#             users = User.query.filter(
#                 (User.email.like(query_string)) |
#                 (cast(User.id, String) == query_string)
#             ).all()
#             # if not users[0]:
#             if not users:
#                 abort(404)
#             # return users
#         else:
#             # import ipdb
#             # ipdb.set_trace()
#             # return self.make_response(User.query.all())
#             # users = [User.query.all()]
#             users = User.query.all()
#
#         paginated_users = self.paginate_users(users, page, size)
#         # import ipdb
#         # ipdb.set_trace()
#         result = self.make_response(
#             users=paginated_users['hits'],
#             links=paginated_users['links'],
#             total=len(paginated_users['hits']),
#             code=200,
#         )
#
#     def paginate_users(self, users, page_number, page_size):
#         """Return paginated list of user's roles."""
#         result_users = users[
#                        (page_number - 1) * page_size:page_number * page_size
#                        ]
#         endpoint = 'invenio_accounts_rest.users_list'
#         result_links = dict(self=url_for(endpoint, page=page_number))
#         if page_number > 1:
#             result_links['prev'] = url_for(endpoint, page=page_number - 1)
#
#         if page_size * page_number < len(users) and \
#                     page_size * page_number < self.max_result_window:
#             result_links['next'] = url_for(endpoint, page=page_number + 1)
#
#         return {
#             'hits': result_users,
#             'links': result_links,
#         }


# blueprint.add_url_rule(
#     '/roles',
#     view_func=RolesListResource.as_view(
#         RolesListResource.view_name
#     )
# )

blueprint.add_url_rule(
    '/roles/<string:role_id>',
    view_func=RoleResource.as_view(
        RoleResource.view_name
    )
)


# blueprint.add_url_rule(
#     '/roles/<string:role_id>/users/<string:user_id>',
#     view_func=AssignRoleResource.as_view(
#         AssignRoleResource.view_name
#     )
# )
#
#
# blueprint.add_url_rule(
#     '/roles/<string:role_id>/users/<string:user_id>',
#     view_func=UnassignRoleResource.as_view(
#         UnassignRoleResource.view_name
#     )
# )
#
#
# blueprint.add_url_rule(
#     '/users/<string:user_id>/roles',
#     view_func=UserRolesListResource.as_view(
#         UserRolesListResource.view_name
#     )
# )
#
#
# blueprint.add_url_rule(
#     '/users/<string:user_id>',
#     view_func=UserAccountResource.as_view(
#         UserAccountResource.view_name
#     )
# )
#
#
# blueprint.add_url_rule(
#     '/users',
#     view_func=UserListResource.as_view(
#         UserListResource.view_name
#     )
# )

