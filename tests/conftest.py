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


"""Pytest configuration."""

from __future__ import absolute_import, print_function

import os
import six
import tempfile
from collections import namedtuple

import pytest
from flask import Flask
from flask_babelex import Babel
from flask_breadcrumbs import Breadcrumbs
from flask_mail import Mail
from flask_menu import Menu
from flask_security import url_for_security
from flask_security.utils import encrypt_password
from invenio_access import InvenioAccess
from invenio_access.models import ActionUsers
from invenio_access.permissions import superuser_access
from invenio_accounts import InvenioAccounts
from invenio_accounts.models import Role
from invenio_db import db as db_
from invenio_db import InvenioDB
from invenio_oauth2server import InvenioOAuth2Server, current_oauth2server, \
    InvenioOAuth2ServerREST
from invenio_oauth2server.models import Token
from invenio_userprofiles import InvenioUserProfiles
from six import iteritems
from sqlalchemy_utils.functions import create_database, database_exists
from werkzeug.local import LocalProxy
from invenio_accounts.models import User

from invenio_accounts_rest import InvenioAccountsREST


@pytest.fixture()
def role_permission_factory():
    """."""
    # will be initialized later as user_id: [role ids]
    allowed_users = {
        'read_role': {},
        'update_role': {},
        'delete_role': {}
    }

    def role_permission_factory_sub(action):
        def permission_factory(role):
            # role = kwargs['role']
            from flask_login import current_user
            # import ipdb
            # ipdb.set_trace()
            return (current_user.is_authenticated and
                    current_user.id in allowed_users[action] and
                    role.id in allowed_users[action][current_user.id])
        return lambda role: type('permission_factory', (), {
            'can': lambda: permission_factory(role)
        })

    return {
        'read_role': role_permission_factory_sub('read_role'),
        'update_role': role_permission_factory_sub('update_role'),
        'delete_role': role_permission_factory_sub('delete_role'),
        'allowed_users': allowed_users,
    }

# users['user1'], users['admin']

@pytest.yield_fixture()
# def app(role_permission_factory):
def app(role_permission_factory):
    """Flask application fixture."""
    instance_path = tempfile.mkdtemp()
    app = Flask(__name__, instance_path=instance_path)
    InvenioAccess(app)
    InvenioAccounts(app)
    InvenioAccountsREST(app)
    InvenioOAuth2Server(app)
    InvenioOAuth2ServerREST(app)
    InvenioDB(app)
    InvenioUserProfiles(app)
    Babel(app)
    Mail(app)
    Menu(app)
    Breadcrumbs(app)

    app.config.update(
        ACCOUNTS_REST_READ_ROLE_PERMISSION_FACTORY=
            role_permission_factory['read_role'],
        ACCOUNTS_REST_UPDATE_ROLE_PERMISSION_FACTORY=
            role_permission_factory['update_role'],
        ACCOUNTS_REST_DELETE_ROLE_PERMISSION_FACTORY=
            role_permission_factory['delete_role'],
        OAUTH2SERVER_CLIENT_ID_SALT_LEN=40,
        OAUTH2SERVER_CLIENT_SECRET_SALT_LEN=60,
        OAUTH2SERVER_TOKEN_PERSONAL_SALT_LEN=60,
        SECRET_KEY='changeme',
        TESTING=True,
        SERVER_NAME='localhost',
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            'SQLALCHEMY_DATABASE_URI', 'sqlite:///test.db'),
        SECURITY_SEND_PASSWORD_CHANGE_EMAIL=False
    )
    from invenio_oauth2server.views.server import blueprint

    with app.app_context():
        db_.create_all()
    yield app
    with app.app_context():
        db_.drop_all()


@pytest.yield_fixture()
def db(app):
    """Setup database."""
    with app.app_context():
        db_.init_app(app)
        if not database_exists(str(db_.engine.url)):
            create_database(str(db_.engine.url))
        db_.create_all()
    yield db_
    with app.app_context():
        db_.session.remove()
        db_.drop_all()


@pytest.fixture()
def users_data():
    """User data fixture."""
    return {
        'user1': dict(
            id=47,
            email='user1@inveniosoftware.org',
            password='pass1',
            active=True,
            profile={
                'user_id': 47,
                'full_name': 'full_name',
                'username': 'username'
            }
        ),
        'user2': dict(
            id=48,
            email='user2@inveniosoftware.org',
            password='pass1',
            active=True,
        ),
        'inactive': dict(
            id=49,
            email='inactive@inveniosoftware.org',
            password='pass1',
            active=False
        ),
    }


@pytest.fixture()
def roles_data():
    _roles_data = [
        dict(name='role1', description='desc1'),
        dict(name='role2', description='desc2'),
    ]
    return _roles_data


@pytest.fixture()
def users(app, db, roles_data, users_data, create_roles):
    """Create test users."""
    ds = app.extensions['invenio-accounts'].datastore
    result = {}

    with app.app_context():
        with db.session.begin_nested():

            for user_key, user_data in iteritems(users_data):
                user_data['password'] = encrypt_password(user_data['password'])
                user = ds.create_user(**user_data)
                result[user_key] = user

            r1 = Role.query.filter_by(name=roles_data[0]['name']).one()
            result['user1'].roles.append(r1)

            result['admin'] = ds.create_user(**{
                "id": 50,
                "email": 'admin@inveniosoftware.org',
                "password": 'pass1',
                "active": True
            })

            db.session.add(ActionUsers.allow(
                superuser_access,
                user=result['admin'],
            ))

            for user in result.values():
                scopes = current_oauth2server.scope_choices()
                db.session.add(user)

                user.allowed_token = Token.create_personal(
                    name='allowed_token',
                    user_id=user.id,
                    scopes=[s[0] for s in scopes]
                ).access_token

            user_ref = namedtuple('UserRef', 'id, model, allowed_token')

            result_user = {
                name: user_ref(
                    id=user.id,
                    model=lambda: User.query.filter(User.id == user.id).one(),
                    allowed_token=user.allowed_token,
                ) for name, user in six.iteritems(result)
            }
        db.session.commit()
    return result_user


@pytest.yield_fixture()
def create_roles(app, db, roles_data):
    """Create test roles."""

