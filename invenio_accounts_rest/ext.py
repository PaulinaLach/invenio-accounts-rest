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

from flask import current_app
from werkzeug.utils import cached_property, import_string

from . import config
from .config import ACCOUNTS_REST_READ_ROLE_PERMISSION_FACTORY, \
    ACCOUNTS_REST_UPDATE_ROLE_PERMISSION_FACTORY, \
    ACCOUNTS_REST_DELETE_ROLE_PERMISSION_FACTORY
from .utils import load_or_import_from_config
from .views import blueprint


# class _AccountsRESTState(object):
#     """Accounts REST state."""
#
#     def __init__(self, app):
#         """Initialize state."""
#         self.app = app
#
#     # @cached_property
#     # def loaders(self):
#     #     """Load default read permission factory."""
#     #     return load_or_import_from_config(
#     #         'RECORDS_REST_DEFAULT_LOADERS', app=self.app
#     #     )
#
#     @cached_property
#     def get_role_permission_factory(self):
#         """Load default create permission factory."""
#         return load_or_import_from_config(
#             'ACCOUNTS_REST_DEFAULT_GET_ROLE_PERMISSION_FACTORY', app=self.app
#         )
#
#     @cached_property
#     def update_role_permission_factory(self):
#         """Load default update role permission factory."""
#         return load_or_import_from_config(
#             'ACCOUNTS_REST_DEFAULT_UPDATE_ROLE_PERMISSION_FACTORY', app=self.app
#         )
#
#     @cached_property
#     def delete_role_permission_factory(self):
#         """Load default delete permission factory."""
#         return load_or_import_from_config(
#             'ACCOUNTS_REST_DEFAULT_DELETE_ROLE_PERMISSION_FACTORY', app=self.app
#         )
#
#     def reset_permission_factories(self):
#         """Remove cached permission factories."""
#         for key in ('get_role', 'update_role', 'delete_role'):
#             full_key = '{0}_permission_factory'.format(key)
#             if full_key in self.__dict__:
#                 del self.__dict__[full_key]


class InvenioAccountsREST(object):
    """Invenio-Accounts-REST extension."""

    def __init__(self, app=None):
        """Extension initialization."""
        if app:
            self.init_app(app)

    def init_app(self, app):
        """Flask application initialization."""
        self.init_config(app)
        app.register_blueprint(blueprint)
        # app.extensions['invenio-accounts-rest'] = _AccountsRESTState(app)
        app.extensions['invenio-accounts-rest'] = self

    def read_role_permission_factory(self, app=None, **kwargs):
        """."""
        app = app or current_app
        # imp = app.config.get('ACCOUNTS_REST_GET_ROLE_PERMISSION_FACTORY')
        # import ipdb
        # ipdb.set_trace()
        return app.config.get('ACCOUNTS_REST_READ_ROLE_PERMISSION_FACTORY')
        # import_string(imp)

    def update_role_permission_factory(self, app=None, **kwargs):
        """."""
        app = app or current_app
        # imp = app.config.get('ACCOUNTS_REST_GET_ROLE_PERMISSION_FACTORY')
        # import ipdb
        # ipdb.set_trace()
        return app.config.get('ACCOUNTS_REST_UPDATE_ROLE_PERMISSION_FACTORY')
        # import_string(imp)

    def delete_role_permission_factory(self, app=None, **kwargs):
        """."""
        app = app or current_app
        # imp = app.config.get('ACCOUNTS_REST_GET_ROLE_PERMISSION_FACTORY')
        # import ipdb
        # ipdb.set_trace()
        return app.config.get('ACCOUNTS_REST_DELETE_ROLE_PERMISSION_FACTORY')
        # import_string(imp)

    # def init_config(self, app):
    #     """Initialize configuration."""
    #     # TODO import config

    def init_config(self, app):
        """Initialize configuration."""
        # Set up API endpoints for records.
        for k in dir(config):
            if k.startswith('ACCOUNTS_REST_'):
                app.config.setdefault(k, getattr(config, k))

        # # Resolve the Elasticsearch error handlers
        # handlers = app.config['RECORDS_REST_ELASTICSEARCH_ERROR_HANDLERS']
        # for k, v in handlers.items():
        #     handlers[k] = obj_or_import_string(v)
