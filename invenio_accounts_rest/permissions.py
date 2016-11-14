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

"""Example permissions for AccountsREST."""


from functools import partial

from invenio_access.permissions import DynamicPermission, \
    ParameterizedActionNeed


CommunityReadActionNeed = partial(ParameterizedActionNeed, 'communities-read')
"""Action need for reading a community."""

communities_read_all = CommunityReadActionNeed(None)
"""Read all communities action need."""

CommunityCreateActionNeed = partial(
    ParameterizedActionNeed, 'communities-create')
"""Action need for creating a community."""

communities_create_all = CommunityCreateActionNeed(None)
"""Create all communities action need."""

CommunityUpdateActionNeed = partial(
    ParameterizedActionNeed, 'communities-update')
"""Action need for updating a community."""

communities_update_all = CommunityUpdateActionNeed(None)
"""Update all communities action need."""

CommunityDeleteActionNeed = partial(
    ParameterizedActionNeed, 'communities-delete')
"""Action need for deleting a community."""

communities_delete_all = CommunityDeleteActionNeed(None)
"""Delete all communities action need."""

communities_create_all_permission = DynamicPermission(communities_create_all)


def read_permission_factory(community):
    """Factory for creating read permissions for communities."""
    return DynamicPermission(CommunityReadActionNeed(str(community.id)))


def update_permission_factory(community):
    """Factory for creating update permissions for communities."""
    return DynamicPermission(CommunityUpdateActionNeed(str(community.id)))


def delete_permission_factory(community):
    """Factory for creating delete permissions for communities."""
    return DynamicPermission(CommunityDeleteActionNeed(str(community.id)))
