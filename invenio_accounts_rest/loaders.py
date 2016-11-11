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

"""."""

from flask import request


def default_loader_with_profile():
    """Default data loader when Invenio Userprofiles is installed."""
    data = request.get_json(force=True)
    for key in data:
        if key not in [
            'email',
            'active',
            'full_name',
            'username',
            'password',
            'old_password'
        ]:
            raise NameError()

    # import ipdb
    # ipdb.set_trace()
    data['profile'] = {}
    if 'full_name' in data:
        data['profile']['full_name'] = data['full_name']
        del data['full_name']
    if 'username' in data:
        data['profile']['username'] = data['username']
        del data['username']

    return data


def default_loader_without_profile():
    """Default data loader when Invenio Userprofiles is not installed."""
    data = request.get_json(force=True)
    for key in data:
        if key not in ['email', 'active', 'password', 'old_password']:
            raise NameError()
    return data
