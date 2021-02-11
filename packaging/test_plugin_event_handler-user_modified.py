import os
import sys

import contextlib
import os.path
import shutil



if sys.version_info >= (2, 7):
    import unittest
else:
    import unittest2 as unittest

from ..configuration import IrodsConfig
from ..controller import IrodsController
from .resource_suite import ResourceBase

from . import session

from .. import paths
from .. import lib


@contextlib.contextmanager
def event_handler_configured(arg=None):
    filename = paths.server_config_path()
    with lib.file_backed_up(filename):
        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['rule_engine_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
            {
                "instance_name": "irods_rule_engine_plugin-event_handler-user_modified-instance",
                "plugin_name": "irods_rule_engine_plugin-event_handler-user_modified",
                'plugin_specific_configuration': {
                    "policies_to_invoke" : [
                        {
                            "conditional" : {
                                "user_name" : "eve"
                            },
                            "active_policy_clauses" : ["post"],
                            "events" : ["create", "modify", "remove"],
                            "policy_to_invoke"    : "irods_policy_testing_policy",
                            "configuration" : {
                            }
                        }
                    ]
                }
            }
        )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
           {
                "instance_name": "irods_rule_engine_plugin-policy_engine-testing_policy-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-testing_policy",
                "plugin_specific_configuration": {
                    "log_errors" : "true"
                }
           }
        )

        irods_config.commit(irods_config.server_config, irods_config.server_config_path)

        IrodsController().restart()

        try:
            yield
        finally:
            pass

@contextlib.contextmanager
def event_handler_configured_fail_conditional(arg=None):
    filename = paths.server_config_path()
    with lib.file_backed_up(filename):
        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['rule_engine_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
            {
                "instance_name": "irods_rule_engine_plugin-event_handler-user_modified-instance",
                "plugin_name": "irods_rule_engine_plugin-event_handler-user_modified",
                'plugin_specific_configuration': {
                    "policies_to_invoke" : [
                        {
                            "conditional" : {
                                "user_name" : "noteve"
                            },
                            "active_policy_clauses" : ["post"],
                            "events" : ["create", "modify", "remove"],
                            "policy_to_invoke"    : "irods_policy_testing_policy",
                            "configuration" : {
                            }
                        }
                    ]
                }
            }
        )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
           {
                "instance_name": "irods_rule_engine_plugin-policy_engine-testing_policy-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-testing_policy",
                "plugin_specific_configuration": {
                    "log_errors" : "true"
                }
           }
        )

        irods_config.commit(irods_config.server_config, irods_config.server_config_path)

        IrodsController().restart()

        try:
            yield
        finally:
            pass

class TestEventHandlerUserModified(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(TestEventHandlerUserModified, self).setUp()

    def tearDown(self):
        super(TestEventHandlerUserModified, self).tearDown()

    def test_event_handler_user_create(self):
        with session.make_session_for_existing_admin() as admin_session:
            user_name = 'eve'
            try:
                with event_handler_configured():
                    admin_session.assert_icommand('iadmin mkuser ' + user_name + ' rodsuser')
                    admin_session.assert_icommand('imeta ls -u ' + user_name, 'STDOUT_SINGLELINE', 'CREATE')
            finally:
                admin_session.assert_icommand('iadmin rmuser ' + user_name)
                admin_session.assert_icommand('iadmin rum')

    def test_event_handler_user_create_fail_conditional(self):
        with session.make_session_for_existing_admin() as admin_session:
            user_name = 'eve'
            try:
                with event_handler_configured_fail_conditional():
                    admin_session.assert_icommand('iadmin mkuser ' + user_name + ' rodsuser')
                    admin_session.assert_icommand('imeta ls -u ' + user_name, 'STDOUT_SINGLELINE', 'None')
            finally:
                admin_session.assert_icommand('iadmin rmuser ' + user_name)
                admin_session.assert_icommand('iadmin rum')

    def test_event_handler_user_modify(self):
        with session.make_session_for_existing_admin() as admin_session:
            user_name = 'eve'
            admin_session.assert_icommand('iadmin mkuser ' + user_name + ' rodsuser')
            try:
                with event_handler_configured():
                    admin_session.assert_icommand('iadmin moduser ' + user_name + ' password apass')
                    admin_session.assert_icommand('imeta ls -u ' + user_name, 'STDOUT_SINGLELINE', 'MODIFY')
            finally:
                admin_session.assert_icommand('iadmin rmuser ' + user_name)
                admin_session.assert_icommand('iadmin rum')

    def test_event_handler_user_remove(self):
        with session.make_session_for_existing_admin() as admin_session:
            user_name = 'eve'
            admin_session.assert_icommand('iadmin mkuser ' + user_name + ' rodsuser')
            try:
                with event_handler_configured():
                    admin_session.assert_icommand('iadmin rmuser ' + user_name)
                    admin_session.assert_icommand('imeta ls -u rods', 'STDOUT_SINGLELINE', 'REMOVE')
            finally:
                admin_session.assert_icommand('imeta rm -u rods irods_policy_testing_policy REMOVE')
                admin_session.assert_icommand('iadmin rum')

