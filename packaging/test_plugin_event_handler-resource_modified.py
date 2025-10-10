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

    irods_config = IrodsConfig()
    irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

    irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
            {
                "instance_name": "irods_rule_engine_plugin-event_handler-resource_modified-instance",
                "plugin_name": "irods_rule_engine_plugin-event_handler-resource_modified",
                'plugin_specific_configuration': {
                    "policies_to_invoke" : [
                        {
                            "conditional" : {
                                "source_resource" : "policy_comp_resc"
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


    try:
        with lib.file_backed_up(filename):
            irods_config.commit(irods_config.server_config, irods_config.server_config_path)
            IrodsController().reload_configuration()
            yield
    finally:
        IrodsController().reload_configuration()

@contextlib.contextmanager
def event_handler_configured_fail_conditional(arg=None):
    filename = paths.server_config_path()

    irods_config = IrodsConfig()
    irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

    irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
            {
                "instance_name": "irods_rule_engine_plugin-event_handler-resource_modified-instance",
                "plugin_name": "irods_rule_engine_plugin-event_handler-resource_modified",
                'plugin_specific_configuration': {
                    "policies_to_invoke" : [
                        {
                            "conditional" : {
                                "source_resource" : "mumbleresc"
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


    try:
        with lib.file_backed_up(filename):
            irods_config.commit(irods_config.server_config, irods_config.server_config_path)
            IrodsController().reload_configuration()
            yield
    finally:
        IrodsController().reload_configuration()

class TestEventHandlerResourceModified(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(TestEventHandlerResourceModified, self).setUp()

    def tearDown(self):
        super(TestEventHandlerResourceModified, self).tearDown()

    def test_event_handler_resource_create(self):
        with session.make_session_for_existing_admin() as admin_session:
            resource_name = 'policy_comp_resc'
            try:
                with event_handler_configured():
                    admin_session.assert_icommand("iadmin mkresc %s unixfilesystem %s:/tmp/irods/test_%s" %
                             (resource_name, lib.get_hostname(), resource_name), 'STDOUT_SINGLELINE', "Creating")
                    admin_session.assert_icommand('imeta ls -R ' + resource_name, 'STDOUT_SINGLELINE', 'CREATE')
            finally:
                admin_session.assert_icommand('iadmin rmresc ' + resource_name)
                admin_session.assert_icommand('iadmin rum')

    def test_event_handler_resource_create_fail_conditional(self):
        with session.make_session_for_existing_admin() as admin_session:
            resource_name = 'policy_comp_resc'
            try:
                with event_handler_configured_fail_conditional():
                    admin_session.assert_icommand("iadmin mkresc %s unixfilesystem %s:/tmp/irods/test_%s" %
                             (resource_name, lib.get_hostname(), resource_name), 'STDOUT_SINGLELINE', "Creating")
                    admin_session.assert_icommand('imeta ls -R ' + resource_name, 'STDOUT_SINGLELINE', 'None')
            finally:
                admin_session.assert_icommand('iadmin rmresc ' + resource_name)
                admin_session.assert_icommand('iadmin rum')

    def test_event_handler_resource_modify(self):
        with session.make_session_for_existing_admin() as admin_session:
            resource_name = 'policy_comp_resc'
            admin_session.assert_icommand("iadmin mkresc %s unixfilesystem %s:/tmp/irods/test_%s" %
                     (resource_name, lib.get_hostname(), resource_name), 'STDOUT_SINGLELINE', "Creating")
            try:
                with event_handler_configured():
                    admin_session.assert_icommand('iadmin modresc ' + resource_name + ' status delighted')
                    admin_session.assert_icommand('imeta ls -R ' + resource_name, 'STDOUT_SINGLELINE', 'MODIFY')
            finally:
                admin_session.assert_icommand('iadmin rmresc ' + resource_name)
                admin_session.assert_icommand('iadmin rum')

    def test_event_handler_resource_remove(self):
        with session.make_session_for_existing_admin() as admin_session:
            resource_name = 'policy_comp_resc'
            admin_session.assert_icommand("iadmin mkresc %s unixfilesystem %s:/tmp/irods/test_%s" %
                     (resource_name, lib.get_hostname(), resource_name), 'STDOUT_SINGLELINE', "Creating")
            try:
                with event_handler_configured():
                    admin_session.assert_icommand('iadmin rmresc ' + resource_name)
                    admin_session.assert_icommand('imeta ls -R demoResc', 'STDOUT_SINGLELINE', 'REMOVE')
            finally:
                admin_session.assert_icommand('imeta rm -R demoResc irods_policy_testing_policy REMOVE')
                admin_session.assert_icommand('iadmin rum')

