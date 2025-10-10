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
                "instance_name": "irods_rule_engine_plugin-event_handler-collection_modified-instance",
                "plugin_name": "irods_rule_engine_plugin-event_handler-collection_modified",
                'plugin_specific_configuration': {
                    "policies_to_invoke" : [
                        {
                            "conditional" : {
                                "logical_path" : "\\/tempZone.*"
                            },
                            "active_policy_clauses" : ["post"],
                            "events" : ["create", "register", "remove"],
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
                "instance_name": "irods_rule_engine_plugin-event_handler-collection_modified-instance",
                "plugin_name": "irods_rule_engine_plugin-event_handler-collection_modified",
                'plugin_specific_configuration': {
                    "policies_to_invoke" : [
                        {
                            "conditional" : {
                                "logical_path" : "\\/badZone.*"
                            },
                            "active_policy_clauses" : ["post"],
                            "events" : ["create", "register", "remove"],
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

class TestEventHandlerCollectionModified(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(TestEventHandlerCollectionModified, self).setUp()

    def tearDown(self):
        super(TestEventHandlerCollectionModified, self).tearDown()

    def test_event_handler_collection_mkdir(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                with event_handler_configured():
                    collection_name = '/tempZone/home/rods/test_collection'
                    admin_session.assert_icommand('imkdir ' + collection_name)
                    admin_session.assert_icommand('imeta ls -C ' + collection_name, 'STDOUT_SINGLELINE', 'CREATE')
            finally:
                admin_session.assert_icommand('irm -rf ' + collection_name)
                admin_session.assert_icommand('iadmin rum')

    def test_event_handler_collection_mkdir_fail_conditional(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                with event_handler_configured_fail_conditional():
                    collection_name = '/tempZone/home/rods/test_collection'
                    admin_session.assert_icommand('imkdir ' + collection_name)
                    admin_session.assert_icommand('imeta ls -C ' + collection_name, 'STDOUT_SINGLELINE', 'None')
            finally:
                admin_session.assert_icommand('irm -rf ' + collection_name)
                admin_session.assert_icommand('iadmin rum')

    def test_event_handler_collection_rmdir(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                with event_handler_configured():
                    collection_name = '/tempZone/home/rods/test_collection'
                    admin_session.assert_icommand('imkdir ' + collection_name)
                    admin_session.assert_icommand('irmdir -f ' + collection_name)
                    admin_session.assert_icommand('imeta ls -C /tempZone/home/rods', 'STDOUT_SINGLELINE', 'REMOVE')
            finally:
                admin_session.assert_icommand('imeta rm -C /tempZone/home/rods irods_policy_testing_policy REMOVE')
                admin_session.assert_icommand('iadmin rum')

    def test_event_handler_collection_register(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                with event_handler_configured():
                    local_dir = os.path.join(os.getcwd(), 'test_event_handler_collection_register_dir')
                    if not os.path.isdir(local_dir):
                        lib.make_large_local_tmp_dir(local_dir, 10, 100)
                    collection_name = '/tempZone/home/rods/test_collection'
                    admin_session.assert_icommand('ireg -r ' + local_dir + ' ' + collection_name)
                    admin_session.assert_icommand('imeta ls -C ' + collection_name, 'STDOUT_SINGLELINE', 'REGISTER')
            finally:
                shutil.rmtree(local_dir)
                admin_session.assert_icommand('irm -rf ' + collection_name)
                admin_session.assert_icommand('iadmin rum')
