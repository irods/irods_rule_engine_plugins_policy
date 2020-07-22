
import sys

import contextlib
import tempfile





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
def access_time_configured(arg=None):
    filename = paths.server_config_path()
    with lib.file_backed_up(filename):
        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['rule_engine_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
            {
                "instance_name": "irods_rule_engine_plugin-event_handler-data_object_modified-instance",
                "plugin_name": "irods_rule_engine_plugin-event_handler-data_object_modified",
                "plugin_specific_configuration": {
                    "policies_to_invoke" : [
                        {   "active_policy_clauses" : ["post"],
                            "events" : ["put", "get", "create", "read", "write", "rename", "registration", "replication"],
                            "policy"    : "irods_policy_access_time",
                            "configuration" : {
                            }
                        }
                    ]
                }
            }
        )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
           {
                "instance_name": "irods_rule_engine_plugin-policy_engine-access_time-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-access_time",
                "plugin_specific_configuration": {
                    "log_errors" : "true"
                }
           }
        )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
           {
                "instance_name": "irods_rule_engine_plugin-policy_engine-query_processor-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-query_processor",
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
def access_time_alternate_attributes_configured(arg=None):
    filename = paths.server_config_path()
    with lib.file_backed_up(filename):
        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['rule_engine_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
            {
                "instance_name": "irods_rule_engine_plugin-event_handler-data_object_modified-instance",
                "plugin_name": "irods_rule_engine_plugin-event_handler-data_object_modified",
                "plugin_specific_configuration": {
                    "policies_to_invoke" : [
                        {   "active_policy_clauses" : ["post"],
                            "events" : ["put", "get", "create", "read", "write", "rename", "registration", "replication"],
                            "policy"    : "irods_policy_access_time",
                            "configuration" : {
                                "attribute"  : "event_handler_attribute"
                            }
                        }
                    ]
                }
            }
        )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
           {
                "instance_name": "irods_rule_engine_plugin-policy_engine-access_time-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-access_time",
                "plugin_specific_configuration": {
                    "log_errors" : "true",
                    "attribute"  : "access_time_attribute"
                }
           }
        )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
           {
                "instance_name": "irods_rule_engine_plugin-policy_engine-query_processor-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-query_processor",
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

class TestPolicyEngineAccessTime(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(TestPolicyEngineAccessTime, self).setUp()

    def tearDown(self):
        super(TestPolicyEngineAccessTime, self).tearDown()

    def test_direct_invocation(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'None')

                rule = """
{
    "policy" : "irods_policy_execute_rule",
    "payload" : {
        "policy_to_invoke" : "irods_policy_access_time",
        "parameters" : {
            "user_name" : "rods",
            "logical_path" : "/tempZone/home/rods/test_put_file"
        },
        "configuration" : {
        }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with access_time_configured():
                    admin_session.assert_icommand(['irule', '-F', rule_file])
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'irods::access_time')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation(self):
        with session.make_session_for_existing_admin() as admin_session:
            with access_time_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'irods::access_time')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_query_invocation(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)
                admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'None')

                rule = """
{
    "policy" : "irods_policy_execute_rule",
    "payload" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file'",
              "query_limit" : 10,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policy_to_invoke" : "irods_policy_access_time",
              "configuration" : {
              }
         }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with access_time_configured():
                    admin_session.assert_icommand(['irule', '-F', rule_file])
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'irods::access_time')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_direct_invocation_alternate_attribute(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'None')

                rule = """
{
    "policy" : "irods_policy_execute_rule",
    "payload" : {
        "policy_to_invoke" : "irods_policy_access_time",
        "parameters" : {
            "user_name" : "rods",
            "logical_path" : "/tempZone/home/rods/test_put_file"
        },
        "configuration" : {
        }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with access_time_alternate_attributes_configured():
                    admin_session.assert_icommand(['irule', '-F', rule_file])
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'access_time_attribute')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)

    def test_direct_invocation_alternate_attribute_calling_configuration(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'None')

                rule = """
{
    "policy" : "irods_policy_execute_rule",
    "payload" : {
        "policy_to_invoke" : "irods_policy_access_time",
        "parameters" : {
            "user_name" : "rods",
            "logical_path" : "/tempZone/home/rods/test_put_file"
        },
        "configuration" : {
            "attribute" : "direct_invocation_attribute"
        }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with access_time_alternate_attributes_configured():
                    admin_session.assert_icommand(['irule', '-F', rule_file])
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'direct_invocation_attribute')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)


    def test_event_handler_invocation_alternate_attribute(self):
        with session.make_session_for_existing_admin() as admin_session:
            with access_time_alternate_attributes_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'event_handler_attribute')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_query_invocation_alternate_attribute(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)
                admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'None')

                rule = """
{
    "policy" : "irods_policy_execute_rule",
    "payload" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file'",
              "query_limit" : 10,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policy_to_invoke" : "irods_policy_access_time",
              "configuration" : {
                  "attribute" : "query_processor_attribute"
              }
         }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with access_time_alternate_attributes_configured():
                    admin_session.assert_icommand(['irule', '-F', rule_file])
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'query_processor_attribute')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)

