
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
def data_replication_configured(arg=None):
    filename = paths.server_config_path()
    with lib.file_backed_up(filename):
        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['rule_engine_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
           {
                "instance_name": "irods_rule_engine_plugin-policy_engine-data_replication-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-data_replication",
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
def data_replication_with_event_handler_configured(arg=None):
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
                            "events" : ["put", "get", "create", "read", "write", "rename", "registration"],
                            "policy"    : "irods_policy_data_replication",
                            "configuration" : {
                                "destination_resource" : "AnotherResc"
                            }
                        }
                    ]
                }
            }
        )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
           {
                "instance_name": "irods_rule_engine_plugin-policy_engine-data_replication-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-data_replication",
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
def data_replication_with_event_handler_metadata_configured(arg=None):
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
                            "events" : ["put", "get", "create", "read", "write", "rename", "registration"],
                            "policy"    : "irods_policy_data_replication",
                            "configuration" : {
                                "destination_resource" : "AnotherResc"
                            }
                        }
                    ]
                }
            }
        )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
           {
                "instance_name": "irods_rule_engine_plugin-policy_engine-data_replication-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-data_replication",
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
def data_replication_alternate_attributes_configured(arg=None):
    filename = paths.server_config_path()
    with lib.file_backed_up(filename):
        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['rule_engine_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
           {
                "instance_name": "irods_rule_engine_plugin-policy_engine-data_replication-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-data_replication",
                "plugin_specific_configuration": {
                    "log_errors" : "true",
                    "attribute"  : "data_replication_attribute"
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
def data_replication_alternate_attributes_with_event_handler_configured(arg=None):
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
                            "events" : ["put", "get", "create", "read", "write", "rename", "registration"],
                            "policy"    : "irods_policy_data_replication",
                            "configuration" : {
                                "attribute"  : "event_handler_attribute",
                                "destination_resource" : "AnotherResc"
                            }
                        }
                    ]
                }
            }
        )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
           {
                "instance_name": "irods_rule_engine_plugin-policy_engine-data_replication-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-data_replication",
                "plugin_specific_configuration": {
                    "log_errors" : "true",
                    "attribute"  : "data_replication_attribute"
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


class TestPolicyEngineDataReplication(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(TestPolicyEngineDataReplication, self).setUp()

    def tearDown(self):
        super(TestPolicyEngineDataReplication, self).tearDown()



    def test_direct_invocation(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)

                rule = """
{
    "policy" : "irods_policy_execute_rule",
    "payload" : {
        "policy_to_invoke" : "irods_policy_data_replication",
        "parameters" : {
            "user_name" : "rods",
            "logical_path" : "/tempZone/home/rods/test_put_file",
            "source_resource" : "demoResc",
            "destination_resource" : "AnotherResc"
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

                with data_replication_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file])
                    admin_session.assert_icommand('ils -l '+filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_direct_invocation_source_to_destination_map(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)

                rule = """
{
    "policy" : "irods_policy_execute_rule",
    "payload" : {
        "policy_to_invoke" : "irods_policy_data_replication",
        "parameters" : {
            "user_name" : "rods",
            "logical_path" : "/tempZone/home/rods/test_put_file",
            "source_resource" : "demoResc"
        },
        "configuration" : {
            "source_to_destination_map" : {
                "demoResc" : ["TestResc", "AnotherResc"]
            }
        }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with data_replication_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file])
                    admin_session.assert_icommand('ils -l '+filename, 'STDOUT_SINGLELINE', 'AnotherResc')
                    admin_session.assert_icommand('ils -l '+filename, 'STDOUT_SINGLELINE', 'TestResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation(self):
        with session.make_session_for_existing_admin() as admin_session:
            with data_replication_with_event_handler_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
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
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND RESC_NAME = 'demoResc'",
              "query_limit" : 10,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policy_to_invoke" : "irods_policy_data_replication",
              "configuration" : {
                  "destination_resource" : "AnotherResc"
              }
         }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with data_replication_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file])
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_direct_invocation_alternate_attribute(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)

                rule = """
{
    "policy" : "irods_policy_execute_rule",
    "payload" : {
        "policy_to_invoke" : "irods_policy_data_replication",
        "parameters" : {
            "user_name" : "rods",
            "logical_path" : "/tempZone/home/rods/test_put_file",
            "source_resource" : "demoResc",
            "destination_resource" : "AnotherResc"
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

                with data_replication_alternate_attributes_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file])
                    admin_session.assert_icommand('ils -l '+filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation_alternate_attribute(self):
        with session.make_session_for_existing_admin() as admin_session:
            with data_replication_alternate_attributes_with_event_handler_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('ils -l '+filename, 'STDOUT_SINGLELINE', 'AnotherResc')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_query_invocation_alternate_attribute(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)

                rule = """
{
    "policy" : "irods_policy_execute_rule",
    "payload" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND RESC_NAME = 'demoResc'",
              "query_limit" : 10,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policy_to_invoke" : "irods_policy_data_replication",
              "configuration" : {
                  "attribute" : "query_processor_attribute",
                  "destination_resource" : "AnotherResc"
              }
         }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with data_replication_alternate_attributes_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file])
                    admin_session.assert_icommand('ils -l '+filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)

