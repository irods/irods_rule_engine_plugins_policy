import os
import sys
import shutil
import contextlib
import tempfile
import json
import os.path

from time import sleep

if sys.version_info >= (2, 7):
    import unittest
else:
    import unittest2 as unittest

from ..configuration import IrodsConfig
from ..controller import IrodsController
from .resource_suite import ResourceBase
from ..test.command import assert_command
from . import session
from .. import test
from .. import paths
from .. import lib
import ustrings

@contextlib.contextmanager
def data_retention_configured(arg=None):
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
                        {    "pre_or_post_invocation" : ["post"],
                            "events" : ["replication"],
                            "policy"    : "irods_policy_data_retention",
                            "configuration" : {
                            }
                        }
                    ]
                }
            }
        )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
           {
                "instance_name": "irods_rule_engine_plugin-policy_engine-data_retention-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-data_retention",
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
def data_retention_with_whitelist_configured(arg=None):
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
                        {    "pre_or_post_invocation" : ["post"],
                            "events" : ["replication"],
                            "policy"    : "irods_policy_data_retention",
                            "configuration" : {
                                "resource_white_list" : ["demoResc", "AnotherResc"]
                            }
                        }
                    ]
                }
            }
        )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
           {
                "instance_name": "irods_rule_engine_plugin-policy_engine-data_retention-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-data_retention",
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
def data_retention_alternate_attributes_configured(arg=None):
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
                        {    "pre_or_post_invocation" : ["post"],
                            "events" : ["replication"],
                            "policy"    : "irods_policy_data_retention",
                            "configuration" : {
                                "log_errors" : "true",
                                "attribute"  : "event_handler_attribute"
                            }
                        }
                    ]
                }
            }
        )

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
           {
                "instance_name": "irods_rule_engine_plugin-policy_engine-data_retention-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-data_retention",
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

class TestPolicyEngineDataRetention(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(TestPolicyEngineDataRetention, self).setUp()

    def tearDown(self):
        super(TestPolicyEngineDataRetention, self).tearDown()

    def test_direct_invocation_with_trim_single(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)

                rule = """
{
"policy" : "irods_policy_execute_rule",
"payload" : {
    "policy_to_invoke" : "irods_policy_data_retention",
    "parameters" : {
        "user_name" : "rods",
        "object_path" : "/tempZone/home/rods/test_put_file",
        "source_resource" : "demoResc"
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

                with data_retention_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file])
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)

    def test_direct_invocation_with_remove_all(self):
        with session.make_session_for_existing_admin() as admin_session:
            filename = 'test_put_file'
            lib.create_local_testfile(filename)
            admin_session.assert_icommand('iput ' + filename)
            admin_session.assert_icommand('irepl -R AnotherResc ' + filename)

            rule = """
{
"policy" : "irods_policy_execute_rule",
"payload" : {
    "policy_to_invoke" : "irods_policy_data_retention",
    "parameters" : {
        "user_name" : "rods",
        "object_path" : "/tempZone/home/rods/test_put_file"
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

            with data_retention_configured():
                admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file])
                admin_session.assert_icommand('ils -l ' + filename, 'STDERR_SINGLELINE', 'does not exist')



    def test_direct_invocation_with_preserve_replicas(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::retention::preserve_replicas true')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)

                rule = """
{
"policy" : "irods_policy_execute_rule",
"payload" : {
    "policy_to_invoke" : "irods_policy_data_retention",
    "parameters" : {
        "user_name" : "rods",
        "object_path" : "/tempZone/home/rods/test_put_file",
        "source_resource" : "AnotherResc"
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

                with data_retention_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file])
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation_with_trim_single(self):
        with session.make_session_for_existing_admin() as admin_session:
            with data_retention_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
                    admin_session.assert_icommand('irepl -R TestResc ' + filename)
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'TestResc')
                    admin_session.assert_icommand('irepl -R demoResc ' + filename)
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'demoResc')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation_with_whitelist(self):
        with session.make_session_for_existing_admin() as admin_session:
            with data_retention_with_whitelist_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation_with_trim_single_preserve_replica(self):
        with session.make_session_for_existing_admin() as admin_session:
            admin_session.assert_icommand('imeta set -R AnotherResc irods::retention::preserve_replicas true')
            with data_retention_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput -R AnotherResc ' + filename)
                    admin_session.assert_icommand('irepl -R demoResc ' + filename)
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_query_invocation_with_trim_single(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)

                rule = """
{
    "policy" : "irods_policy_execute_rule",
    "payload" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND RESC_NAME = 'demoResc'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policy_to_invoke" : "irods_policy_data_retention",
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

                with data_retention_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file])
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)


    def test_query_invocation_with_remove_all(self):
        with session.make_session_for_existing_admin() as admin_session:
            filename = 'test_put_file'
            lib.create_local_testfile(filename)
            admin_session.assert_icommand('iput ' + filename)
            admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
            admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)

            rule = """
{
"policy" : "irods_policy_execute_rule",
"payload" : {
    "policy_to_invoke" : "irods_policy_query_processor",
    "parameters" : {
          "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file'",
          "query_limit" : 1,
          "query_type" : "general",
          "number_of_threads" : 1,
          "policy_to_invoke" : "irods_policy_data_retention",
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

            with data_retention_configured():
                admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file])
                admin_session.assert_icommand('ils -l ' + filename, 'STDERR_SINGLELINE', 'does not exist')



    def test_query_invocation_with_invalid_parameters(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)

                rule = """
{
"policy" : "irods_policy_execute_rule",
"payload" : {
    "policy_to_invoke" : "irods_policy_query_processor",
    "parameters" : {
          "query_string" : "SELECT COLL_NAME, DATA_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file'",
          "query_limit" : 1,
          "query_type" : "general",
          "number_of_threads" : 1,
          "policy_to_invoke" : "irods_policy_data_retention",
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

                with data_retention_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'invalid')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)





























    def test_direct_invocation_with_preserve_replicas_alternate_attribute(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc direct_invocation_attribute true')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)

                rule = """
{
"policy" : "irods_policy_execute_rule",
"payload" : {
    "policy_to_invoke" : "irods_policy_data_retention",
    "parameters" : {
        "user_name" : "rods",
        "object_path" : "/tempZone/home/rods/test_put_file",
        "source_resource" : "AnotherResc"
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

                with data_retention_alternate_attributes_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file])
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation_with_trim_single_preserve_replica_alternate_attribute(self):
        with session.make_session_for_existing_admin() as admin_session:
            admin_session.assert_icommand('imeta set -R AnotherResc event_handler_attribute true')
            with data_retention_alternate_attributes_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput -R AnotherResc ' + filename)
                    admin_session.assert_icommand('irepl -R demoResc ' + filename)
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)




