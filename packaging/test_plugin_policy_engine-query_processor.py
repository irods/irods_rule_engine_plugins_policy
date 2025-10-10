
import sys

import contextlib
import tempfile



from time import sleep

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
def query_processor_configured(arg=None):
    filename = paths.server_config_path()

    irods_config = IrodsConfig()
    irods_config.server_config['advanced_settings']['delay_server_sleep_time_in_seconds'] = 1

    irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
            {
                "instance_name": "irods_rule_engine_plugin-event_handler-data_object_modified-instance",
                "plugin_name": "irods_rule_engine_plugin-event_handler-data_object_modified",
                "plugin_specific_configuration": {
                    "policies_to_invoke" : [
                        {   "active_policy_clauses" : ["post"],
                            "events" : ["put", "get", "create", "read", "write", "rename", "registration", "replication"],
                            "policy_to_invoke"    : "irods_policy_access_time",
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

    irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
           {
                "instance_name": "irods_rule_engine_plugin-policy_engine-access_time-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-access_time",
                "plugin_specific_configuration": {
                }
           }
        )

    irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
           {
                "instance_name": "irods_rule_engine_plugin-policy_engine-data_verification-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-data_verification",
                "plugin_specific_configuration": {
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


class TestPolicyEngineQueryProcessor(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(TestPolicyEngineQueryProcessor, self).setUp()

    def tearDown(self):
        super(TestPolicyEngineQueryProcessor, self).tearDown()

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
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_testing_policy",
                      "configuration" : {
                      }
                  }
              ]
         }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with query_processor_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'irods_policy_testing_policy')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)
                admin_session.assert_icommand('iadmin rum')

    def test_query_invocation_fail(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)
                admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'None')

                # verification which fails on a replica existing on AnotherResc
                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "stop_on_error" : "true",
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_data_verification",
                      "parameters" : {
                          "source_resource" : "AnotherResc"
                      },
                      "configuration" : {
                      }
                  },
                  {
                      "policy_to_invoke" : "irods_policy_testing_policy",
                      "configuration" : {
                      }
                  }
              ]
         }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with query_processor_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file])
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'None')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)
                admin_session.assert_icommand('iadmin rum')

    def test_query_invocation_lifetime(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                with query_processor_configured():
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'irods::access_time')
                    sleep(10)
                    rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "lifetime" : 5,
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND META_DATA_ATTR_NAME = 'irods::access_time' AND META_DATA_ATTR_VALUE < 'IRODS_TOKEN_LIFETIME'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_testing_policy",
                      "configuration" : {
                      }
                  }
              ]
         }
    }
}
INPUT null
OUTPUT ruleExecOut
"""

                    rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                    with open(rule_file, 'w') as f:
                        f.write(rule)

                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'irods_policy_testing_policy')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)
                admin_session.assert_icommand('iadmin rum')

    def test_query_invocation_lifetime_with_substitution(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                with query_processor_configured():
                    admin_session.assert_icommand('imeta set -R demoResc irods::testing::time 4')
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'irods::access_time')
                    sleep(10)
                    rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "source_resource" : "demoResc",
              "lifetime" : "IRODS_TOKEN_QUERY_SUBSTITUTION_END_TOKEN(SELECT META_RESC_ATTR_VALUE WHERE META_RESC_ATTR_NAME = 'irods::testing::time' AND RESC_NAME = 'IRODS_TOKEN_SOURCE_RESOURCE')",
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND META_DATA_ATTR_NAME = 'irods::access_time' AND META_DATA_ATTR_VALUE < 'IRODS_TOKEN_LIFETIME'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_testing_policy",
                      "configuration" : {
                      }
                  }
              ]
         }
    }
}
INPUT null
OUTPUT ruleExecOut
"""

                    rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                    with open(rule_file, 'w') as f:
                        f.write(rule)

                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'irods_policy_testing_policy')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)
                admin_session.assert_icommand('imeta rm -R demoResc irods::testing::time 4')
                admin_session.assert_icommand('iadmin rum')


    def test_query_invocation_with_default(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)
                admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'None')

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'incorrect_file_name'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "default_results_when_no_rows_found" : [["rods", "/tempZone/home/rods", "test_put_file", "demoResc"]],
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_testing_policy",
                      "configuration" : {
                      }
                  }
              ]
         }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with query_processor_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'irods_policy_testing_policy')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)
                admin_session.assert_icommand('iadmin rum')


    def test_query_to_query_invocation(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)
                admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'None')

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
            "query_string" : "SELECT COLL_NAME, DATA_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file'",
            "query_limit" : 1,
            "query_type" : "general",
            "number_of_threads" : 1,
            "policies_to_invoke" : [
                {
                    "policy_to_invoke" : "irods_policy_query_processor",
                    "parameters" : {
                        "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '{0}' AND DATA_NAME = '{1}'",
                        "query_limit" : 1,
                        "query_type" : "general",
                        "number_of_threads" : 1,
                        "policies_to_invoke" : [
                            {
                                "policy_to_invoke" : "irods_policy_testing_policy",
                                "configuration" : {
                                }
                            }
                        ]
                    }
                }
            ]
        }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with query_processor_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'irods_policy_testing_policy')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)
                admin_session.assert_icommand('iadmin rum')
