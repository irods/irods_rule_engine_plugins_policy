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
def query_processor_configured(arg=None):
    filename = paths.server_config_path()
    with lib.file_backed_up(filename):
        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['rule_engine_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
           {
                "instance_name": "irods_rule_engine_plugin-policy_engine-testing_policy-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-testing_policy",
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
    "policy" : "irods_policy_execute_rule",
    "payload" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policy_to_invoke" : "irods_policy_testing_policy",
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

                with query_processor_configured():
                    admin_session.assert_icommand(['irule', '-F', rule_file])
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
    "policy" : "irods_policy_execute_rule",
    "payload" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
            "query_string" : "SELECT COLL_NAME, DATA_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file'",
            "query_limit" : 1,
            "query_type" : "general",
            "number_of_threads" : 1,
            "policy_to_invoke" : "irods_policy_query_processor",
            "parameters" : {
                "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '{0}' AND DATA_NAME = '{1}'",
                "query_limit" : 1,
                "query_type" : "general",
                "number_of_threads" : 1,
                "policy_to_invoke" : "irods_policy_testing_policy",
                "configuration" : {
                }
            }
        }
    }
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with query_processor_configured():
                    admin_session.assert_icommand(['irule', '-F', rule_file])
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'irods_policy_testing_policy')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)
                admin_session.assert_icommand('iadmin rum')
