
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
def data_verification_configured(arg=None):
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
                            "events" : ["replication"],
                            "policy_to_invoke"    : "irods_policy_data_verification",
                            "configuration" : {
                            }
                        }
                    ]
                }
            }
        )

    irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
           {
                "instance_name": "irods_rule_engine_plugin-policy_engine-data_verification-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-data_verification",
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


    try:
        with lib.file_backed_up(filename):
            irods_config.commit(irods_config.server_config, irods_config.server_config_path)
            IrodsController().reload_configuration()
            yield
    finally:
        IrodsController().reload_configuration()


@contextlib.contextmanager
def data_verification_alternate_attributes_configured(arg=None):
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
                            "events" : ["replication"],
                            "policy_to_invoke"    : "irods_policy_data_verification",
                            "configuration" : {
                                "log_errors" : "true",
                                "attribute"  : "event_handler_attribute",
                            }
                        }
                    ]
                }
            }
        )

    irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
           {
                "instance_name": "irods_rule_engine_plugin-policy_engine-data_verification-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-data_verification",
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


    try:
        with lib.file_backed_up(filename):
            irods_config.commit(irods_config.server_config, irods_config.server_config_path)
            IrodsController().reload_configuration()
            yield
    finally:
        IrodsController().reload_configuration()

class TestPolicyEngineDataVerification(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(TestPolicyEngineDataVerification, self).setUp()

    def tearDown(self):
        super(TestPolicyEngineDataVerification, self).tearDown()

    def test_direct_invocation_verify_catalog(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type catalog')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)

                rule = """
{
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_data_verification",
    "parameters" : {
        "user_name" : "rods",
        "logical_path" : "/tempZone/home/rods/test_put_file",
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

                with data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)


# TODO :: add iadmin modrepl for Fail Test
    def test_direct_invocation_verify_catalog_fail(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type catalog')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)

                rule = """
{
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_data_verification",
    "parameters" : {
        "user_name" : "rods",
        "logical_path" : "/tempZone/home/rods/test_put_file",
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

                with data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_direct_invocation_verify_filesystem(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type filesystem')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)

                rule = """
{
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_data_verification",
    "parameters" : {
        "user_name" : "rods",
        "logical_path" : "/tempZone/home/rods/test_put_file",
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

                with data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_direct_invocation_verify_filesystem_fail(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type filesystem')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
                admin_session.assert_icommand('ils -L ' + filename, 'STDOUT_SINGLELINE', filename)

                rule = """
{
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_data_verification",
    "parameters" : {
        "user_name" : "rods",
        "logical_path" : "/tempZone/home/rods/test_put_file",
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

                # truncate file in vault path to force a failure
                with open('/tmp/irods/AnotherResc/home/rods/test_put_file', 'w') as f:
                    f.truncate(5)

                with data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'failed')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_direct_invocation_verify_checksum(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type checksum')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)

                rule = """
{
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_data_verification",
    "parameters" : {
        "user_name" : "rods",
        "logical_path" : "/tempZone/home/rods/test_put_file",
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

                with data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_direct_invocation_verify_checksum_fail(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type filesystem')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
                admin_session.assert_icommand('ils -L ' + filename, 'STDOUT_SINGLELINE', filename)

                rule = """
{
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_data_verification",
    "parameters" : {
        "user_name" : "rods",
        "logical_path" : "/tempZone/home/rods/test_put_file",
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

                # truncate file in vault path to force a failure
                with open('/tmp/irods/AnotherResc/home/rods/test_put_file', 'w') as f:
                    f.truncate(5)

                with data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'failed')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation_verify_catalog(self):
        with session.make_session_for_existing_admin() as admin_session:
            with data_verification_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type catalog')
                    admin_session.assert_icommand('irepl -R AnotherResc ' + filename, 'STDOUT_SINGLELINE', 'usage')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)


# TODO :: add iadmin modrepl for Fail Test
    def test_event_handler_invocation_verify_catalog_fail(self):
        with session.make_session_for_existing_admin() as admin_session:
            with data_verification_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type catalog')
                    admin_session.assert_icommand('irepl -R AnotherResc ' + filename, 'STDOUT_SINGLELINE', 'usage')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation_verify_filesystem(self):
        with session.make_session_for_existing_admin() as admin_session:
            with data_verification_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type filesystem')
                    admin_session.assert_icommand('irepl -R AnotherResc ' + filename, 'STDOUT_SINGLELINE', 'usage')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



# TODO :: Add MungeFS for Fail Test
    def test_event_handler_invocation_verify_filesystem_fail(self):
        with session.make_session_for_existing_admin() as admin_session:
            with data_verification_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type filesystem')
                    admin_session.assert_icommand('irepl -R AnotherResc ' + filename, 'STDOUT_SINGLELINE', 'usage')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation_verify_checksum(self):
        with session.make_session_for_existing_admin() as admin_session:
            with data_verification_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type checksum')
                    admin_session.assert_icommand('irepl -R AnotherResc ' + filename, 'STDOUT_SINGLELINE', 'usage')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



# TODO :: Add MungeFS for Fail Test
    def test_event_handler_invocation_verify_checksum_fail(self):
        with session.make_session_for_existing_admin() as admin_session:
            with data_verification_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type checksum')
                    admin_session.assert_icommand('irepl -R AnotherResc ' + filename, 'STDOUT_SINGLELINE', 'usage')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_query_invocation_verify_catalog(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type catalog')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND RESC_NAME = 'AnotherResc'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_data_verification",
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

                with data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_query_invocation_verify_catalog_missing_source_resource(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type catalog')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND RESC_NAME = 'AnotherResc'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_data_verification",
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

                with data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_query_invocation_verify_filesystem(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type filesystem')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND RESC_NAME = 'AnotherResc'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_data_verification",
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

                with data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_query_invocation_verify_filesystem_fail(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type filesystem')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)

                # truncate file in vault path to force a failure
                with open('/tmp/irods/AnotherResc/home/rods/test_put_file', 'w') as f:
                    f.truncate(5)

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND RESC_NAME = 'AnotherResc'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_data_verification",
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

                with data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'failed')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_query_invocation_verify_checksum(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type checksum')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND RESC_NAME = 'AnotherResc'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_data_verification",
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

                with data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_query_invocation_verify_checksum_fail(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::verification::type checksum')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)
                admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', filename)

                # truncate file in vault path to force a failure
                with open('/tmp/irods/AnotherResc/home/rods/test_put_file', 'w') as f:
                    f.truncate(5)

                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND RESC_NAME = 'AnotherResc'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_data_verification",
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

                with data_verification_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'failed')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                admin_session.assert_icommand('irm -f ' + filename)



    def test_direct_invocation_with_alternate_attribute(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc direct_invocation_attribute filesystem')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)

                rule = """
{
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_data_verification",
    "parameters" : {
        "user_name" : "rods",
        "logical_path" : "/tempZone/home/rods/test_put_file",
        "destination_resource" : "AnotherResc"
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

                with data_verification_alternate_attributes_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
            finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation_with_alternate_attribute(self):
        with session.make_session_for_existing_admin() as admin_session:
            admin_session.assert_icommand('imeta set -R AnotherResc event_handler_attribute filesystem')
            with data_verification_alternate_attributes_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('irepl -R AnotherResc ' + filename, 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)




