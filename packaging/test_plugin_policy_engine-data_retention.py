
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
def data_retention_remove_all_direct_invocation_configured(arg=None):
    filename = paths.server_config_path()
    with lib.file_backed_up(filename):
        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['rule_engine_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
           {
                "instance_name": "irods_rule_engine_plugin-policy_engine-data_retention-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-data_retention",
                "plugin_specific_configuration": {
                    "log_errors" : "true",
                    "mode" : "remove_all_replicas"
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
def data_retention_trim_single_direct_invocation_configured(arg=None):
    filename = paths.server_config_path()
    with lib.file_backed_up(filename):
        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['rule_engine_server_sleep_time_in_seconds'] = 1

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
def data_retention_alternate_attributes_direct_invocation_configured(arg=None):
    filename = paths.server_config_path()
    with lib.file_backed_up(filename):
        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['rule_engine_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
           {
                "instance_name": "irods_rule_engine_plugin-policy_engine-data_retention-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-data_retention",
                "plugin_specific_configuration": {
                    "log_errors" : "true",
                    "mode" : "trim_single_replica"
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



###############




@contextlib.contextmanager
def data_retention_remove_all_configured(arg=None):
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
                            "events" : ["replication"],
                            "policy_to_invoke"    : "irods_policy_data_retention",
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
                    "log_errors" : "true",
                    "mode" : "remove_all_replicas"
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
def data_retention_trim_single_configured(arg=None):
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
                            "events" : ["replication"],
                            "policy_to_invoke"    : "irods_policy_data_retention",
                            "configuration" : {
                                "mode" : "trim_single_replica"
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
                        {   "active_policy_clauses" : ["post"],
                            "events" : ["replication"],
                            "policy_to_invoke"    : "irods_policy_data_retention",
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
                    "log_errors" : "true",
                    "mode" : "trim_single_replica"
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
                        {   "active_policy_clauses" : ["post"],
                            "events" : ["replication"],
                            "policy_to_invoke"    : "irods_policy_data_retention",
                            "configuration" : {
                                "log_errors" : "true",
                                "attribute"  : "event_handler_attribute",
                                "mode" : "trim_single_replica"
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
                    "log_errors" : "true",
                    "mode" : "trim_single_replica"
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
        with session.make_session_for_existing_admin() as admin_session:
            admin_session.assert_icommand("iadmin mkresc rnd random", 'STDOUT_SINGLELINE', 'random')
            admin_session.assert_icommand("iadmin mkresc ufs0 'unixfilesystem' localhost:/tmp/irods/ufs0", 'STDOUT_SINGLELINE', 'unixfilesystem')
            admin_session.assert_icommand("iadmin mkresc ufs1 'unixfilesystem' localhost:/tmp/irods/ufs1", 'STDOUT_SINGLELINE', 'unixfilesystem')
            admin_session.assert_icommand("iadmin mkresc ufs2 'unixfilesystem' localhost:/tmp/irods/ufs2", 'STDOUT_SINGLELINE', 'unixfilesystem')
            admin_session.assert_icommand("iadmin addchildtoresc rnd ufs0")
            admin_session.assert_icommand("iadmin addchildtoresc rnd ufs1")
            admin_session.assert_icommand("iadmin addchildtoresc rnd ufs2")
    def tearDown(self):
        super(TestPolicyEngineDataRetention, self).tearDown()
        with session.make_session_for_existing_admin() as admin_session:
            admin_session.assert_icommand("iadmin rmchildfromresc rnd ufs0")
            admin_session.assert_icommand("iadmin rmchildfromresc rnd ufs1")
            admin_session.assert_icommand("iadmin rmchildfromresc rnd ufs2")
            admin_session.assert_icommand("iadmin rmresc ufs0")
            admin_session.assert_icommand("iadmin rmresc ufs1")
            admin_session.assert_icommand("iadmin rmresc ufs2")
            admin_session.assert_icommand("iadmin rmresc rnd")

    def test_direct_invocation_with_trim_single(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput -R rnd ' + filename)
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)

                rule = """
{
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_data_retention",
    "parameters" : {
        "user_name" : "rods",
        "logical_path" : "/tempZone/home/rods/test_put_file",
        "source_resource" : "rnd"
    },
    "configuration" : {
        "mode" : "trim_single_replica"
    }
}
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with data_retention_trim_single_direct_invocation_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'from ufs')
                    out, err, ec = admin_session.run_icommand('ils -l')
                    assert(out.find('rnd') == -1)
            finally:
                admin_session.assert_icommand('irm -f ' + filename)

    def test_direct_invocation_with_remove_all(self):
        with session.make_session_for_existing_admin() as admin_session:
            filename = 'test_put_file'
            lib.create_local_testfile(filename)
            admin_session.assert_icommand('iput -R rnd ' + filename)
            admin_session.assert_icommand('irepl -R AnotherResc ' + filename)

            rule = """
{
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_data_retention",
    "parameters" : {
        "user_name" : "rods",
        "logical_path" : "/tempZone/home/rods/test_put_file"
    },
    "configuration" : {
        "mode" : "remove_all_replicas"
    }
}
}
INPUT null
OUTPUT ruleExecOut"""

            rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
            with open(rule_file, 'w') as f:
                f.write(rule)

            with data_retention_remove_all_direct_invocation_configured():
                admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                admin_session.assert_icommand('ils -l ' + filename, 'STDERR_SINGLELINE', 'does not exist')

    def test_direct_invocation_with_preserve_replicas(self):
        with session.make_session_for_existing_admin() as admin_session:
            try:
                filename = 'test_put_file'
                lib.create_local_testfile(filename)
                admin_session.assert_icommand('iput -R rnd ' + filename)
                admin_session.assert_icommand('imeta set -R AnotherResc irods::retention::preserve_replicas true')
                admin_session.assert_icommand('irepl -R AnotherResc ' + filename)

                rule = """
{
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_data_retention",
    "parameters" : {
        "user_name" : "rods",
        "logical_path" : "/tempZone/home/rods/test_put_file",
        "source_resource" : "AnotherResc"
    },
    "configuration" : {
        "mode" : "trim_single_replica"
    }
}
}
INPUT null
OUTPUT ruleExecOut"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                with data_retention_trim_single_direct_invocation_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'rnd')
            finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation_with_trim_single(self):
        with session.make_session_for_existing_admin() as admin_session:
            with data_retention_trim_single_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput -R rnd ' + filename)
                    admin_session.assert_icommand('irepl -R AnotherResc ' + filename, 'STDOUT_SINGLELINE', 'Specifying a minimum number of replicas to keep is deprecated')
                    out, err, ec = admin_session.run_icommand('ils -l')
                    assert(out.find('rnd') == -1)

                    admin_session.assert_icommand('irepl -R TestResc ' + filename, 'STDOUT_SINGLELINE', 'Specifying a minimum number of replicas to keep is deprecated')
                    out, err, ec = admin_session.run_icommand('ils -l')
                    assert(out.find('AnotherResc') == -1)
                    
                    admin_session.assert_icommand('irepl -R demoResc ' + filename, 'STDOUT_SINGLELINE', 'Specifying a minimum number of replicas to keep is deprecated')
                    out, err, ec = admin_session.run_icommand('ils -l')
                    assert(out.find('TestResc') == -1)
                    
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation_with_whitelist(self):
        with session.make_session_for_existing_admin() as admin_session:
            with data_retention_with_whitelist_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('irepl -R AnotherResc ' + filename, 'STDOUT_SINGLELINE', 'Specifying a minimum number of replicas to keep is deprecated')
                    out, err, ec = admin_session.run_icommand('ils -l')
                    print(out)
                    assert(out.find('demoResc') == -1)
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)



    def test_event_handler_invocation_with_trim_single_preserve_replica(self):
        with session.make_session_for_existing_admin() as admin_session:
            admin_session.assert_icommand('imeta set -R AnotherResc irods::retention::preserve_replicas true')
            with data_retention_trim_single_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput -R AnotherResc ' + filename)
                    admin_session.assert_icommand('irepl -R demoResc ' + filename, 'STDOUT_SINGLELINE', 'usage')
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
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke" : "irods_policy_query_processor",
        "parameters" : {
              "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME, RESC_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file' AND RESC_NAME = 'demoResc'",
              "query_limit" : 1,
              "query_type" : "general",
              "number_of_threads" : 1,
              "policies_to_invoke" : [
                  {
                      "policy_to_invoke" : "irods_policy_data_retention",
                      "configuration" : {
                          "mode" : "trim_single_replica"
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

                with data_retention_trim_single_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'Spec')
                    out, err, ec = admin_session.run_icommand('ils -l')
                    assert(out.find('demoResc') == -1)
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
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_query_processor",
    "parameters" : {
          "query_string" : "SELECT USER_NAME, COLL_NAME, DATA_NAME WHERE COLL_NAME = '/tempZone/home/rods' AND DATA_NAME = 'test_put_file'",
          "query_limit" : 1,
          "query_type" : "general",
          "number_of_threads" : 1,
          "policies_to_invoke" : [
              {
                  "policy_to_invoke" : "irods_policy_data_retention",
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

            with data_retention_remove_all_configured():
                admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
                admin_session.assert_icommand('ils -l ' + filename, 'STDERR_SINGLELINE', 'does not exist')

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
"policy_to_invoke" : "irods_policy_execute_rule",
"parameters" : {
    "policy_to_invoke" : "irods_policy_data_retention",
    "parameters" : {
        "user_name" : "rods",
        "logical_path" : "/tempZone/home/rods/test_put_file",
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

                with data_retention_alternate_attributes_direct_invocation_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'usage')
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
                    admin_session.assert_icommand('irepl -R demoResc ' + filename, 'STDOUT_SINGLELINE', 'usage')
                    admin_session.assert_icommand('ils -l ' + filename, 'STDOUT_SINGLELINE', 'AnotherResc')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)
