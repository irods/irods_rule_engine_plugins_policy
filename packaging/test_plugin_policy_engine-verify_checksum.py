import sys
import time
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
def filesystem_usage_configured(arg=None):
    filename = paths.server_config_path()
    with lib.file_backed_up(filename):
        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['rule_engine_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
           {
                "instance_name": "irods_rule_engine_plugin-policy_engine-verify_checksum-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-verify_checksum",
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


class TestPolicyEngineVerifyChecksum(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(TestPolicyEngineVerifyChecksum, self).setUp()

    def tearDown(self):
        super(TestPolicyEngineVerifyChecksum, self).tearDown()

    def test_verify_checksum_success(self):
        with session.make_session_for_existing_admin() as admin_session:
            value = ""

            try:
                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke"    : "irods_policy_verify_checksum",
        "parameters" : {
            "logical_path" : "/tempZone/home/rods/file0",
            "source_resource" : "demoResc"
        }
    }
}
INPUT null
OUTPUT ruleExecOut
"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                admin_session.assert_icommand(['iput', '-fK', rule_file, 'file0'])

                out = 'need more scope'
                with filesystem_usage_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file])

            finally:
                print('annnnd... were done\n')


    def test_verify_checksum_failure(self):
        with session.make_session_for_existing_admin() as admin_session:
            value = ""

            try:
                rule = """
{
    "policy_to_invoke" : "irods_policy_execute_rule",
    "parameters" : {
        "policy_to_invoke"    : "irods_policy_verify_checksum",
        "parameters" : {
            "logical_path" : "/tempZone/home/rods/file0",
            "source_resource" : "demoResc"
        }
    }
}
INPUT null
OUTPUT ruleExecOut
"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                admin_session.assert_icommand(['iput', '-fK', rule_file, 'file0'])

                with open('/var/lib/irods/Vault/home/rods/file0', 'w') as f:
                    f.write('X')

                out = 'need more scope'
                with filesystem_usage_configured():
                    admin_session.assert_icommand(['irule', '-r', 'irods_rule_engine_plugin-cpp_default_policy-instance', '-F', rule_file], 'STDOUT_SINGLELINE', 'failed')

            finally:
                print('annnnd... were done\n')

