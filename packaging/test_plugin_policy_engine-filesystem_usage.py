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
                "instance_name": "irods_rule_engine_plugin-policy_engine-filesystem_usage-instance",
                "plugin_name": "irods_rule_engine_plugin-policy_engine-filesystem_usage",
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


class TestPolicyEngineFilesystemUsage(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(TestPolicyEngineFilesystemUsage, self).setUp()

    def tearDown(self):
        super(TestPolicyEngineFilesystemUsage, self).tearDown()

    def test_filesystem_usage(self):
        with session.make_session_for_existing_admin() as admin_session:
            value = ""

            try:
                rule = """
{
    "comment" : "S1.4 : When the disk usage exceeds 80%, files are automatically deleted from Tier 1 in the order of the oldest last access time",

    "policy_to_invoke" : "irods_policy_enqueue_rule",
    "parameters" : {
        "comment"          : "Set the PLUSET value to the interval desired to run the rule",
        "delay_conditions" : "<PLUSET>10s</PLUSET><EF>REPEAT FOR EVER</EF><INST_NAME>irods_rule_engine_plugin-cpp_default_policy-instance</INST_NAME>",
        "policy_to_invoke" : "irods_policy_execute_rule",
        "parameters" : {
            "policy_to_invoke"    : "irods_policy_filesystem_usage",
            "parameters" : {
                "source_resource" : "demoResc"
            }
        }
    }
}
INPUT null
OUTPUT ruleExecOut
"""

                rule_file = tempfile.NamedTemporaryFile(mode='wt', dir='/tmp', delete=False).name + '.r'
                with open(rule_file, 'w') as f:
                    f.write(rule)

                out = 'need more scope'
                with filesystem_usage_configured():
                    admin_session.assert_icommand(['irule', '-F', rule_file])
                    done = False;
                    while(not done):
                        out, err, _ = admin_session.run_icommand(['iquest', '%s', "SELECT META_RESC_ATTR_VALUE WHERE RESC_NAME = 'demoResc' AND META_RESC_ATTR_NAME = 'irods::resource::filesystem_percent_used'"])
                        if(out.find('CAT_NO_ROWS_FOUND') == -1):
                            done = True
                        else:
                            time.sleep(0.5)
                            done = False

                assert(out != '')

            finally:
                admin_session.assert_icommand('iqdel -a')
                admin_session.assert_icommand('imeta rm -R demoResc irods::resource::filesystem_percent_used '+out)


