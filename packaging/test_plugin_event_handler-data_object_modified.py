import os
import sys

import contextlib


import os.path



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
    with lib.file_backed_up(filename):
        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['rule_engine_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
            {
                "instance_name": "irods_rule_engine_plugin-event_handler-data_object_modified-instance",
                "plugin_name": "irods_rule_engine_plugin-event_handler-data_object_modified",
                'plugin_specific_configuration': {
                    "policies_to_invoke" : [
                        {
                            "conditional" : {
                                "logical_path" : "\/tempZone.*"
                            },
                            "active_policy_clauses" : ["post"],
                            "events" : ["put", "get", "create", "read", "write", "rename", "register", "unregister", "replication", "checksum", "copy", "seek", "truncate"],
                            "policy"    : "irods_policy_testing_policy",
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

        irods_config.commit(irods_config.server_config, irods_config.server_config_path)

        IrodsController().restart()

        try:
            yield
        finally:
            pass

@contextlib.contextmanager
def event_handler_configured_fail_conditional(arg=None):
    filename = paths.server_config_path()
    with lib.file_backed_up(filename):
        irods_config = IrodsConfig()
        irods_config.server_config['advanced_settings']['rule_engine_server_sleep_time_in_seconds'] = 1

        irods_config.server_config['plugin_configuration']['rule_engines'].insert(0,
            {
                "instance_name": "irods_rule_engine_plugin-event_handler-data_object_modified-instance",
                "plugin_name": "irods_rule_engine_plugin-event_handler-data_object_modified",
                'plugin_specific_configuration': {
                    "policies_to_invoke" : [
                        {
                            "conditional" : {
                                "logical_path" : "\/badZone.*"
                            },
                            "active_policy_clauses" : ["post"],
                            "events" : ["put", "get", "create", "read", "write", "rename", "register", "unregister", "replication", "checksum", "copy", "seek", "truncate"],
                            "policy"    : "irods_policy_testing_policy",
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

        irods_config.commit(irods_config.server_config, irods_config.server_config_path)

        IrodsController().restart()

        try:
            yield
        finally:
            pass

class TestEventHandlerObjectModified(ResourceBase, unittest.TestCase):
    def setUp(self):
        super(TestEventHandlerObjectModified, self).setUp()

    def tearDown(self):
        super(TestEventHandlerObjectModified, self).tearDown()


    def test_event_handler_put(self):
        with session.make_session_for_existing_admin() as admin_session:
            with event_handler_configured():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'PUT')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)


    def test_event_handler_put_fail_conditional(self):
        with session.make_session_for_existing_admin() as admin_session:
            with event_handler_configured_fail_conditional():
                try:
                    filename = 'test_put_file'
                    lib.create_local_testfile(filename)
                    admin_session.assert_icommand('iput ' + filename)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'None')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)

    def test_event_handler_get(self):
        with session.make_session_for_existing_admin() as admin_session:
            filename = 'test_put_file'
            lib.create_local_testfile(filename)
            admin_session.assert_icommand('iput ' + filename)
            with event_handler_configured():
                try:
                    admin_session.assert_icommand('iget -f ' + filename)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'GET')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)


    def test_event_handler_istream_put(self):
        with session.make_session_for_existing_admin() as admin_session:
            with event_handler_configured():
                try:
                    filename = 'test_put_file'
                    contents = 'hello, world!'
                    admin_session.assert_icommand(['istream', 'write', filename], input=contents)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'PUT')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)


    def test_event_handler_istream_get(self):
        with session.make_session_for_existing_admin() as admin_session:
            filename = 'test_put_file'
            contents = 'hello, world!'
            lib.create_local_testfile(filename)
            admin_session.assert_icommand(['istream', 'write', filename], input=contents)
            with event_handler_configured():
                try:
                    admin_session.assert_icommand(['istream', 'read', filename], 'STDOUT', [contents])
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'GET')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)


    def test_event_handler_mv(self):
        with session.make_session_for_existing_admin() as admin_session:
            filename  = 'test_put_file'
            filename2 = 'test_put_file2'
            lib.create_local_testfile(filename)
            admin_session.assert_icommand('iput ' + filename)
            with event_handler_configured():
                try:
                    admin_session.assert_icommand('imv ' + filename + ' ' + filename2)
                    admin_session.assert_icommand('imeta ls -d ' + filename2, 'STDOUT_SINGLELINE', 'RENAME')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename2)


    def test_event_handler_checksum(self):
        with session.make_session_for_existing_admin() as admin_session:
            filename  = 'test_put_file'
            lib.create_local_testfile(filename)
            admin_session.assert_icommand('iput ' + filename)
            with event_handler_configured():
                try:
                    admin_session.assert_icommand('ichksum ' + filename, 'STDOUT_SINGLELINE', filename)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'CHECKSUM')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)


    def test_event_handler_copy(self):
        with session.make_session_for_existing_admin() as admin_session:
            filename  = 'test_put_file'
            filename2 = 'test_put_file2'
            lib.create_local_testfile(filename)
            admin_session.assert_icommand('iput ' + filename)
            with event_handler_configured():
                try:
                    admin_session.assert_icommand('icp ' + filename + ' ' + filename2)
                    admin_session.assert_icommand('imeta ls -d ' + filename,  'STDOUT_SINGLELINE', 'COPY')
                    admin_session.assert_icommand('imeta ls -d ' + filename2, 'STDOUT_SINGLELINE', 'COPY')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)
                    admin_session.assert_icommand('irm -f ' + filename2)


    def test_event_handler_istream_seek(self):
        with session.make_session_for_existing_admin() as admin_session:
            filename = 'test_put_file'
            contents = 'hello, world!'
            lib.create_local_testfile(filename)
            admin_session.assert_icommand(['istream', 'write', filename], input=contents)
            with event_handler_configured():
                try:
                    admin_session.assert_icommand(['istream', '--offset', '1', 'write', filename], input=contents)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'SEEK')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)


    def test_event_handler_istream_truncate(self):
        with session.make_session_for_existing_admin() as admin_session:
            filename = 'test_put_file'
            contents = 'hello, world!'
            lib.create_local_testfile(filename)
            admin_session.assert_icommand(['istream', 'write', filename], input=contents)
            with event_handler_configured():
                try:
                    admin_session.assert_icommand(['istream', '--offset', '1', 'write', filename], input=contents)
                    admin_session.assert_icommand('imeta ls -d ' + filename, 'STDOUT_SINGLELINE', 'TRUNCATE')
                finally:
                    admin_session.assert_icommand('irm -f ' + filename)


    def test_event_handler_register(self):
        with session.make_session_for_existing_admin() as admin_session:
            filename = 'test_put_file'
            contents = 'hello, world!'
            lib.create_local_testfile(filename)

            physical_path = os.path.join(os.getcwd(), filename)
            with event_handler_configured():
                try:
                    admin_session.assert_icommand('ireg ' + physical_path + ' /tempZone/home/rods/regfile')
                    admin_session.assert_icommand('ils -l', 'STDOUT_SINGLELINE', 'rods')
                    admin_session.assert_icommand('imeta ls -d /tempZone/home/rods/regfile', 'STDOUT_SINGLELINE', 'REGISTER')
                finally:
                    admin_session.assert_icommand('irm -f /tempZone/home/rods/regfile')


    def test_event_handler_unregister(self):
        with session.make_session_for_existing_admin() as admin_session:
            filename = 'test_put_file'
            contents = 'hello, world!'
            lib.create_local_testfile(filename)

            physical_path = os.path.join(os.getcwd(), filename)
            with event_handler_configured():
                try:
                    admin_session.assert_icommand('ireg ' + physical_path + ' /tempZone/home/rods/regfile')
                    admin_session.assert_icommand('iunreg /tempZone/home/rods/regfile')
                    admin_session.assert_icommand('imeta ls -C /tempZone/home/rods', 'STDOUT_SINGLELINE', 'UNREGISTER')
                finally:
                    admin_session.assert_icommand('imeta rm -C /tempZone/home/rods irods_policy_testing_policy UNREGISTER')
