#!/usr/bin/env python3
# coding=utf-8

#
# This file is part of the PyRDP project.
# Copyright (C) 2025 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import unittest
from unittest.mock import Mock, patch, MagicMock
import os
import tempfile
import json

from pyrdp.bin.tproxy_setup import (
    TProxyConfig,
    TProxySetup,
    validate_prerequisites,
    check_root,
    check_kernel_module,
    check_command_exists,
)


class TestTProxyConfig(unittest.TestCase):
    """Test TProxyConfig data class."""

    def test_basic_l3_config(self):
        """Test basic L3 configuration."""
        config = TProxyConfig(
            mode='l3',
            server_ip='10.2.2.2',
            mark=1,
            table_id=100
        )
        self.assertEqual(config.mode, 'l3')
        self.assertEqual(config.server_ip, '10.2.2.2')
        self.assertEqual(config.mark, 1)
        self.assertEqual(config.table_id, 100)

    def test_l2_bridge_config(self):
        """Test L2 bridge configuration with all parameters."""
        config = TProxyConfig(
            mode='l2',
            server_ip='10.13.37.111',
            client_if='enp0s3',
            server_if='enp0s8',
            gateway_ip='10.13.37.10',
            local_net='10.13.37.0/24',
            gateway_mac='08:00:27:59:05:fe',
            server_mac='08:00:27:2d:b6:50',
            mitm_ns='mitm',
            mark=1,
            table_id=100,
            bridge_name='br0'
        )
        self.assertEqual(config.mode, 'l2')
        self.assertEqual(config.client_if, 'enp0s3')
        self.assertEqual(config.server_if, 'enp0s8')
        self.assertEqual(config.gateway_ip, '10.13.37.10')

    def test_to_dict(self):
        """Test config serialization to dict."""
        config = TProxyConfig(
            mode='l3',
            server_ip='10.2.2.2'
        )
        config_dict = config.to_dict()
        self.assertIsInstance(config_dict, dict)
        self.assertEqual(config_dict['mode'], 'l3')
        self.assertEqual(config_dict['server_ip'], '10.2.2.2')

    def test_from_dict(self):
        """Test config deserialization from dict."""
        config_dict = {
            'mode': 'l3',
            'server_ip': '10.2.2.2',
            'mark': 1,
            'table_id': 100
        }
        config = TProxyConfig.from_dict(config_dict)
        self.assertEqual(config.mode, 'l3')
        self.assertEqual(config.server_ip, '10.2.2.2')


class TestPrerequisiteValidation(unittest.TestCase):
    """Test prerequisite validation functions."""

    @patch('os.geteuid')
    def test_check_root_as_root(self, mock_geteuid):
        """Test root check when running as root."""
        mock_geteuid.return_value = 0
        self.assertTrue(check_root())

    @patch('os.geteuid')
    def test_check_root_as_user(self, mock_geteuid):
        """Test root check when running as non-root."""
        mock_geteuid.return_value = 1000
        self.assertFalse(check_root())

    @patch('os.path.exists')
    def test_check_kernel_module_loaded(self, mock_exists):
        """Test kernel module check when module is loaded."""
        mock_exists.return_value = True
        self.assertTrue(check_kernel_module('br_netfilter'))

    @patch('os.path.exists')
    def test_check_kernel_module_not_loaded(self, mock_exists):
        """Test kernel module check when module is not loaded."""
        mock_exists.return_value = False
        self.assertFalse(check_kernel_module('br_netfilter'))

    @patch('subprocess.run')
    def test_check_command_exists_found(self, mock_run):
        """Test command existence check when command exists."""
        mock_run.return_value = Mock(returncode=0)
        self.assertTrue(check_command_exists('iptables'))

    @patch('subprocess.run')
    def test_check_command_exists_not_found(self, mock_run):
        """Test command existence check when command doesn't exist."""
        mock_run.return_value = Mock(returncode=1)
        self.assertFalse(check_command_exists('nonexistent'))

    @patch('pyrdp.bin.tproxy_setup.check_root')
    @patch('pyrdp.bin.tproxy_setup.check_command_exists')
    def test_validate_prerequisites_l3_mode(self, mock_check_cmd, mock_check_root):
        """Test prerequisite validation for L3 mode."""
        mock_check_root.return_value = True
        mock_check_cmd.return_value = True

        config = TProxyConfig(mode='l3', server_ip='10.2.2.2')
        errors = validate_prerequisites(config)
        self.assertEqual(len(errors), 0)

    @patch('pyrdp.bin.tproxy_setup.check_root')
    @patch('pyrdp.bin.tproxy_setup.check_command_exists')
    @patch('pyrdp.bin.tproxy_setup.check_kernel_module')
    def test_validate_prerequisites_l2_mode(self, mock_check_module, mock_check_cmd, mock_check_root):
        """Test prerequisite validation for L2 mode."""
        mock_check_root.return_value = True
        mock_check_cmd.return_value = True
        mock_check_module.return_value = True

        config = TProxyConfig(
            mode='l2',
            server_ip='10.13.37.111',
            client_if='enp0s3',
            server_if='enp0s8'
        )
        errors = validate_prerequisites(config)
        self.assertEqual(len(errors), 0)

    @patch('pyrdp.bin.tproxy_setup.check_root')
    def test_validate_prerequisites_not_root(self, mock_check_root):
        """Test prerequisite validation fails when not root."""
        mock_check_root.return_value = False

        config = TProxyConfig(mode='l3', server_ip='10.2.2.2')
        errors = validate_prerequisites(config)
        self.assertGreater(len(errors), 0)
        self.assertIn('root', errors[0].lower())


class TestTProxySetup(unittest.TestCase):
    """Test TProxySetup class."""

    def setUp(self):
        """Set up test fixtures."""
        self.l3_config = TProxyConfig(
            mode='l3',
            server_ip='10.2.2.2',
            mark=1,
            table_id=100
        )
        self.l2_config = TProxyConfig(
            mode='l2',
            server_ip='10.13.37.111',
            client_if='enp0s3',
            server_if='enp0s8',
            gateway_ip='10.13.37.10',
            local_net='10.13.37.0/24',
            mark=1,
            table_id=100,
            bridge_name='br0',
            mitm_ns='mitm'
        )

    def test_generate_l3_setup_commands(self):
        """Test L3 setup command generation."""
        setup = TProxySetup(self.l3_config)
        commands = setup.generate_setup_commands()

        self.assertIsInstance(commands, list)
        self.assertGreater(len(commands), 0)

        # Check for key commands
        command_str = ' '.join(commands)
        self.assertIn('ip_forward', command_str)
        self.assertIn('iptables', command_str)
        self.assertIn('TPROXY', command_str)
        self.assertIn(self.l3_config.server_ip, command_str)

    def test_generate_l3_teardown_commands(self):
        """Test L3 teardown command generation."""
        setup = TProxySetup(self.l3_config)
        commands = setup.generate_teardown_commands()

        self.assertIsInstance(commands, list)
        self.assertGreater(len(commands), 0)

        # Check for cleanup commands
        command_str = ' '.join(commands)
        self.assertIn('iptables', command_str)
        self.assertIn('-D', command_str)  # Delete rules

    def test_generate_l2_setup_commands(self):
        """Test L2 setup command generation."""
        setup = TProxySetup(self.l2_config)
        commands = setup.generate_setup_commands()

        self.assertIsInstance(commands, list)
        self.assertGreater(len(commands), 0)

        # Check for key commands
        command_str = ' '.join(commands)
        self.assertIn('netns', command_str)
        self.assertIn('bridge', command_str)
        self.assertIn('ebtables', command_str)
        self.assertIn(self.l2_config.bridge_name, command_str)

    def test_generate_l2_teardown_commands(self):
        """Test L2 teardown command generation."""
        setup = TProxySetup(self.l2_config)
        commands = setup.generate_teardown_commands()

        self.assertIsInstance(commands, list)
        self.assertGreater(len(commands), 0)

        # Check for cleanup commands
        command_str = ' '.join(commands)
        self.assertIn('ebtables', command_str)
        self.assertIn('-F', command_str)  # Flush rules

    @patch('subprocess.run')
    def test_execute_commands_success(self, mock_run):
        """Test successful command execution."""
        mock_run.return_value = Mock(returncode=0, stdout='', stderr='')

        setup = TProxySetup(self.l3_config)
        commands = ['echo test']

        result = setup.execute_commands(commands, dry_run=False)
        self.assertTrue(result)

    @patch('subprocess.run')
    def test_execute_commands_failure(self, mock_run):
        """Test command execution failure."""
        mock_run.return_value = Mock(returncode=1, stdout='', stderr='Error')

        setup = TProxySetup(self.l3_config)
        commands = ['false']

        result = setup.execute_commands(commands, dry_run=False)
        self.assertFalse(result)

    def test_execute_commands_dry_run(self):
        """Test dry run mode doesn't execute commands."""
        setup = TProxySetup(self.l3_config)
        commands = ['echo test']

        # Dry run should always return True without executing
        result = setup.execute_commands(commands, dry_run=True)
        self.assertTrue(result)

    def test_save_and_load_config(self):
        """Test saving and loading configuration."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_file = f.name

        try:
            # Save config
            setup = TProxySetup(self.l3_config)
            setup.save_config(config_file)

            # Load config
            loaded_setup = TProxySetup.load_config(config_file)

            self.assertEqual(loaded_setup.config.mode, self.l3_config.mode)
            self.assertEqual(loaded_setup.config.server_ip, self.l3_config.server_ip)
        finally:
            if os.path.exists(config_file):
                os.unlink(config_file)


class TestMainFunction(unittest.TestCase):
    """Test main function and CLI integration."""

    @patch('sys.argv', ['pyrdp-tproxy-setup', 'setup', '--dry-run', '--config', '/tmp/test_config.json'])
    @patch('pyrdp.bin.tproxy_setup.interactive_config')
    @patch('os.path.exists')
    def test_main_setup_dry_run(self, mock_exists, mock_interactive):
        """Test main function with setup and dry-run."""
        mock_exists.return_value = False
        mock_interactive.return_value = TProxyConfig(
            mode='l3',
            server_ip='10.2.2.2'
        )

        # Should not raise exception
        try:
            from pyrdp.bin.tproxy_setup import main
            with patch('sys.exit'):
                main()
        except SystemExit:
            pass  # Expected for successful dry run

    @patch('sys.argv', ['pyrdp-tproxy-setup', 'teardown', '--config', '/tmp/test_config.json'])
    @patch('os.path.exists')
    @patch('pyrdp.bin.tproxy_setup.TProxySetup.load_config')
    @patch('pyrdp.bin.tproxy_setup.TProxySetup.execute_commands')
    @patch('pyrdp.bin.tproxy_setup.check_root')
    @patch('pyrdp.bin.tproxy_setup.check_command_exists')
    def test_main_teardown_with_config(self, mock_check_cmd, mock_check_root, mock_execute, mock_load, mock_exists):
        """Test main function with teardown from config file."""
        mock_exists.return_value = True
        mock_check_root.return_value = True
        mock_check_cmd.return_value = True
        mock_config = TProxyConfig(mode='l3', server_ip='10.2.2.2')
        mock_load.return_value = TProxySetup(mock_config)
        mock_execute.return_value = True

        from pyrdp.bin.tproxy_setup import main
        try:
            main()
        except SystemExit as e:
            # Should exit with 0 on success
            self.assertEqual(e.code, 0)


class TestInteractiveConfig(unittest.TestCase):
    """Test interactive configuration."""

    @patch('builtins.input', side_effect=['1', '10.2.2.2'])
    def test_interactive_config_l3(self, mock_input):
        """Test interactive config for L3 mode."""
        from pyrdp.bin.tproxy_setup import interactive_config

        config = interactive_config()
        self.assertEqual(config.mode, 'l3')
        self.assertEqual(config.server_ip, '10.2.2.2')

    @patch('builtins.input', side_effect=[
        '2',  # L2 mode
        '10.13.37.111',  # server IP
        'enp0s3',  # client interface
        'enp0s8',  # server interface
        '10.13.37.10',  # gateway IP
        '10.13.37.0/24',  # local net
        'y',  # use ARP pinning
        '08:00:27:59:05:fe',  # gateway MAC
        '08:00:27:2d:b6:50'  # server MAC
    ])
    def test_interactive_config_l2_with_arp(self, mock_input):
        """Test interactive config for L2 mode with ARP pinning."""
        from pyrdp.bin.tproxy_setup import interactive_config

        config = interactive_config()
        self.assertEqual(config.mode, 'l2')
        self.assertEqual(config.server_ip, '10.13.37.111')
        self.assertEqual(config.client_if, 'enp0s3')
        self.assertEqual(config.gateway_mac, '08:00:27:59:05:fe')

    @patch('builtins.input', side_effect=[
        '2',  # L2 mode
        '10.13.37.111',  # server IP
        'enp0s3',  # client interface
        'enp0s8',  # server interface
        '',  # no gateway IP
        '',  # no local net
    ])
    def test_interactive_config_l2_minimal(self, mock_input):
        """Test interactive config for L2 mode with minimal options."""
        from pyrdp.bin.tproxy_setup import interactive_config

        config = interactive_config()
        self.assertEqual(config.mode, 'l2')
        self.assertEqual(config.server_ip, '10.13.37.111')
        self.assertIsNone(config.gateway_ip)
        self.assertIsNone(config.gateway_mac)


if __name__ == '__main__':
    unittest.main()
