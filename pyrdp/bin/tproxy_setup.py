#!/usr/bin/env python3
# coding=utf-8

#
# This file is part of the PyRDP project.
# Copyright (C) 2025 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

"""
Transparent proxy setup automation tool.

This script automates the complex network configuration required for
transparent proxying as described in docs/transparent-proxy.md.
"""

import argparse
import json
import logging
import os
import subprocess
import sys
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)


@dataclass
class TProxyConfig:
    """Configuration for transparent proxy setup."""

    mode: str  # 'l3' or 'l2'
    server_ip: str
    mark: int = 1
    table_id: int = 100

    # L2 bridge specific
    client_if: Optional[str] = None
    server_if: Optional[str] = None
    gateway_ip: Optional[str] = None
    local_net: Optional[str] = None
    gateway_mac: Optional[str] = None
    server_mac: Optional[str] = None
    mitm_ns: str = 'mitm'
    bridge_name: str = 'br0'

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TProxyConfig':
        """Create config from dictionary."""
        return cls(**data)


def check_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0


def check_kernel_module(module: str) -> bool:
    """Check if a kernel module is loaded."""
    return os.path.exists(f'/sys/module/{module}')


def check_command_exists(command: str) -> bool:
    """Check if a command exists in PATH."""
    result = subprocess.run(
        ['which', command],
        capture_output=True,
        text=True
    )
    return result.returncode == 0


def validate_prerequisites(config: TProxyConfig) -> List[str]:
    """
    Validate prerequisites for transparent proxy setup.

    Args:
        config: TProxyConfig object

    Returns:
        List of error messages (empty if all checks pass)
    """
    errors = []

    # Check root access
    if not check_root():
        errors.append('Error: This script must be run as root (use sudo)')

    # Check required commands
    required_commands = ['iptables', 'ip']
    if config.mode == 'l2':
        required_commands.extend(['ebtables', 'brctl'])

    for cmd in required_commands:
        if not check_command_exists(cmd):
            errors.append(f'Error: Required command not found: {cmd}')

    # Check kernel modules for L2 mode
    if config.mode == 'l2':
        if not check_kernel_module('br_netfilter'):
            errors.append(
                'Warning: br_netfilter module not loaded. '
                'It will be loaded during setup.'
            )

    # Validate L2 specific requirements
    if config.mode == 'l2':
        if not config.client_if or not config.server_if:
            errors.append('Error: L2 mode requires client_if and server_if')

    return errors


class TProxySetup:
    """Handles transparent proxy setup and teardown."""

    def __init__(self, config: TProxyConfig):
        """
        Initialize TProxySetup.

        Args:
            config: TProxyConfig object
        """
        self.config = config

    def generate_setup_commands(self) -> List[str]:
        """
        Generate setup commands based on configuration.

        Returns:
            List of shell commands to execute
        """
        if self.config.mode == 'l3':
            return self._generate_l3_setup_commands()
        elif self.config.mode == 'l2':
            return self._generate_l2_setup_commands()
        else:
            raise ValueError(f'Invalid mode: {self.config.mode}')

    def _generate_l3_setup_commands(self) -> List[str]:
        """Generate L3 setup commands."""
        commands = []

        # Add routing table entry
        commands.append(
            f'echo "{self.config.table_id}    pyrdp" >> /etc/iproute2/rt_tables'
        )

        # Enable IP forwarding
        commands.append('echo 1 > /proc/sys/net/ipv4/ip_forward')

        # TPROXY iptables rule for incoming traffic
        commands.append(
            f'iptables -t mangle -I PREROUTING -p tcp -d {self.config.server_ip} '
            f'--dport 3389 -j TPROXY --tproxy-mark {self.config.mark} '
            '--on-port 3389 --on-ip 127.0.0.1'
        )

        # Mark return traffic
        commands.append(
            f'iptables -t mangle -A PREROUTING -s {self.config.server_ip} '
            f'-m tcp -p tcp --sport 3389 -j MARK --set-mark {self.config.mark}'
        )

        # Routing rule for marked packets
        commands.append(
            f'ip rule add fwmark {self.config.mark} lookup {self.config.table_id}'
        )

        # Route marked traffic to loopback
        commands.append(
            f'ip route add local default dev lo table {self.config.table_id}'
        )

        return commands

    def _generate_l2_setup_commands(self) -> List[str]:
        """Generate L2 bridge setup commands."""
        commands = []

        # Create network namespace
        commands.append(f'ip netns add {self.config.mitm_ns}')

        # Assign interfaces to namespace
        commands.append(
            f'ip link set dev {self.config.client_if} netns {self.config.mitm_ns}'
        )
        commands.append(
            f'ip link set dev {self.config.server_if} netns {self.config.mitm_ns}'
        )

        # Commands to run inside namespace
        ns_prefix = f'ip netns exec {self.config.mitm_ns}'

        # Enable loopback
        commands.append(f'{ns_prefix} ip link set dev lo up')

        # Create bridge
        commands.append(f'{ns_prefix} ip link add name {self.config.bridge_name} type bridge')
        commands.append(f'{ns_prefix} ip link set {self.config.client_if} master {self.config.bridge_name}')
        commands.append(f'{ns_prefix} ip link set {self.config.server_if} master {self.config.bridge_name}')
        commands.append(f'{ns_prefix} brctl setfd {self.config.bridge_name} 0')
        commands.append(f'{ns_prefix} ip link set {self.config.client_if} up')
        commands.append(f'{ns_prefix} ip link set {self.config.server_if} up')
        commands.append(f'{ns_prefix} ip link set {self.config.bridge_name} up')

        # Add routing table entry
        commands.append(
            f'{ns_prefix} bash -c "echo \'{self.config.table_id}    pyrdp\' >> /etc/iproute2/rt_tables"'
        )

        # Routing rules
        commands.append(
            f'{ns_prefix} ip rule add fwmark {self.config.mark} lookup {self.config.table_id}'
        )
        commands.append(
            f'{ns_prefix} ip route add local default dev lo table {self.config.table_id}'
        )

        # Load br_netfilter module
        commands.append('modprobe br_netfilter')
        commands.append('echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables')

        # Disable reverse path filtering
        commands.append('echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter')
        commands.append('echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter')
        commands.append(
            f'{ns_prefix} bash -c "echo 0 > /proc/sys/net/ipv4/conf/{self.config.client_if}/rp_filter"'
        )
        commands.append(
            f'{ns_prefix} bash -c "echo 0 > /proc/sys/net/ipv4/conf/{self.config.server_if}/rp_filter"'
        )

        # Add routes if gateway info provided
        if self.config.gateway_ip and self.config.local_net:
            commands.append(
                f'{ns_prefix} ip route add {self.config.local_net} dev {self.config.bridge_name}'
            )
            commands.append(
                f'{ns_prefix} ip route add default via {self.config.gateway_ip} dev {self.config.bridge_name}'
            )

            # Add ARP pinning if MACs provided
            if self.config.gateway_mac and self.config.server_mac:
                commands.append(
                    f'{ns_prefix} arp -i {self.config.bridge_name} -s {self.config.gateway_ip} '
                    f'{self.config.gateway_mac}'
                )
                commands.append(
                    f'{ns_prefix} arp -i {self.config.bridge_name} -s {self.config.server_ip} {self.config.server_mac}'
                )

        # ebtables and iptables rules for interception
        commands.append(
            f'{ns_prefix} ebtables -t broute -A BROUTING -i {self.config.client_if} '
            f'-p ipv4 --ip-dst {self.config.server_ip} --ip-proto tcp --ip-dport 3389 '
            '-j redirect --redirect-target DROP'
        )
        commands.append(
            f'{ns_prefix} iptables -t mangle -I PREROUTING -p tcp -d {self.config.server_ip} '
            f'--dport 3389 -j TPROXY --tproxy-mark {self.config.mark} '
            '--on-port 3389 --on-ip 127.0.0.1'
        )
        commands.append(
            f'{ns_prefix} ebtables -t broute -A BROUTING -i {self.config.server_if} '
            f'-p ipv4 --ip-src {self.config.server_ip} --ip-proto tcp --ip-source-port 3389 '
            '-j redirect --redirect-target DROP'
        )
        commands.append(
            f'{ns_prefix} iptables -t mangle -A PREROUTING -s {self.config.server_ip} '
            f'-m tcp -p tcp --sport 3389 -j MARK --set-mark {self.config.mark}'
        )

        return commands

    def generate_teardown_commands(self) -> List[str]:
        """
        Generate teardown commands to clean up setup.

        Returns:
            List of shell commands to execute
        """
        if self.config.mode == 'l3':
            return self._generate_l3_teardown_commands()
        elif self.config.mode == 'l2':
            return self._generate_l2_teardown_commands()
        else:
            raise ValueError(f'Invalid mode: {self.config.mode}')

    def _generate_l3_teardown_commands(self) -> List[str]:
        """Generate L3 teardown commands."""
        commands = []

        # Delete iptables rules (reverse order)
        commands.append(
            f'ip route del local default dev lo table {self.config.table_id} 2>/dev/null || true'
        )
        commands.append(
            f'ip rule del fwmark {self.config.mark} lookup {self.config.table_id} 2>/dev/null || true'
        )
        commands.append(
            f'iptables -t mangle -D PREROUTING -s {self.config.server_ip} '
            f'-m tcp -p tcp --sport 3389 -j MARK --set-mark {self.config.mark} 2>/dev/null || true'
        )
        commands.append(
            f'iptables -t mangle -D PREROUTING -p tcp -d {self.config.server_ip} '
            f'--dport 3389 -j TPROXY --tproxy-mark {self.config.mark} '
            '--on-port 3389 --on-ip 127.0.0.1 2>/dev/null || true'
        )

        # Clean up routing table entry
        commands.append(
            f'sed -i "/{self.config.table_id}\\s*pyrdp/d" /etc/iproute2/rt_tables 2>/dev/null || true'
        )

        return commands

    def _generate_l2_teardown_commands(self) -> List[str]:
        """Generate L2 teardown commands."""
        commands = []

        ns_prefix = f'ip netns exec {self.config.mitm_ns}'

        # Flush ebtables and iptables rules
        commands.append(f'{ns_prefix} ebtables -t broute -F BROUTING 2>/dev/null || true')
        commands.append(f'{ns_prefix} iptables -t mangle -F PREROUTING 2>/dev/null || true')

        # Delete routing rules
        commands.append(
            f'{ns_prefix} ip route del local default dev lo table {self.config.table_id} 2>/dev/null || true'
        )
        commands.append(
            f'{ns_prefix} ip rule del fwmark {self.config.mark} lookup {self.config.table_id} 2>/dev/null || true'
        )

        # Delete network namespace (this also removes interfaces and bridge)
        commands.append(f'ip netns del {self.config.mitm_ns} 2>/dev/null || true')

        # Clean up routing table entry
        commands.append(
            f'sed -i "/{self.config.table_id}\\s*pyrdp/d" /etc/iproute2/rt_tables 2>/dev/null || true'
        )

        return commands

    def execute_commands(self, commands: List[str], dry_run: bool = False) -> bool:
        """
        Execute a list of shell commands.

        Args:
            commands: List of commands to execute
            dry_run: If True, only print commands without executing

        Returns:
            True if all commands succeeded, False otherwise
        """
        for cmd in commands:
            if dry_run:
                print(f'[DRY RUN] {cmd}')
                continue

            logger.info(f'Executing: {cmd}')
            try:
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    check=False
                )

                if result.returncode != 0:
                    logger.error(f'Command failed: {cmd}')
                    logger.error(f'Error: {result.stderr}')
                    return False

                if result.stdout:
                    logger.debug(result.stdout)

            except Exception as e:
                logger.error(f'Exception executing command: {cmd}')
                logger.error(str(e))
                return False

        return True

    def save_config(self, filepath: str):
        """Save configuration to a JSON file."""
        with open(filepath, 'w') as f:
            json.dump(self.config.to_dict(), f, indent=2)

    @classmethod
    def load_config(cls, filepath: str) -> 'TProxySetup':
        """Load configuration from a JSON file."""
        with open(filepath, 'r') as f:
            data = json.load(f)
        config = TProxyConfig.from_dict(data)
        return cls(config)


def interactive_config() -> TProxyConfig:
    """Interactively gather configuration from user."""
    print('\n=== PyRDP Transparent Proxy Setup ===\n')

    # Choose mode
    print('Select proxy mode:')
    print('  1) L3 - Basic Layer 3 proxy (simple)')
    print('  2) L2 - Layer 2 bridge with network namespace (advanced)')
    mode_choice = input('Enter choice [1/2]: ').strip()

    if mode_choice == '2':
        mode = 'l2'
    else:
        mode = 'l3'

    # Common parameters
    server_ip = input('\nEnter RDP server IP to intercept: ').strip()

    if mode == 'l3':
        return TProxyConfig(mode='l3', server_ip=server_ip)

    # L2 specific parameters
    print('\nL2 Bridge Configuration:')
    client_if = input('Enter client-facing interface (e.g., enp0s3): ').strip()
    server_if = input('Enter server-facing interface (e.g., enp0s8): ').strip()
    gateway_ip = input('Enter gateway IP (optional): ').strip() or None
    local_net = input('Enter local network CIDR (optional, e.g., 10.13.37.0/24): ').strip() or None

    gateway_mac = None
    server_mac = None
    if gateway_ip:
        use_arp_pinning = input('Use ARP pinning for stealth? [y/N]: ').strip().lower() == 'y'
        if use_arp_pinning:
            gateway_mac = input('Enter gateway MAC address: ').strip()
            server_mac = input('Enter server MAC address: ').strip()

    return TProxyConfig(
        mode='l2',
        server_ip=server_ip,
        client_if=client_if,
        server_if=server_if,
        gateway_ip=gateway_ip,
        local_net=local_net,
        gateway_mac=gateway_mac,
        server_mac=server_mac
    )


def main():
    """Main entry point for the transparent proxy setup tool."""
    parser = argparse.ArgumentParser(
        description='Automate PyRDP transparent proxy setup',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Interactive setup
  sudo pyrdp-tproxy-setup setup

  # Setup from config file
  sudo pyrdp-tproxy-setup setup --config tproxy.json

  # Teardown
  sudo pyrdp-tproxy-setup teardown --config tproxy.json

  # Dry run (show commands without executing)
  sudo pyrdp-tproxy-setup setup --dry-run

For more information, see docs/transparent-proxy.md
        '''
    )

    parser.add_argument(
        'action',
        choices=['setup', 'teardown'],
        help='Action to perform'
    )
    parser.add_argument(
        '--config',
        help='Load/save configuration from/to JSON file'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show commands without executing them'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(levelname)s: %(message)s'
    )

    # Load or create configuration
    if args.config and os.path.exists(args.config):
        logger.info(f'Loading configuration from {args.config}')
        setup = TProxySetup.load_config(args.config)
    else:
        config = interactive_config()
        setup = TProxySetup(config)

        # Save config if path provided
        if args.config:
            setup.save_config(args.config)
            logger.info(f'Configuration saved to {args.config}')

    # Validate prerequisites
    errors = validate_prerequisites(setup.config)
    if errors:
        for error in errors:
            if error.startswith('Error:'):
                logger.error(error)
            else:
                logger.warning(error)

        # Exit on actual errors (not warnings)
        if any(e.startswith('Error:') for e in errors):
            sys.exit(1)

    # Generate and execute commands
    if args.action == 'setup':
        logger.info('Generating setup commands...')
        commands = setup.generate_setup_commands()
    else:
        logger.info('Generating teardown commands...')
        commands = setup.generate_teardown_commands()

    if args.dry_run:
        print('\n=== Commands to execute ===\n')

    success = setup.execute_commands(commands, dry_run=args.dry_run)

    if args.dry_run:
        print('\n=== Dry run complete ===')
        print('\nTo execute these commands, run without --dry-run')
    elif success:
        logger.info(f'{args.action.capitalize()} completed successfully!')

        if args.action == 'setup':
            print('\nNext steps:')
            if setup.config.mode == 'l2':
                print(f'  1. Enter network namespace: sudo ip netns exec {setup.config.mitm_ns} bash')
                print(f'  2. Launch PyRDP: pyrdp-mitm --transparent {setup.config.server_ip}')
            else:
                print(f'  1. Launch PyRDP: sudo pyrdp-mitm --transparent {setup.config.server_ip}')
    else:
        logger.error(f'{args.action.capitalize()} failed!')
        sys.exit(1)


if __name__ == '__main__':
    main()
