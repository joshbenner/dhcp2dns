#!/usr/bin/env python
import base64
import contextlib
import logging
from posixpath import join as urljoin
import re
import time

import click
import click_log
import netmiko
import requests

LOGGER = logging.getLogger(__name__)
click_log.basic_config(LOGGER)


@contextlib.contextmanager
def action(msg, *args, lvl=logging.INFO):
    LOGGER.log(lvl, msg, *args)
    start = time.perf_counter()
    try:
        yield
    finally:
        duration = time.perf_counter() - start
        LOGGER.debug('%s in %f seconds', msg % args, duration)


class PowerDnsAdmin(requests.Session):
    def __init__(self, url, key):
        self._base = urljoin(url, 'api/v1')
        super().__init__()
        self.headers.update({
            'X-API-KEY': base64.b64encode(key.encode('utf-8'))
        })

    def url(self, *segments):
        return urljoin(self._base, '/'.join(segments))

    def get_zone(self, zone_name):
        url = self.url('servers/localhost/zones', zone_name)
        with action('GET zone %s from %s', zone_name, url):
            r = self.get(url)
        r.raise_for_status()
        return r.json()

    def get_address_map(self, zone_name):
        zone = self.get_zone(zone_name)
        n = -len(zone_name) - 2
        return {r['name'][:n].lower(): r['records'][0]['content']
                for r in zone['rrsets'] if r['type'] == 'A'}

    def update_zone(self, zone_name, changes):
        url = self.url('servers/localhost/zones', zone_name)
        with action('PATCH zone %s at %s', zone_name, url):
            r = self.patch(url, json={'rrsets': changes})
        r.raise_for_status()


class EdgeRouter:
    _lease_re = re.compile(r'^(?P<ip>[.0-9]+) +(?P<mac>[:0-9a-f]{17})'
                           r' +\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}'
                           r' +[^ ]+ +(?P<name>[^? ]+) *$')
    _static_re = re.compile(r'^.*static-mapping (?P<name>[^ ]+)'
                            r' ip-address (?P<ip>.*)$')

    def __init__(self, host, user, password):
        with action('Connect to %s as %s', host, user):
            self._conn = netmiko.ConnectHandler(
                device_type='vyos',
                host=host,
                username=user,
                password=password
            )
        self.cmd('terminal pager cat')

    def cmd(self, command):
        with action('ER CMD: %s', command):
            return self._conn.send_command(command)

    def get_address_map(self):
        addrmap = {}
        addrmap.update(self.get_leases())
        addrmap.update(self.get_static())
        return addrmap

    def get_leases(self):
        lines = self.cmd('show dhcp leases').splitlines()
        parsed = filter(None, (self._lease_re.match(line) for line in lines))
        return {p['name'].lower(): p['ip'] for p in parsed}

    def get_static(self):
        raw = self.cmd('show configuration commands'
                       ' | grep static-mapping.*ip-address')
        lines = raw.splitlines()
        parsed = filter(None, (self._static_re.match(line) for line in lines))
        return {p['name'].lower(): p['ip'] for p in parsed}


def calculate_changes(dns_map, dhcp_map, zone_name):
    return [
        {
            'name': f'{name}.{zone_name}.'.lower(),
            'type': 'A',
            'ttl': 60,
            'changetype': 'REPLACE',
            'records': [{'content': ip, 'disabled': False}]
        }
        for name, ip in dhcp_map.items()
        if dns_map.get(name) != ip
    ]


@click.command()
@click_log.simple_verbosity_option(LOGGER)
@click.option('--pda-url', help='URL to base of PowerDNS-Admin')
@click.option('--pda-key', help='API key for PowerDNS-Admin')
@click.option('--pda-zone', help='Zone to publish names in')
@click.option('--er-host', help='EdgeRouter hostname or IP')
@click.option('--er-user', help='User to access EdgeRouter')
@click.option('--er-pass', help='EdgeRouter password')
@click.option('--dry-run', help='Do not make changes', is_flag=True)
def sync(pda_url, pda_key, pda_zone, er_host, er_user, er_pass, dry_run):
    LOGGER.debug('DEBUG OUTPUT ENABLED')
    pda = PowerDnsAdmin(pda_url, pda_key)
    er = EdgeRouter(er_host, er_user, er_pass)
    dns_map = pda.get_address_map(pda_zone)
    dhcp_map = er.get_address_map()
    changes = calculate_changes(dns_map, dhcp_map, pda_zone)
    if dry_run:
        LOGGER.info('Changes not applied due to DRY RUN:')
        for change in changes:
            LOGGER.info(repr(change))
    elif len(changes) > 0:
        LOGGER.info('Applying %d changes', len(changes))
        pda.update_zone(pda_zone, changes)
    else:
        LOGGER.info('No changes found')


if __name__ == '__main__':
    sync(auto_envvar_prefix='DHCP2PDA')
