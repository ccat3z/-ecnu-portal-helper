#! /usr/bin/env python3

from urllib.request import urlopen
from urllib.parse import urlencode
from html.parser import HTMLParser
import logging
import logging.handlers
import sys
import ssl
import os
from textwrap import dedent
import argparse

logger = logging.getLogger('ecnu-portal')
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())  # Log to stdout

# Fix issues that dh key too small when request ecnu's portal
# See: https://stackoverflow.com/a/36417794
ssl_ctx = ssl.create_default_context()
ssl_ctx.set_ciphers('DEFAULT:!DH')


class PortalHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.username = None
        self.ip = None

    def handle_starttag(self, tag, attrs):
        if tag != 'input':
            return

        attrs = dict(attrs)
        tag_id = attrs.get('id', None)
        value = attrs.get('value', None)

        if tag_id == 'user_ip':
            self.ip = value
        elif tag_id == 'username':
            self.username = value

    @classmethod
    def parse(cls, data):
        parser = cls()
        parser.feed(data)
        return (parser.ip, parser.username)


def status():
    with urlopen(
        'https://login.ecnu.edu.cn/srun_portal_pc.php',
        context=ssl_ctx,
    ) as req:
        resp = req.read().decode('UTF-8')
        return PortalHTMLParser.parse(resp)


def login(username, password):
    logger.debug('Login...')

    if status()[1]:
        raise Exception('Already logined')

    with urlopen(
        'https://login.ecnu.edu.cn/include/auth_action.php',
        urlencode({
            'action': 'login',
            'username': username,
            'password': password,
            'ac_id': 1,
            'user_ip': '',
            'nas_ip': '',
            'user_mac': '',
            'save_me': 0,
            'ajax': 1
        }).encode('UTF-8'),
        context=ssl_ctx,
    ) as req:
        resp = req.read().decode('UTF-8')
        if resp.startswith('login_ok'):
            logger.debug('Login ok')
        else:
            raise Exception(resp)


def logout(dryrun=False):
    logger.debug('Logout...')

    ip, username = status()
    if not username:
        raise Exception('You are not logged in')

    if dryrun:
        return True

    with urlopen(
        'https://login.ecnu.edu.cn/srun_portal_pc.php',
        urlencode({
            'action': 'auto_logout',
            'user_ip': ip,
            'username': username
        }).encode('UTF-8'),
        context=ssl_ctx,
    ) as req:
        if req.code == 200:
            logger.debug('Logout success')
        else:
            raise Exception('Logout failed')


def nm_dispatcher(interface, username, password):
    logger.debug(sys.argv)

    # NetworkManager似乎不能检测出华师大的Portal
    # if sys.argv[2] == 'connectivity-change':
    #     state = os.getenv('CONNECTIVITY_STATE')
    #     logger.debug('connectivity change: ' + str(state))

    if sys.argv[1] != interface:
        return

    if sys.argv[2] != 'up':
        return

    login(username, password)


if __name__ == '__main__':
    try:
        if os.getenv('NM_DISPATCHER_ACTION') is None:
            parser = argparse.ArgumentParser()
            subparsers = parser.add_subparsers(required=True)

            parser_status = subparsers.add_parser('status')
            parser_status.set_defaults(func=lambda _: logger.info(status()))

            parser_login = subparsers.add_parser('login')
            parser_login.set_defaults(func=login)
            parser_login.add_argument('username', type=str)
            parser_login.add_argument('password', type=str)
            parser_login.set_defaults(
                func=lambda args: login(args.username, args.password)
            )

            parser_logout = subparsers.add_parser('logout')
            parser_logout.set_defaults(func=lambda _: logout())

            args = parser.parse_args()

            args.func(args)
        else:
            # Log to syslog
            syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
            syslog_handler.setFormatter(
                logging.Formatter('ecnu-portal: %(message)s')
            )
            logger.addHandler(syslog_handler)

            nm_dispatcher('__INTERFACE__', '__USERNAME__', '__PASSWORD__')
    except Exception as e:
        logger.error(e)
