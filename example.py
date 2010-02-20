#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Example implementation.

If run, access token

"""
import string
import simplejson

from yammer import Yammer, YammerError

try:
    from example_local_settings import *
except ImportError:
    pass


__author__ = 'Jonas Nockert'
__license__ = "MIT"
__version__ = '0.2'
__email__ = "jonasnockert@gmail.com"


def get_proxy_info():
    """ Ask user for proxy information if not already defined in
    configuration file.

    """
    # Set defaults
    proxy = {'host': None,
             'port': None,
             'username': None,
             'password': None}

    # Is proxy host set? If not, ask user for proxy information
    if 'proxy_host' not in globals():
        proxy_yesno = raw_input("Use http proxy? [y/N]: ")
        if string.strip((proxy_yesno.lower())[0:1]) == 'y':
            proxy['host'] = raw_input("Proxy hostname: ")
            port = raw_input("Proxy port: ")
            if not port:
                port = 8080
            proxy['port'] = int(port)
            proxy['username'] = raw_input("Proxy username (return for none): ")
            if len(proxy['username']) != 0:
                proxy['password'] = raw_input("Proxy password: ")
    else:
        proxy['host'] = proxy_host
        if 'proxy_port' in globals():
            proxy['port'] = proxy_port
        else:
            proxy['port'] = 8080
        if 'proxy_username' in globals():
            proxy['username'] = proxy_username
        if 'proxy_password' in globals():
            proxy['password'] = proxy_password

    return proxy

def get_consumer_info():
    """ Get consumer key and secret from user unless defined in
    local settings.

    """
    consumer = {'key': None,
                'secret': None}
    if ('consumer_key' not in globals()
            or not consumer_key
            or 'consumer_secret' not in globals()
            or not consumer_secret):
        print "\n#1 ... visit https://www.yammer.com/client_applications/new"
        print "       to register your application.\n"

        consumer['key'] = raw_input("Enter consumer key: ")
        consumer['secret'] = raw_input("Enter consumer secret: ")
    else:
        consumer['key'] = consumer_key
        consumer['secret'] = consumer_secret

    if not consumer['key'] or not consumer['secret']:
        print "*** Error: Consumer key or (%s) secret (%s) not valid.\n" % (
                                                        consumer['key'],
                                                        consumer['secret'])
        raise StandardError("Consumer key or secret not valid")

    return consumer

#
# Main
#

yammer = None
proxy = get_proxy_info()
consumer = get_consumer_info()

# If we already have an access token, we don't need to do the full
# OAuth dance
if ('access_token_key' not in globals()
            or not access_token_key
            or 'access_token_secret' not in globals()
            or not access_token_secret):
    try:
        yammer = Yammer(consumer['key'],
                        consumer['secret'],
                        proxy_host=proxy['host'],
                        proxy_port=proxy['port'],
                        proxy_username=proxy['username'],
                        proxy_password=proxy['password'])
    except YammerError, m:
        print "*** Error: %s" % m.message
        quit()

    print "\n#2 ... Fetching request token.\n"

    try:
        unauth_request_token = yammer.fetch_request_token()
    except YammerError, m:
        print "*** Error: %s" % m.message
        quit()

    unauth_request_token_key = unauth_request_token.key
    unauth_request_token_secret = unauth_request_token.secret

    try:
        url = yammer.get_authorization_url(unauth_request_token)
    except YammerError, m:
        print "*** Error: %s" % m.message
        quit()

    print "#3 ... Manually authorize via url: %s\n" % url

    oauth_verifier = raw_input("After authorizing, enter the OAuth "
                               "verifier (four characters): ")

    print "\n#4 ... Fetching access token.\n"

    try:
        access_token = yammer.fetch_access_token(unauth_request_token_key,
                                                 unauth_request_token_secret,
                                                 oauth_verifier)
    except YammerError, m:
        print "*** Error: %s" % m.message
        quit()

    access_token_key = access_token.key
    access_token_secret = access_token.secret

    print "Your access token:\n"
    print "Key:    %s" % access_token_key
    print "Secret: %s" % access_token_secret

if 'username' not in globals():
    username = raw_input("Enter Yammer username (or return for "
                         "current): ")

if 'include_replies' not in globals():
    include_replies_yesno = raw_input("Include replies? [y/N]: ")
    if string.strip((include_replies_yesno.lower())[0:1]) == 'y':
        include_replies = True
    else:
        include_replies = False

print "\n#5 ... Fetching latest user post.\n"

# If we just got our access key, we already have a Yammer instance
if not yammer:
    try:
        yammer = Yammer(consumer['key'],
                        consumer['secret'],
                        access_token_key=access_token_key,
                        access_token_secret=access_token_secret,
                        proxy_host=proxy['host'],
                        proxy_port=proxy['port'],
                        proxy_username=proxy['username'],
                        proxy_password=proxy['password'])
    except YammerError, m:
        print "*** Error: %s" % m.message
        quit()

try:
    r = yammer.get_user_posts(max_length=1,
                              username=username,
                              include_replies=include_replies)
    yammer.close()
    print "Result:"
    print simplejson.dumps(r, indent=4)
except YammerError, m:
    print "*** Error: %s" % m.message
    quit()
