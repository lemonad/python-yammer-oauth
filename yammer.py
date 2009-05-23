#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
A library for authorizing and accessing Yammer via OAuth.

Requires:
  OAuth: http://code.google.com/p/oauth/
  pycurl: http://pycurl.sourceforge.net/ (only if using proxy)

Note: The Yammer API methods seem to be designed for being used by users
themselves rather than by bots. If your intention is to bring out material
to, say, an intranet. Think carefully about how to do it in order not to
expose sensitive information (e.g. direct messages, multiple networks)

"""

import string
import simplejson
import oauth.oauth as oauth
try:
    # Httplib does not support using proxy over https so use
    # pycurl if available
    import pycurl, StringIO
    use_pycurl = True
except ImportError:
    import httplib, socket
    use_pycurl = False

try:
    from local_settings import *
except ImportError:
    http_debug_flag = False
    consumer_key = ''
    consumer_secret = ''
    access_token_key = ''
    access_token_secret = ''
    username = ''
    include_replies = None


__author__ = 'Jonas Nockert'
__license__ = "GPL"
__version__ = '0.1.0'
__email__ = "jonasnockert@gmail.com"

YAMMER_REQUEST_TOKEN_URL = 'https://www.yammer.com/oauth/request_token'
YAMMER_ACCESS_TOKEN_URL = 'https://www.yammer.com/oauth/access_token'
YAMMER_AUTHORIZATION_URL = 'https://www.yammer.com/oauth/authorize'
YAMMER_API_BASE_URL = 'https://www.yammer.com/api/v1/'
YAMMER_URL = 'www.yammer.com'
YAMMER_TIMEOUT = 30

class YammerError(RuntimeError):

    def __init__(self, message='Yammer API error occured.'):
        self.message = message

class YammerOAuthClient(oauth.OAuthClient):

    def __init__(self, consumer_key, consumer_secret,
                  proxy_host=None, proxy_port=None,
                  proxy_username=None, proxy_password=None):
        """
        Register applications at https://www.yammer.com/client_applications/new
        in order to get consumer keys and secrets.

        Keyword arguments:

        consumer key -- identifies a Yammer application
        consumer secret -- establishes ownership of the consumer key
        proxy host -- host name of proxy server (optional)
        proxy port -- port number (integer, optional)
        proxy username -- used if proxy requires authentication (optional)
        proxy password -- used if proxy requires authentication (optional)

        """
        if use_pycurl:
            self._connection = pycurl.Curl()
            self._connection.setopt(pycurl.CONNECTTIMEOUT, YAMMER_TIMEOUT)
            self._connection.setopt(pycurl.TIMEOUT, YAMMER_TIMEOUT)
            if http_debug_flag:
                self._connection.setopt(pycurl.VERBOSE, 1)
        else:
            self._connection = httplib.HTTPSConnection("%s" % YAMMER_URL)
            if http_debug_flag:
                self._connection.set_debuglevel(100000)

        if proxy_host is not None or proxy_port is not None:
            if not use_pycurl:
                raise YammerError("Use of proxy settings requires pycurl "
                                  "to be installed.")
            elif proxy_host is None or proxy_port is None:
                raise YammerError("Proxy settings missing host and/or port.")
            elif ((proxy_username is not None and proxy_password is None) or
                 (proxy_username is None and proxy_password is not None)):
                raise YammerError("Proxy settings missing username or "
                                  "password.")
            try:
                self._connection.setopt(pycurl.PROXY, proxy_host)
                self._connection.setopt(pycurl.PROXYPORT, proxy_port)
                if proxy_username is not None:
                    self._connection.setopt(pycurl.PROXYUSERPWD, "%s:%s" % (
                                            proxy_username, proxy_password))
            except:
                raise YammerError("Could not set up proxied connection.")

        try:
            self._consumer = oauth.OAuthConsumer(consumer_key, consumer_secret)
            # Can't get HMAC-SHA1 to work but since Yammer is using HTTPS,
            # PLAINTEXT should be fine.
            # self._signature = oauth.OAuthSignatureMethod_HMAC_SHA1()
            self._signature = oauth.OAuthSignatureMethod_PLAINTEXT()
        except oauth.OAuthError, m:
            raise YammerError(m.message)

    def close(self):
        """Explicitly closes HTTP connection."""

        # both pycurl and httplib use the same close method
        self._connection.close()

    def fetch_request_token(self):
        """
        Retrieve an unauthorized request token that, in the next step of the
        OAuth process, will be used to authorize an application.

        """
        try:
            oauth_request = oauth.OAuthRequest.from_consumer_and_token(
                                            self._consumer,
                                            http_method='POST',
                                            http_url=YAMMER_REQUEST_TOKEN_URL)
            oauth_request.sign_request(self._signature, self._consumer, None)
            headers = oauth_request.to_header()
        except oauth.OAuthError, m:
            raise YammerError(m.message)

        if use_pycurl:
            # convert header dictionary to pycurl header list
            header_list = []
            for h in headers:
                header_list.append("%s:%s" % (h, headers[h]))

            try:
                content = StringIO.StringIO()
                self._connection.setopt(pycurl.HTTPHEADER, header_list)
                self._connection.setopt(pycurl.WRITEFUNCTION, content.write)
                self._connection.setopt(pycurl.URL, YAMMER_REQUEST_TOKEN_URL)
                self._connection.perform()
            except pycurl.error, (n, m):
                raise YammerError(m)

            status = self._connection.getinfo(pycurl.HTTP_CODE)
            if status == 401:
                raise YammerError("Consumer key and/or secret not accepted.")
            elif status != 200:
                raise YammerError("Request to '%s' returned HTTP code %d." % (
                                  YAMMER_REQUEST_TOKEN_URL, status))
            r = content.getvalue()
        else:
            try:
                self._connection.request(oauth_request.http_method,
                                          YAMMER_REQUEST_TOKEN_URL,
                                          headers=headers)
            except socket.gaierror, (n, m):
                raise YammerError(m)

            response = self._connection.getresponse()
            if response.status == 401:
                raise YammerError("Consumer key and/or secret not accepted.")
            elif response.status != 200:
                raise YammerError("Request to '%s' returned HTTP code %d." % (
                                  YAMMER_REQUEST_TOKEN_URL, response.status))
            r = response.read()

        try:
            token = oauth.OAuthToken.from_string(r)
        except oauth.OAuthError, m:
            raise YammerError(m.message)
        return token

    def get_authorization_url(self, token):
        """
        Return URL from which a user can authorize Yammer API access for
        a given application.

        Keyword arguments:

        token  -- an unauthorized OAuth request token

        """
        try:
            oauth_request = oauth.OAuthRequest.from_token_and_callback(
                token=token,
                http_url=YAMMER_AUTHORIZATION_URL)
            url = oauth_request.to_url()
        except oauth.OAuthError, m:
            raise YammerError(m.message)
        return url

    def fetch_access_token(self, unauth_request_token, callback_token):
        """
        After the user has authorizated API access via the authorization URL,
        get the (semi-)permanent access key using the user-authorized request
        token.

        Keyword arguments:

        unauth_request_token -- The user-authorized OAuth request token
        callback_token -- Yammer specific token as of
                          http://oauth.net/advisories/2009-1

        """

        url = YAMMER_ACCESS_TOKEN_URL + "?callback_token=" + callback_token
        try:
            oauth_request = oauth.OAuthRequest.from_consumer_and_token(
                self._consumer,
                token=unauth_request_token,
                http_method='POST',
                http_url=url)
            oauth_request.sign_request(self._signature,
                                       self._consumer,
                                       unauth_request_token)
            headers = oauth_request.to_header()
        except oauth.OAuthError, m:
            raise YammerError(m.message)

        if use_pycurl:
            # convert header dictionary to pycurl header list
            header_list = []
            for h in headers:
                header_list.append("%s:%s" % (h, headers[h]))

            try:
                content = StringIO.StringIO()
                self._connection.setopt(pycurl.HTTPHEADER, header_list)
                self._connection.setopt(pycurl.WRITEFUNCTION, content.write)
                self._connection.setopt(pycurl.URL, url)
                self._connection.perform()
            except pycurl.error, (n, m):
                raise YammerError(m)

            status = self._connection.getinfo(pycurl.HTTP_CODE)
            if status == 401:
                raise YammerError("Request token not authorized.")
            elif status != 200:
                raise YammerError("Request to '%s' returned HTTP code %d." % (
                                  url, status))
            r = content.getvalue()
            if http_debug_flag:
                print "----response----"
                print r
                print "----end-response----"
        else:
            try:
                self._connection.request(oauth_request.http_method,
                                         url,
                                         headers=headers)
            except socket.gaierror, (n, m):
                raise YammerError(m)

            response = self._connection.getresponse()
            r = response.read()
            if http_debug_flag:
                print "----response----"
                print r
                print "----end-response----"
            if response.status == 401:
                raise YammerError("Request token not authorized.")
            elif response.status != 200:
                raise YammerError("Resource '%s' returned HTTP code %d." % (
                                  url, response.status))

        try:
            access_token = oauth.OAuthToken.from_string(r)
        except oauth.OAuthError, m:
            raise YammerError(m.message)
        return access_token

    def fetch_resource(self, token, url, parameters=None):
        """
        Retrieve a Yammer API resource.

        Keyword arguments:

        token -- an OAuth access token
        url -- a Yammer API URL (excluding query parameters)
        parameters -- Used to pass query parameters to add to the
                      request (optional).

        """
        try:
            oauth_request = oauth.OAuthRequest.from_consumer_and_token(
                                                self._consumer,
                                                token=token,
                                                http_method='GET',
                                                http_url=url,
                                                parameters=parameters)
            oauth_request.sign_request(self._signature, self._consumer, token)
            url = oauth_request.to_url()
        except oauth.OAuthError, m:
            raise YammerError(m.message)

        if use_pycurl:
            try:
                content = StringIO.StringIO()
                self._connection.setopt(pycurl.WRITEFUNCTION, content.write)
                self._connection.setopt(pycurl.URL, url)
                self._connection.perform()
            except pycurl.error, (n, m):
                raise YammerError(m)

            status = self._connection.getinfo(pycurl.HTTP_CODE)
            if status != 200:
                raise YammerError("Resource '%s' returned HTTP code %d." % (
                                  url, status))
            return content.getvalue()
        else:
            try:
                self._connection.request(oauth_request.http_method, url)
            except socket.gaierror, (n, m):
                raise YammerError(m)

            response = self._connection.getresponse()
            if response.status != 200:
                raise YammerError("Resource '%s' returned HTTP code %d." % (
                                  url, response.status))
            return response.read()

def get_user_posts(consumer_key, consumer_secret,
                    access_token, access_token_secret,
                    max_length=10,
                    username=None,
                    include_replies=False,
                    proxy_host=None, proxy_port=None,
                    proxy_username=None, proxy_password=None):
    """
    Fetch a user's yammer posts and returns a json decoded python structure.

    Note that if a username is not given, the posts of the owner of the API
    keys are fetched.

    Keyword arguments:

    consumer key -- identifies a Yammer application
    consumer secret -- establishes ownership of the consumer key
    access token -- an OAuth access token which enables access to protected
                    resources on behalf of the user
    access token secret -- establish ownership of the access token
    max length -- maximum number of posts to return
    username -- a Yammer username for whom to fetch posts (optional)
    include_replies -- return only posts or both posts and replies (optional)
    proxy host -- host name of proxy server (optional)
    proxy port -- port number (integer, optional)
    proxy username -- used if proxy requires authentication (optional)
    proxy password -- used if proxy requires authentication (optional)

    """
    if username:
        url = "%smessages/from_user/%s.json" % (YAMMER_API_BASE_URL, username)
    else:
        url = "%smessages/sent.json" % (YAMMER_API_BASE_URL)

    client = YammerOAuthClient(consumer_key, consumer_secret,
                                proxy_host=proxy_host,
                                proxy_port=proxy_port,
                                proxy_username=proxy_username,
                                proxy_password=proxy_password)
    token = oauth.OAuthToken(access_token, access_token_secret)
    json = client.fetch_resource(token, url)
    client.close()

    try:
        pyjson = simplejson.loads(json)
    except ValueError:
        raise YammerError("Could not decode json.")

    if 'messages' not in pyjson:
        raise YammerError("Messages section missing in returned JSON.")

    if include_replies:
        return pyjson['messages'][0:max_length]
    else:
        replies = []
        for m in pyjson['messages']:
            if not m['replied_to_id']:
                replies.append(m)
        return replies[0:max_length]


#
# If invoked directly, go through Yammer API authorization process,
# step by step.
#

if __name__ == "__main__":
    proxy_yesno = raw_input("Use http proxy? [y/N]: ")
    if string.strip((proxy_yesno.lower())[0:1]) == 'y':
        proxy_host = raw_input("Proxy hostname: ")
        proxy_port = int(raw_input("Proxy port: "))
        proxy_username = raw_input("Proxy username (return for none): ")
        if len(proxy_username) != 0:
            proxy_password = raw_input("Proxy password: ")
        else:
            proxy_username = None
            proxy_password = None
    else:
        proxy_host = None
        proxy_port = None
        proxy_username = None
        proxy_password = None

    if consumer_key == '' or consumer_secret == '':
        print "\n#1 ... visit " \
            "https://www.yammer.com/client_applications/new\n" \
            "       to register your application.\n"

        consumer_key = raw_input("Enter consumer key: ")
        consumer_secret = raw_input("Enter consumer secret: ")

    if consumer_key == '' or consumer_secret == '':
        print "*** Error: Consumer key or (%s) secret (%s) not valid.\n" % (
                                                consumer_key, consumer_secret)
        quit()

    if(access_token_key == '' or access_token_secret == ''):
        try:
            client = YammerOAuthClient(consumer_key, consumer_secret,
                                proxy_host=proxy_host,
                                proxy_port=proxy_port,
                                proxy_username=proxy_username,
                                proxy_password=proxy_password)
        except YammerError, m:
            print "*** Error: %s" % m.message
            quit()

        print "\n#2 ... Fetching request token.\n"

        try:
            unauth_request_token = client.fetch_request_token()
        except YammerError, m:
            print "*** Error: %s" % m.message
            quit()
        unauth_request_token_key = unauth_request_token.key
        unauth_request_token_secret = unauth_request_token.secret

        try:
            url = client.get_authorization_url(unauth_request_token)
        except YammerError, m:
            print "*** Error: %s" % m.message
            quit()

        print "#3 ... Manually authorize via url: %s\n" % url

        callback_token = raw_input("After authorizing, enter callback" \
                                   " token (four characters): ")

        print "\n#4 ... Fetching access token.\n"

        unauth_request_token = oauth.OAuthToken(unauth_request_token_key,
                              unauth_request_token_secret)
        try:
            access_token = client.fetch_access_token(unauth_request_token,
                                                     callback_token)
        except YammerError, m:
            print "*** Error: %s" % m.message
            quit()
        access_token_key = access_token.key
        access_token_secret = access_token.secret

        print "Your access token: "
        print "\nKey:    %s" % access_token_key
        print "Secret: %s" % access_token_secret

    if username == '':
        username = raw_input("Enter Yammer username (or return for current): ")

    if include_replies == None:
        include_replies_yesno = raw_input("Include replies? [y/N]: ")
        if string.strip((include_replies_yesno.lower())[0:1]) == 'y':
            include_replies = True
        else:
            include_replies = False

    print "\n#5 ... Fetching latest user post.\n"

    try:
        p = get_user_posts(consumer_key,
                          consumer_secret,
                          access_token_key,
                          access_token_secret,
                          1,
                          username=username,
                          include_replies=include_replies,
                          proxy_host=proxy_host,
                          proxy_port=proxy_port,
                          proxy_username=proxy_username,
                          proxy_password=proxy_password)
        print "Result:\n"
        print p
    except YammerError, m:
        print "*** Error: %s" % m.message
        quit()
