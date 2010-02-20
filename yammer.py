#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
A library for authorizing and accessing Yammer via OAuth.

Requires:
  oauth: http://code.google.com/p/oauth/
  pycurl: http://pycurl.sourceforge.net/ (only if using proxy)
  simplejson: http://simplejson.googlecode.com/svn/trunk/simplejson/

Note: The Yammer API methods seem to be designed for being used by users
themselves rather than by bots. If your intention is to bring out material
to, say, an intranet, don't forget to think about how to do it in order
not to expose sensitive information (e.g. direct messages and multiple
networks). Yammer has good defaults in this regard though.

"""
__author__ = 'Jonas Nockert'
__version__ = '0.2'
__license__ = "MIT"
__email__ = "jonasnockert@gmail.com"

from oauth.oauth import (OAuthClient, OAuthConsumer, OAuthError,
                         OAuthRequest, OAuthSignatureMethod_HMAC_SHA1,
                         OAuthSignatureMethod_PLAINTEXT, OAuthToken)
import simplejson

try:
    from local_settings import *
except ImportError:
    debug = False

try:
    # Use pycurl if available since httplib does not support using proxy
    # over https
    import pycurl
    import StringIO
    _use_pycurl = True
    if debug:
        print "Using pycurl."
except ImportError:
    import httplib
    import socket
    _use_pycurl = False


YAMMER_REQUEST_TOKEN_URL = 'https://www.yammer.com/oauth/request_token'
YAMMER_ACCESS_TOKEN_URL = 'https://www.yammer.com/oauth/access_token'
YAMMER_AUTHORIZATION_URL = 'https://www.yammer.com/oauth/authorize'
YAMMER_API_BASE_URL = 'https://www.yammer.com/api/v1/'
YAMMER_URL = 'www.yammer.com'
YAMMER_TIMEOUT = 30


class YammerError(RuntimeError):

    def __init__(self, message='Yammer API error occured.'):
        self.message = message


class Yammer(OAuthClient):

    def __init__(self,
                 consumer_key,
                 consumer_secret,
                 access_token_key=None,
                 access_token_secret=None,
                 proxy_host=None,
                 proxy_port=None,
                 proxy_username=None,
                 proxy_password=None):
        """ Register applications at
        https://www.yammer.com/client_applications/new in order to get
        consumer key and secret.

        Keyword arguments:
        consumer key -- identifies a Yammer application
        consumer secret -- establishes ownership of the consumer key
        access token key -- an OAuth access token (optional)
        access token secret -- establishes ownership of the access key
                               (optional)
        proxy host -- host name of proxy server (optional)
        proxy port -- port number (optional)
        proxy username -- used if proxy requires authentication (optional)
        proxy password -- used if proxy requires authentication (optional)

        """
        self._proxy_host = None
        self._proxy_host = None
        self._proxy_username = None
        self._proxy_password = None
        self._access_token = None

        try:
            self._consumer = OAuthConsumer(consumer_key,
                                           consumer_secret)
            # Could not get HMAC-SHA1 to work but since Yammer is using
            # HTTPS, plaintext should be fine.
            #
            # self._signature = OAuthSignatureMethod_HMAC_SHA1()
            self._signature = OAuthSignatureMethod_PLAINTEXT()
        except OAuthError, m:
            raise YammerError(m.message)

        if access_token_key and access_token_secret:
            self._access_token = OAuthToken(access_token_key,
                                            access_token_secret)

        if _use_pycurl:
            self._connection = pycurl.Curl()
            self._connection.setopt(pycurl.CONNECTTIMEOUT, YAMMER_TIMEOUT)
            self._connection.setopt(pycurl.TIMEOUT, YAMMER_TIMEOUT)
            if debug:
                self._connection.setopt(pycurl.VERBOSE, 1)
        else:
            self._connection = httplib.HTTPSConnection("%s" % YAMMER_URL)
            if debug:
                self._connection.set_debuglevel(1)

        if proxy_host and proxy_port:
            self._proxy_host = proxy_host
            self._proxy_port = int(proxy_port)

            if not _use_pycurl:
                raise YammerError("Use of proxy settings requires pycurl "
                                  "to be installed.")
            elif self._proxy_host is None or self._proxy_port is None:
                raise YammerError("Proxy settings missing host and/or port.")
            elif ((proxy_username and not proxy_password) or
                  (not proxy_username and proxy_password)):
                raise YammerError("Proxy settings missing username (%s) or "
                                  "password (%s)." % (proxy_username,
                                                      proxy_password))

            if proxy_username:
                self._proxy_username = proxy_username
                self._proxy_password = proxy_password

            try:
                self._connection.setopt(pycurl.PROXY, self._proxy_host)
                self._connection.setopt(pycurl.PROXYPORT, self._proxy_port)
                if self._proxy_username:
                    self._connection.setopt(pycurl.PROXYUSERPWD,
                                            "%s:%s" % (self._proxy_username,
                                                       self._proxy_password))
            except:
                raise YammerError("Could not set up proxied connection.")

    def close(self):
        """ Explicitly closes HTTP connection. """

        # both pycurl and httplib use the same close method
        self._connection.close()

    def fetch_request_token(self):
        """ Retrieve an unauthorized request token that, in the next step of
        the OAuth process, will be used to authorize the application.

        """
        try:
            oauth_request = OAuthRequest.from_consumer_and_token(
                                            self._consumer,
                                            http_method='POST',
                                            http_url=YAMMER_REQUEST_TOKEN_URL)
            oauth_request.sign_request(self._signature,
                                       self._consumer,
                                       None)
            headers = oauth_request.to_header()
        except OAuthError, m:
            raise YammerError(m.message)

        if _use_pycurl:
            # convert header dictionary to pycurl header list
            header_list = []
            for h in headers:
                header_list.append("%s:%s" % (h, headers[h]))

            try:
                content = StringIO.StringIO()
                self._connection.setopt(pycurl.HTTPHEADER, header_list)
                self._connection.setopt(pycurl.URL, YAMMER_REQUEST_TOKEN_URL)
                self._connection.setopt(pycurl.WRITEFUNCTION, content.write)
                self._connection.perform()
            except pycurl.error, (n, m):
                raise YammerError(m)

            status = self._connection.getinfo(pycurl.HTTP_CODE)
        else:
            try:
                self._connection.request(oauth_request.http_method,
                                         YAMMER_REQUEST_TOKEN_URL,
                                         headers=headers)
            except socket.gaierror, (n, m):
                raise YammerError(m)

            response = self._connection.getresponse()
            status = response.status

        if status == 401:
            raise YammerError("Consumer key and/or secret not accepted.")
        elif status != 200:
            raise YammerError("Request to '%s' returned HTTP code %d." % (
                                        YAMMER_REQUEST_TOKEN_URL, status))

        if _use_pycurl:
            r = content.getvalue()
        else:
            r = response.read()

        try:
            token = OAuthToken.from_string(r)
        except OAuthError, m:
            raise YammerError(m.message)
        return token

    def get_authorization_url(self, token):
        """ Return URL from which a user can authorize Yammer API access for
        a given application.

        Keyword arguments:
        token -- an unauthorized OAuth request token

        """
        try:
            oauth_request = OAuthRequest.from_token_and_callback(
                                            token=token,
                                            http_url=YAMMER_AUTHORIZATION_URL)
            url = oauth_request.to_url()
        except OAuthError, m:
            raise YammerError(m.message)
        return url

    def fetch_access_token(self,
                           unauth_request_token_key,
                           unauth_request_token_secret,
                           oauth_verifier):
        """ After the user has authorizated API access via the authorization
        URL, get the (semi-)permanent access key using the user-authorized
        request token.

        Keyword arguments:
        unauth_request_token -- the user-authorized OAuth request token
        oauth_verifier -- per OAuth 1.0 Revision A

        """
        url = "%s?oauth_verifier=%s" % (YAMMER_ACCESS_TOKEN_URL,
                                        oauth_verifier)
        try:
            unauth_request_token = OAuthToken(unauth_request_token_key,
                                              unauth_request_token_secret)
            oauth_request = OAuthRequest.from_consumer_and_token(
                                                self._consumer,
                                                token=unauth_request_token,
                                                http_method='POST',
                                                http_url=url)
            oauth_request.sign_request(self._signature,
                                       self._consumer,
                                       unauth_request_token)
            headers = oauth_request.to_header()
        except OAuthError, m:
            raise YammerError(m.message)

        if _use_pycurl:
            # convert header dictionary to pycurl header list
            header_list = []
            for h in headers:
                header_list.append("%s:%s" % (h, headers[h]))

            try:
                content = StringIO.StringIO()
                self._connection.setopt(pycurl.HTTPHEADER, header_list)
                self._connection.setopt(pycurl.URL, url)
                self._connection.setopt(pycurl.WRITEFUNCTION, content.write)
                self._connection.perform()
            except pycurl.error, (n, m):
                raise YammerError(m)

            status = self._connection.getinfo(pycurl.HTTP_CODE)
        else:
            try:
                self._connection.request(oauth_request.http_method,
                                         url,
                                         headers=headers)
            except socket.gaierror, (n, m):
                raise YammerError(m)

            response = self._connection.getresponse()
            status = response.status

        if status == 401:
            raise YammerError("Request token not authorized.")
        elif status != 200:
            raise YammerError("Resource '%s' returned HTTP code %d." % (
                                                            url, status))

        if _use_pycurl:
            r = content.getvalue()
        else:
            r = response.read()

        if debug:
            print "----response----\n%s\n----end-response----\n"

        try:
            self._access_token = OAuthToken.from_string(r)
        except OAuthError, m:
            raise YammerError(m.message)

        return self._access_token

    def _fetch_resource(self, url, parameters=None):
        """ Retrieve a Yammer API resource.

        Keyword arguments:
        url -- a Yammer API URL (excluding query parameters)
        parameters -- used to pass query parameters to add to the request
                      (optional).

        """
        if not self._access_token:
            raise YammerError("Can't fetch resource. Missing access token!")

        try:
            oauth_request = OAuthRequest.from_consumer_and_token(
                                                self._consumer,
                                                token=self._access_token,
                                                http_method='GET',
                                                http_url=url,
                                                parameters=parameters)
            headers = oauth_request.to_header()
            oauth_request.sign_request(self._signature,
                                       self._consumer,
                                       self._access_token)
            url = oauth_request.to_url()
        except OAuthError, m:
            raise YammerError(m.message)

        if _use_pycurl:
            header_list = []
            for h in headers:
                header_list.append("%s:%s" % (h, headers[h]))

            try:
                content = StringIO.StringIO()
                self._connection.setopt(pycurl.HTTPHEADER, header_list)
                self._connection.setopt(pycurl.URL, url)
                self._connection.setopt(pycurl.WRITEFUNCTION, content.write)
                self._connection.perform()
            except pycurl.error, (n, m):
                raise YammerError(m)

            status = self._connection.getinfo(pycurl.HTTP_CODE)
        else:
            try:
                self._connection.request(oauth_request.http_method,
                                         url,
                                         headers=headers)
            except socket.gaierror, (n, m):
                raise YammerError(m)

            response = self._connection.getresponse()
            status = response.status

        if status != 200:
            raise YammerError("Resource '%s' returned HTTP code %d." % (
                                                    url, status))

        if _use_pycurl:
            return content.getvalue()
        else:
            return response.read()

    def get_user_posts(self,
                       max_length=10,
                       username=None,
                       include_replies=False):
        """ Fetch a user's Yammer posts and returns a json decoded
        python structure.

        Note that if a username is not given, the posts of the owner of the
        API keys are fetched.

        Keyword arguments:
        max length -- maximum number of posts to return (defaults to 10)
        username -- a Yammer username for whom to fetch posts (optional)
        include_replies -- return only posts or both posts and replies
                           (optional)

        """
        if username:
            url = "%smessages/from_user/%s.json" % (YAMMER_API_BASE_URL,
                                                    username)
        else:
            url = "%smessages/sent.json" % YAMMER_API_BASE_URL

        json = self._fetch_resource(url)

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
