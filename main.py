#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import webapp2
import jinja2
import sys
sys.path.insert(0, 'lib/')
from apiclient.discovery import build
from oauth2client import client
import httplib2
import requests

# Global variables
# Jinja2 global declaration
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                            autoescape = True)

# Google Oauth global declaration
flow = client.flow_from_clientsecrets(
    'json/client_secret.json',
    scope='https://www.googleapis.com/auth/drive.metadata.readonly',
    redirect_uri='http://localhost:10080/oauth2callback')

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class MainHandler(Handler):
    def get(self):
        self.render('index.html')
    def post(self):
        signIn = self.request.get('signIn')
        if(signIn == 'google'):
            self.redirect('/google')
        if(signIn == 'yammer'):
            self.redirect('/yammer')
        if(signIn == 'basecamp'):
            self.redirect('/basecamp')
        if(signIn == 'zendesk'):
            self.redirect('/zendesk')


class GoogleHandler(Handler):
    def get(self):
        self.render('google/transition.html')
    def post(self):
        auth_uri = str(flow.step1_get_authorize_url())
        self.redirect(auth_uri)

class GoogleOAuthHandler(Handler):
    def get(self):
        auth_code = self.request.get('code')
        credentials = flow.step2_exchange(auth_code)
        http_auth = credentials.authorize(httplib2.Http())
        drive_service = build('drive', 'v2', http=http_auth)
        files = drive_service.files().list().execute()
        self.render('google/index.html', files=files)

class YammerHandler(Handler):
    def get(self):
        self.render('yammer/transition.html')
    def post(self):
        self.redirect('https://www.yammer.com/oauth2/authorize?client_id=gitpw9j5yrNRzTvlPTsj3g&response_type=code&redirect_uri=http://localhost:10080/yammercallback')

class YammerOAuthHandler(Handler):
    def get(self):
        auth_code = self.request.get('code')
        r = requests.post('https://www.yammer.com/oauth2/access_token', data={'client_id' : 'gitpw9j5yrNRzTvlPTsj3g', 'client_secret' : 'qoDl7g6qaTV2ATPM9rAFRKLIHONK1lLnGBVcolBsvQ', 'code' : auth_code, 'grant_type' : 'authorization_code'})
        if(r.status_code == 200):
            self.render('yammer/index.html')

class BasecampHandler(Handler):
    def get(self):
        self.render('basecamp/transition.html')
    def post(self):
        self.redirect('https://launchpad.37signals.com/authorization/new?type=web_server&client_id=7608826c852c97260eac10fe40fc8a8f00506387&redirect_uri=http://localhost:10080/basecampcallback')


class BasecampOAuthHandler(Handler):
    def get(self):
        auth_code = self.request.get('code')
        r = requests.post('https://launchpad.37signals.com/authorization/token', data={'type': 'web_server', 'client_id' : '7608826c852c97260eac10fe40fc8a8f00506387', 'client_secret' : 'f2a62818a2909e5905c3510052eea2f168ea9a40', 'code' : auth_code, 'redirect_uri' : 'http://localhost:10080/basecampcallback'})
        if(r.status_code == 200):
            self.render('basecamp/index.html')

class ZendeskHandler(Handler):
    def get(self):
        self.render('zendesk/transition.html')
    def post(self):
        self.redirect('https://amrutha.zendesk.com/oauth/authorizations/new?response_type=code&redirect_uri=http://localhost:10080/zendeskcallback&client_id=team_sso&scope=read%20write')


class ZendeskOAuthHandler(Handler):
    def get(self):
        auth_code = self.request.get('code')
        r = requests.post('https://amrutha.zendesk.com/oauth/tokens', data={'scope': 'read', 'client_id' : 'team_sso', 'client_secret' : '116f699b09f9c987c8140745bd1c3bd9bd02360097db9dc7ba8fde114e54c402', 'code' : auth_code, 'redirect_uri' : 'http://localhost:10080/zendeskcallback', 'grant_type' : 'authorization_code'})
        if(r.status_code == 200):
            self.render('zendesk/index.html')


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/google', GoogleHandler),
    ('/oauth2callback', GoogleOAuthHandler),
    ('/yammer', YammerHandler),
    ('/yammercallback', YammerOAuthHandler),
    ('/basecamp', BasecampHandler),
    ('/basecampcallback', BasecampOAuthHandler),
    ('/zendesk', ZendeskHandler),
    ('/zendeskcallback', ZendeskOAuthHandler)
], debug=True)
