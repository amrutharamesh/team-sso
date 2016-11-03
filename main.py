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

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/google', GoogleHandler),
    ('/oauth2callback', GoogleOAuthHandler)
], debug=True)
