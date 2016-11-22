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
import urllib
import json
import urlparse
from requests.auth import HTTPBasicAuth

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
        if(signIn == 'VK'):
            self.redirect('/VK')
        if(signIn == 'stripe'):
            self.redirect('/stripe')
        if(signIn == 'basecamp'):
            self.redirect('/basecamp')
        if(signIn == 'zendesk'):
            self.redirect('/zendesk')
        if(signIn == 'box'):
            self.redirect('/box')
        if(signIn == 'formstack'):
            self.redirect('/formstack')
        if(signIn == 'github'):
            self.redirect('/github')
        if(signIn == 'reddit'):
            self.redirect('/reddit')
        if(signIn == 'yandex'):
            self.redirect('/yandex')
        if(signIn == 'twitch'):
            self.redirect('/twitch')
        if(signIn == 'insta'):
            self.redirect('/insta')
        if(signIn == 'four'):
            self.redirect('/four')
        if(signIn == 'fitbit'):
            self.redirect('/fitbit')

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
        self.redirect('https://www.yammer.com/oauth2/authorize?client_id=gitpw9j5yrNRzTvlPTsj3g&response_type=code&redirect_uri=http://localhost:10080/yammercallback/test')

class YammerOAuthHandler(Handler):
    def get(self):
        auth_code = self.request.get('code')
        r = requests.post('https://www.yammer.com/oauth2/access_token', data={'client_id' : 'gitpw9j5yrNRzTvlPTsj3g', 'client_secret' : 'qoDl7g6qaTV2ATPM9rAFRKLIHONK1lLnGBVcolBsvQ', 'code' : auth_code, 'grant_type' : 'authorization_code'})
        if(r.status_code == 200):
            self.render('yammer/index.html')


class VKHandler(Handler):
    def get(self):
        self.render('VK/transition.html')
    def post(self):
        self.redirect('https://oauth.vk.com/authorize?client_id=5726964&display=page&redirect_uri=http://localhost:10080/VKcallback&scope=friends&response_type=token&v=5.60')

class VKOAuthHandler(Handler):
    def get(self):
        auth_code = self.request.get('code')
        r = requests.post('https://oauth.vk.com/access_token', data={'client_id' : '5726964', 'client_secret' : 'YqF10CUrcll3U5ZHueNr', 'redirect_uri': 'http://localhost:10080/VKcallback' , 'code' : auth_code})
        data = r.json()
        self.response.write(data)
        if(data['access_token'] is not None):
            self.render('VK/index.html')

class StripeHandler(Handler):
    def get(self):
        self.render('stripe/transition.html')
    def post(self):
        self.redirect('https://connect.stripe.com/oauth/authorize?response_type=code&client_id=ca_9YjV9yzfSkwAeyz1ImubH3xPZZM8srFv&scope=read_only')

class StripeOAuthHandler(Handler):
    def get(self):
        auth_code = self.request.get('code')
        r = requests.post('https://connect.stripe.com/oauth/token', data={'client_id' : 'ca_9YjV9yzfSkwAeyz1ImubH3xPZZM8srFv', 'client_secret' : 'sk_test_x6Wyh4IcFAe1sClkoHTI7oEp','code' : auth_code, 'grant_type' : 'authorization_code'})
        if(r.status_code == 200):
            self.render('stripe/index.html')

class BasecampHandler(Handler):
    def get(self):
        self.render('basecamp/transition.html')
    def post(self):
        self.redirect('https://launchpad.37signals.com/authorization/new?type=web_server&client_id=7608826c852c97260eac10fe40fc8a8f00506387&redirect_uri=http://localhost:10080/basecampcallback')


class BasecampOAuthHandler(Handler):
    def get(self):
        auth_code = self.request.get('code')
        r = requests.post('https://launchpad.37signals.com/authorization/token', data={'type': 'web_server', 'client_id' : '7608826c852c97260eac10fe40fc8a8f00506387', 'client_secret' : 'f2a62818a2909e5905c3510052eea2f168ea9a40', 'code' : auth_code, 'redirect_uri' : 'http://localhost:10080/basecampcallback'})
        data = r.json()
        # self.response.out.write(r.json())
        if(data['access_token'] is not None):
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
        data = r.json()
        # self.response.out.write(r.json())
        if(data['access_token'] is not None):
            self.render('zendesk/index.html')

class BoxHandler(Handler):
    def get(self):
        self.render('box/transition.html')
    def post(self):
        self.redirect('https://account.box.com/api/oauth2/authorize?response_type=code&redirect_uri=http://localhost:10080/boxcallback&client_id=nip8kyd6cqy4a78ze9dcc05lbjhwwv5f&state=security_token')


class BoxOAuthHandler(Handler):
    def get(self):
        auth_code = self.request.get('code')
        r = requests.post('https://api.box.com/oauth2/token', data={'client_id' : 'nip8kyd6cqy4a78ze9dcc05lbjhwwv5f', 'client_secret' : 'zGRMnFayAiDlGRZTKVqEbrvOZWw9SlFZ', 'code' : auth_code, 'redirect_uri' : 'http://localhost:10080/boxcallback', 'grant_type' : 'authorization_code'})
        data = r.json()
        # self.response.out.write(r.json())
        if(data['access_token'] is not None):
            self.render('box/index.html')

class FormstackHandler(Handler):
    def get(self):
        self.render('formstack/transition.html')
    def post(self):
        self.redirect('https://www.formstack.com/api/v2/oauth2/authorize?client_id=13697&redirect_uri=http://localhost:10080/formstackcallback&response_type=code')

class FormstackOAuthHandler(Handler):
    def get(self):
        auth_code = self.request.get('code')
        r = requests.post('https://www.formstack.com/api/v2/oauth2/token', data={'client_id' : '13697', 'client_secret' : '8bd4c955e9', 'code' : auth_code, 'redirect_uri' : 'http://localhost:10080/formstackcallback', 'grant_type' : 'authorization_code'})
        data = r.json()
        # self.response.out.write(r.json())
        if(data['access_token'] is not None):
            self.render('formstack/index.html')

class GithubHandler(Handler):
    def get(self):
        self.render('github/transition.html')
    def post(self):
        self.redirect('https://github.com/login/oauth/authorize?client_id=fa6340a78ff5fb928324&redirect_uri=http://localhost:10080/githubcallback/test&scope=user%20public_repo&state=security_token')

class GithubOAuthHandler(Handler):
    def get(self):
        auth_code = self.request.get('code')
        r = requests.post('https://github.com/login/oauth/access_token', data={'client_id' : 'fa6340a78ff5fb928324', 'client_secret' : 'a0fe27f67175453ac45e47156c5cfe3940afc3f3', 'code' : auth_code, 'redirect_uri' : 'http://localhost:10080/githubcallback', 'state' : 'security_token'})
        data = json.loads(json.dumps(urlparse.parse_qs(r.text)))
        if(data['access_token'] is not None):
            self.render('github/index.html')

class RedditHandler(Handler):
    def get(self):
        self.render('reddit/transition.html')
    def post(self):
        self.redirect('https://www.reddit.com/api/v1/authorize?client_id=RY0F0CYh3LcvVw&response_type=code&state=security_token&redirect_uri=http://localhost:10080/redditcallback&duration=permanent&scope=edit%20flair')

class RedditOAuthHandler(Handler):
    def get(self):
        auth_code = self.request.get('code')
        r = requests.post('https://www.reddit.com/api/v1/access_token', data={'code' : auth_code, 'redirect_uri' : 'http://localhost:10080/redditcallback', 'grant_type' : 'authorization_code'}, auth=HTTPBasicAuth('RY0F0CYh3LcvVw', 'zuwA8gSM5Yz-MzSoFywqV7oBbkQ'))
        data = r.json()
        if(data['access_token'] is not None):
            self.render('reddit/index.html')

class YandexHandler(Handler):
    def get(self):
        self.render('yandex/transition.html')
    def post(self):
        self.redirect('https://oauth.yandex.com/authorize?response_type=code&client_id=512dfa57910844418d5075038406f1cc')

class YandexOAuthHandler(Handler):
    def get(self):
        auth_code = self.request.get('code')
        r = requests.post('https://oauth.yandex.com/token', data={'client_id' : '512dfa57910844418d5075038406f1cc', 'client_secret' : '7f80d86eda454298b488d9938f133e1e', 'code' : auth_code, 'grant_type' : 'authorization_code'})
        data = r.json()
        #self.response.out.write(data)
        if(data['access_token'] is not None):
            self.render('yandex/index.html')


class TwitchHandler(Handler):
    def get(self):
        self.render('twitch/transition.html')
    def post(self):
        self.redirect('https://api.twitch.tv/kraken/oauth2/authorize?client_id=5ha5ls3tuod047zo22nza4sdzkgmu1h&response_type=code&state=security_token&redirect_uri=http://localhost:10080/twitchcallback')

class TwitchOAuthHandler(Handler):
    def get(self):
        auth_code = self.request.get('code')
        r = requests.post('https://api.twitch.tv/kraken/oauth2/token', data={'client_id' : '5ha5ls3tuod047zo22nza4sdzkgmu1h', 'client_secret' : '3pkeng6xnd4as3c5w2edzusw0js82t6', 'code' : auth_code, 'redirect_uri' : 'http://localhost:10080/twitchcallback', 'grant_type' : 'authorization_code'})
        data = r.json()
        # self.response.out.write(r.text)
        if(data['access_token'] is not None):
            self.render('twitch/index.html')

class InstagramHandler(Handler):
    def get(self):
        self.render('insta/transition.html')
    def post(self):
        self.redirect('https://api.instagram.com/oauth/authorize/?client_id=eb5e9e8230884648ac0951c5323222fb&response_type=code&redirect_uri=http://localhost:10080/instacallback')

class InstagramOAuthHandler(Handler):
    def get(self):
        auth_code = self.request.get('code')
        r = requests.post('https://api.instagram.com/oauth/access_token', data={'client_id' : 'eb5e9e8230884648ac0951c5323222fb', 'client_secret' : '21eabb039aff4430b76270aa8a18bb53', 'code' : auth_code, 'redirect_uri' : 'http://localhost:10080/instacallback', 'grant_type' : 'authorization_code'})
        data = r.json()
        # self.response.out.write(r.text)
        if(data['access_token'] is not None):
            self.render('insta/index.html')

class FoursquareHandler(Handler):
    def get(self):
        self.render('four/transition.html')
    def post(self):
        self.redirect('https://foursquare.com/oauth2/authorize?client_id=OX04R4OFNWTMJII3MJKSUXYGVG4RFNUQROLYBF1RKWYC1MLD&response_type=code&redirect_uri=http://localhost:10080/fourcallback')

class FoursquareOAuthHandler(Handler):
    def get(self):
        auth_code = self.request.get('code')
        r = requests.post('https://foursquare.com/oauth2/access_token', data={'client_id' : 'OX04R4OFNWTMJII3MJKSUXYGVG4RFNUQROLYBF1RKWYC1MLD', 'client_secret' : 'N0MMPQ3MJFV0JECFTS5JMAFS0IWIS2KFDJ3MM05TN5LWNYRG', 'code' : auth_code, 'redirect_uri' : 'http://localhost:10080/fourcallback', 'grant_type' : 'authorization_code'})
        data = r.json()
        # self.response.out.write(r.text)
        if(data['access_token'] is not None):
            self.render('fitbit/index.html')

class FitbitHandler(Handler):
    def get(self):
        self.render('fitbit/transition.html')
    def post(self):
        self.redirect('https://www.fitbit.com/oauth2/authorize?client_id=227Y9K&response_type=code&redirect_uri=http://localhost:10080/fitbitcallback&scope=activity%20nutrition%20heartrate%20location%20nutrition%20profile%20settings%20sleep%20social%20weight')

class FitbitOAuthHandler(Handler):
    def get(self):
        auth_code = self.request.get('code')
        r = requests.post('https://api.fitbit.com/oauth2/token', data={'client_id' : '227Y9K', 'code' : auth_code, 'redirect_uri' : 'http://localhost:10080/fitbitcallback', 'grant_type' : 'authorization_code'})
        data = r.json()
        # self.response.out.write(r.text)
        if(data['access_token'] is not None):
            self.render('fitbit/index.html')



app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/google', GoogleHandler),
    ('/oauth2callback', GoogleOAuthHandler),
    ('/yammer', YammerHandler),
    ('/yammercallback', YammerOAuthHandler),
    ('/VK', VKHandler),
    ('/VKcallback', VKOAuthHandler),
    ('/stripe', StripeHandler),
    ('/stripecallback', StripeOAuthHandler),
    ('/basecamp', BasecampHandler),
    ('/basecampcallback', BasecampOAuthHandler),
    ('/zendesk', ZendeskHandler),
    ('/zendeskcallback', ZendeskOAuthHandler),
    ('/box', BoxHandler),
    ('/boxcallback', BoxOAuthHandler),
    ('/formstack', FormstackHandler),
    ('/formstackcallback', FormstackOAuthHandler),
    ('/github', GithubHandler),
    ('/githubcallback/test', GithubOAuthHandler),
    ('/reddit', RedditHandler),
    ('/redditcallback', RedditOAuthHandler),
    ('/yandex', YandexHandler),
    ('/yandexcallback', YandexOAuthHandler),
    ('/twitch', TwitchHandler),
    ('/twitchcallback', TwitchOAuthHandler),
    ('/insta', InstagramHandler),
    ('/instacallback', InstagramOAuthHandler),
    ('/four', FoursquareHandler),
    ('/fourcallback', FoursquareOAuthHandler),
    ('/fitbit', FitbitHandler),
    ('/fitbitcallback', FitbitOAuthHandler)

], debug=True)
