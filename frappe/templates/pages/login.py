# Copyright (c) 2013, Web Notes Technologies Pvt. Ltd. and Contributors
# MIT License. See license.txt

from __future__ import unicode_literals
import frappe
import json
import frappe.utils
from frappe import _
import urllib2

class SignupDisabledError(frappe.PermissionError): pass

no_cache = True

WEIXIN_CORPID = "wxb0a52a35354404e0"
WEIXIN_CORPSECRET = frappe.local.conf.wx_secret
# WEIXIN_AGENTID="0"
# WEIXIN_ENCODEINGAESKEY='*******************************'
# WEIXIN_TOKEN = '****************'
# WEIXIN_APPSERVER_ADDR = "http://www.*************.com"
WEIXIN_ACCESSTOKEN_ADDR = "https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=" + WEIXIN_CORPID + "&corpsecret=" + WEIXIN_CORPSECRET
WEIXIN_USERINFO_ADDR = "https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo?"
WEIXIN_OAUTH2_AUTHORIZE_ADDR = "https://open.weixin.qq.com/connect/oauth2/authorize?"
WEIXIN_SENDMSG_ADDR = "https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token="
WEIXIN_AUTH_SUCC = "https://qyapi.weixin.qq.com/cgi-bin/user/authsucc?access_token="
	
def get_context(context):
	# get settings from site config
	context["title"] = "Login"
	context["disable_signup"] = frappe.utils.cint(frappe.db.get_value("Website Settings", "Website Settings", "disable_signup"))

	for provider in ("google", "github", "facebook"):
		if get_oauth_keys(provider):
			context["{provider}_login".format(provider=provider)] = get_oauth2_authorize_url(provider)
			context["social_login"] = True

	return context

oauth2_providers = {
	"google": {
		"flow_params": {
			"name": "google",
			"authorize_url": "https://accounts.google.com/o/oauth2/auth",
			"access_token_url": "https://accounts.google.com/o/oauth2/token",
			"base_url": "https://www.googleapis.com",
		},

		"redirect_uri": "/api/method/frappe.templates.pages.login.login_via_google",

		"auth_url_data": {
			"scope": "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email",
			"response_type": "code"
		},

		# relative to base_url
		"api_endpoint": "oauth2/v2/userinfo"
	},

	"github": {
		"flow_params": {
			"name": "github",
			"authorize_url": "https://github.com/login/oauth/authorize",
			"access_token_url": "https://github.com/login/oauth/access_token",
			"base_url": "https://api.github.com/"
		},

		"redirect_uri": "/api/method/frappe.templates.pages.login.login_via_github",

		# relative to base_url
		"api_endpoint": "user"
	},

	"facebook": {
		"flow_params": {
			"name": "weixin",
			"authorize_url": "https://open.weixin.qq.com/connect/oauth2/authorize",
			"access_token_url": "https://qyapi.weixin.qq.com/cgi-bin/gettoken",
			"base_url": "https://qyapi.weixin.qq.com"
		},

		"redirect_uri": "/api/method/frappe.templates.pages.login.login_via_weixin",

		"auth_url_data": {
			"response_type": "code",
			'scope': 'snsapi_base',
			'appid': WEIXIN_CORPID,
		},

		# relative to base_url
		"api_endpoint": "cgi-bin/user/getuserinfo"
	}
}

def get_oauth_keys(provider):
	"""get client_id and client_secret from database or conf"""

	# try conf
	keys = frappe.conf.get("{provider}_login".format(provider=provider))

	if not keys:
		# try database
		social = frappe.get_doc("Social Login Keys", "Social Login Keys")
		keys = {}
		for fieldname in ("client_id", "client_secret"):
			value = social.get("{provider}_{fieldname}".format(provider=provider, fieldname=fieldname))
			if not value:
				keys = {}
				break
			keys[fieldname] = value

	return keys

def get_oauth2_authorize_url(provider):
	flow = get_oauth2_flow(provider)

	# relative to absolute url
	data = { "redirect_uri": get_redirect_uri(provider) }

	# additional data if any
	data.update(oauth2_providers[provider].get("auth_url_data", {}))

	return flow.get_authorize_url(**data)

def get_oauth2_flow(provider):
	from rauth import OAuth2Service

	# get client_id and client_secret
	params = get_oauth_keys(provider)

	# additional params for getting the flow
	params.update(oauth2_providers[provider]["flow_params"])

	# and we have setup the communication lines
	return OAuth2Service(**params)

def get_redirect_uri(provider):
	redirect_uri = oauth2_providers[provider]["redirect_uri"]
	return frappe.utils.get_url(redirect_uri)

@frappe.whitelist(allow_guest=True)
def login_via_google(code):
	login_via_oauth2("google", code, decoder=json.loads)

@frappe.whitelist(allow_guest=True)
def login_via_github(code):
	login_via_oauth2("github", code)

@frappe.whitelist(allow_guest=True)
def login_via_weixin(code):
	print WEIXIN_CORPSECRET
	provider = 'weixin'
	token = getAccessToken()
	url = WEIXIN_USERINFO_ADDR + "access_token=" + token + "&code=" + code
	resp = urllib2.urlopen(url)
	description = json.loads(resp.read())
	userId = description.get('UserId', None)

	if userId == None:
		frappe.throw(url)
	else:
		login_oauth_user({'email':userId + "@rd.com", }, provider=provider)
		authSucc(token, userId)
		
def authSucc(token, userid):
	url_auth_suc = WEIXIN_AUTH_SUCC + token + "&userid=" + userid
	resp = urllib2.urlopen(url_auth_suc)
	description = json.loads(resp.read())
	print description
	
def getAccessToken():
	resp = urllib2.urlopen(WEIXIN_ACCESSTOKEN_ADDR)
	description = json.loads(resp.read())
	token = description["access_token"]
	return token

def login_via_oauth2(provider, code, decoder=None):
	flow = get_oauth2_flow(provider)

	args = {
		"data": {
			"code": code,
			"redirect_uri": get_redirect_uri(provider),
			"grant_type": "authorization_code"
		}
	}
	if decoder:
		args["decoder"] = decoder

	session = flow.get_auth_session(**args)

	api_endpoint = oauth2_providers[provider].get("api_endpoint")
	info = session.get(api_endpoint).json()

	if "verified_email" in info and not info.get("verified_email"):
		frappe.throw(_("Email not verified with {1}").format(provider.title()))

	login_oauth_user(info, provider=provider)

def login_oauth_user(data, provider=None):
	user = data["email"]
	try:
		update_oauth_user(user, data, provider)
	except SignupDisabledError:
		return frappe.respond_as_web_page("Signup is Disabled", "Sorry. Signup from Website is disabled.",
			success=False, http_status_code=403)

	frappe.local.login_manager.user = user
	frappe.local.login_manager.post_login()

	# redirect!
	frappe.local.response["type"] = "redirect"

	# the #desktop is added to prevent a baidu redirect bug
	frappe.local.response["location"] = "/desk#desktop" if frappe.local.response.get('message') == 'Logged In' else "/"

	# because of a GET request!
	frappe.db.commit()

def update_oauth_user(email, data, provider):
	if isinstance(data.get("location"), dict):
		data["location"] = data.get("location").get("name")

	save = False

	if not frappe.db.exists("User", email):

		# is signup disabled?
		if frappe.utils.cint(frappe.db.get_single_value("Website Settings", "disable_signup")):
			raise SignupDisabledError

		save = True
		user = frappe.new_doc("User")
		user.update({
			"doctype":"User",
			"first_name": data["email"],
			"email": email,
			"enabled": 1,
			"new_password": frappe.generate_hash(data["email"]),
			"user_type": "Website User",
		})

	else:
		user = frappe.get_doc("User", email)

	if provider == "weixin" and not user.get("fb_userid"):
		save = True

	elif provider == "google" and not user.get("google_userid"):
		save = True
		user.google_userid = data["id"]

	elif provider == "github" and not user.get("github_userid"):
		save = True
		user.github_userid = data["id"]
		user.github_username = data["login"]

	if save:
		user.ignore_permissions = True
		user.no_welcome_mail = True
		user.save()