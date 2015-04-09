@frappe.whitelist(allow_guest=True)
def login_via_weixin(code):
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

	if save:
		user.flags.ignore_permissions = True
		user.flags.no_welcome_mail = True
		user.save()