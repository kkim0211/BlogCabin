#!/usr/bin/env python

################################################################################
# Written by Kevin Kim
# 
# BLOG PROJECT
# 
# References some code in Udactiy's Web Development course
################################################################################

import os
import hmac
import cgi
import random
import hashlib

import jinja2
import webapp2

from google.appengine.ext import db

# Load templates under <current dir>/templates for jinja2
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

################################################################################
# Utility functions

# *secret: secret key
# @make_secure_val(val): make a val|hash pair using the secret key
# @check_secure_val(secure_val): check that secure_val is a valid val|hash pair
#
# @make_salt: make a salt value of 5 random letters
# @make_pw_hash(username, password, salt): make a pw|hash pair using a salt
#								if given. Generate new salt if dne
# @valid_pw(username, password, h): check that h is a valid pw|hash pair
################################################################################

# Cookie hashing functions
secret = "olW2DoXHGJEKGU0aE9fOwSVE/o4="

def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

# Password hashing functions
letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

def make_salt(length = 5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(username, password, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(username + password + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(username, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(username, password, salt)


################################################################################
# DB Models
################################################################################
# Blog #
# *title
# *content
# *post_time
################################################################################
# User #
# *username
# *pw_hash
# *email
# *join_date
# @by_id(uid): get User instance by ID
# @by_name(username): get User instance by username
# @valid_login(username, password): check if username and password combination
#									is valid. Return User instance if valid.
################################################################################
class Blog(db.Model):
	title = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	post_time = db.DateTimeProperty(auto_now_add = True)


class User(db.Model):
	username = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()
	join_date = db.DateTimeProperty(auto_now_add = True)

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid)

	@classmethod
	def by_name(cls, username):
		u = User.all().filter('username =', username).get()
		return u

	@classmethod
	def valid_login(cls, username, password):
		u = cls.by_name(username)
		if u and valid_pw(username, password, u.pw_hash):
			return u


################################################################################
# Main Handler

# @render(template, **kw): write a response on passed template file and parms
# @set_secure_cookie(cookie, val): set a cookie given cookie name and value
# @login(user): set login cookie given User instance
# @logout: set logout cookie
# @user_from_cookie: return current User from cookie if exists
################################################################################

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, cookie, val):
		secure_cookie_val = make_secure_val(val)
		self.response.headers.add_header('Set-Cookie', 
										'%s=%s; Path=/' % (cookie, secure_cookie_val))
	def login(self, user):
		self.set_secure_cookie('user', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user=; Path=/')

	def user_from_cookie(self):
		user_cookie_val = self.request.cookies.get('user')
		if user_cookie_val:
			user_id = check_secure_val(user_cookie_val)
			if user_id:
				return User.by_id(int(user_id))		


################################################################################
# Default Handler
# '/'
# Redirect user to the front page
################################################################################
class DefaultHandler(Handler):
	def get(self):
		self.redirect("/blog")

################################################################################
# Front Page Handler
# '/blog/?'
# Generate the front page of the blog with most recent 10 blog posts
################################################################################
class FrontPage(Handler):
	def get(self):
		blog_posts = db.GqlQuery("SELECT * FROM Blog ORDER BY post_time DESC LIMIT 10")	
		u = self.user_from_cookie()
		if u:
			# if current user cookie exists, load username in header
			self.render("front.html", username = u.username, blog_posts = blog_posts)
		else:
			self.render("front.html", blog_posts = blog_posts)

################################################################################
# New Post Handler
# '/blog/newpost'
# Submit a new post
################################################################################
class NewpostHandler(Handler):
	def get(self):
		self.render("newpost.html")

	def post(self):
		title = self.request.get("title")
		content = self.request.get("content")

		if not title and not content:
			error = "title and content are missing"
			self.render("newpost.html", error = error)
		elif not title:
			error = "title is missing"
			self.render("newpost.html", content = content, error = error)
		elif not content:
			error = "Content is missing"
			self.render("newpost.html", title = title, error = error)	
		else:
			new_post = Blog(title = title, content = content)
			new_post.put()
			link_id = new_post.key().id()
			self.redirect("/blog/%s" % str(link_id))

################################################################################
# New Post Link Handler
# '/blog/(\d+)'
# View the permalink page for a post
################################################################################
class NewpostLinkHandler(Handler):
	def get(self, link_id):
		blog_post = Blog.get_by_id(int(link_id))
		if not blog_post:
			self.error(404)
			return

		u = self.user_from_cookie()

		if u:
			# if current user cookie exists, load username in header
			self.render("post.html", username = u.username, title = blog_post.title, 
				content = blog_post.content.replace('\n','<br>'), post_time = blog_post.post_time, link_id = link_id)
		else:
			self.render("post.html", title = blog_post.title, 
				content = blog_post.content.replace('\n','<br>'), post_time = blog_post.post_time, link_id = link_id)

################################################################################
# Sign Up Handler
# '/blog/signup'
# Sign Up to be a new user. Redirects to front page after successful signup.
################################################################################
class SignupHandler(Handler):
	def get(self):
		u = self.user_from_cookie()
		if u:
			self.render("welcome.html", username=u.username)
		self.render("signup.html")
	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		password_verify = self.request.get("password_verify")
		email = self.request.get("email")

		if not username:
			error = "Username is required"
			self.render("signup.html", email=email, user_error=error)
		elif not (password and password_verify):
			error = "Password is required"
			self.render("signup.html", username=username, email=email, password_error=error)
		elif not (password == password_verify):
			error = "Passwords do not match"
			self.render("signup.html", username=username, email=email, password_error=error)
		else:
			if User.by_name(username):
				error = "That username already exists!"
				self.render("signup.html", email=email, user_error=error)
			else:
				new_user = User(username = username, pw_hash = make_pw_hash(username, password), email = email)
				new_user.put()
				self.login(new_user)
				self.redirect('/blog')

################################################################################
# Login Handler / Logout Handler
# '/blog/login' / '/blog/logout'
# Log in / Log out as a user. Redirects to front page upon successful login/logout
################################################################################
class LoginHandler(Handler):
	def get(self):
		self.render("login.html")
	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")

		if not username:
			error = "Please enter a username"
			self.render("login.html", error=error)
		elif not password:
			error = "Please enter a password"
			self.render("login.html", error=error)
		else:
			u = User.valid_login(username, password)
			if u:
				self.login(u)
				self.redirect('/blog')
			else:
				error = "Invalid login"
				self.render("login.html", error=error)

class LogoutHandler(Handler):
	def get(self):
		self.logout()
		self.redirect('/blog')

################################################################################
# URL Mapping
################################################################################

app = webapp2.WSGIApplication([
	('/', DefaultHandler),
	('/blog/?', FrontPage), 
	('/blog/newpost', NewpostHandler), 
	('/blog/(\d+)', NewpostLinkHandler), 
	('/blog/login', LoginHandler),
	('/blog/logout', LogoutHandler),
	('/blog/signup', SignupHandler)], debug=True)
