import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'ExAM'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# create a secure value
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


# check the secure value against the secret
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# bloghandler class that provides helper methods
class BlogHandler(webapp2.RequestHandler):
    # output to the browser
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    # render the HTML using a template
    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # set the secure cookie
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                                         '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # helps verify the user exists
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # delete the cookie information
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # verify the users status by using cookie information
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# helpers for user model
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


# user model
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    # fetch User object from database with id uid
    @classmethod
    def by_id(self, uid):
        return User.get_by_id(uid, parent=users_key())

    # fetch the list of user objects with name
    @classmethod
    def by_name(self, name):
        u = User.all().filter('name =', name).get()
        return u

    # create the user record in the database
    @classmethod
    def register(self, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(), name=name, pw_hash=pw_hash, email=email)

    @classmethod
    def login(self, name, pw):
        u = self.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

# post model
class Post(db.Model):
    user_id = db.IntegerProperty()
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    # get username of who wrote the blogpost
    def getusername(self):
        user = User.by_id(self.user_id)
        return user.name

    # render the post using the data
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


# comment model

class Comment(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def getusername(self):
        user = User.by_id(self.user_id)
        return user.name

# Like model

class Like(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)

    def getusername(self):
        user = User.by_id(self.user_id)
        return user.name


class BlogFront(BlogHandler):
    def get(self):
        deleted_post_id = self.request.get('deleted_post_id')
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts=posts, deleted_post_id=deleted_post_id)


class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + " order by created desc")

        likes = db.GqlQuery("select * from Like where post_id=" + post_id)

        if not post:
            self.error(404)
            return

        error = self.request.get('error')

        self.render("permalink.html", post=post, noOfLikes=likes.count(),
                    comments=comments, error=error)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        # create a new comment tuples for with the data of the users and post
        c = ""
        if(self.user):
            # increase the like counter
            if (self.request.get('like') and
                        self.request.get('like') == "update"):
                likes = db.GqlQuery("select * from Like where post_id= " +
                                    post_id + " and user_id = " +
                                    str(self.user.key().id()))

                if self.user.key().id() == post.user_id:
                    self.redirect("/blog" + post_id +
                                  "?error=You cannot like your post ")
                    return
                elif likes.count() == 0:
                    like = Like(parent=blog_key(), user_id=self.user.key().id(),
                                post_id=int(post_id))
                    like.put()

            # create a new tuple when you create a comment
            if (self.request.get('comment')):
                c = Comment(parent=blog_key(), user_id=self.user.key().id(),
                            post_id=int(post_id),
                            comment=self.request.get('comment'))
                c.put()
        else:
            self.redirect("/login?error=You need to login before " +
                          "you can edit, like or comment")
            return

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + " order by created desc")
        likes = db.GqlQuery("select * from Like where post_id = " + post_id)

        self.render("permalink.html", post=post, comments=comments,
                    noOfLikes=likes.count(), new=c)


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    # creates a new post and redirects to the newpost page
    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), user_id=self.user.key().id(),
                     subject=subject, content=content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "enter both  the subject and content"
            self.render("newpost.html", subject=subject,
                        content=content, error=error)


class DeletePost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.user_id == self.user.key().id():
                post.delete()
                self.redirect("/?deleted_post_id=" + post_id)
            else:
                self.redirect("/blog/" + post_id + "?error=You don't have " +
                              "access to delete this post")
        else:
            self.redirect("/login?error=You need to be logged in, in order " +
                          "to delete your post")


class EditPost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.user_id == self.user.key().id():
                self.render("editpost.html", subject=post.subject,
                            content=post.content)
            else:
                self.redirect("/blog/" + post_id + "?error=You dont have " +
                              "access to edit this post")
        else:
            self.redirect("/login?error=You need to be logged in " +
                          "to edit your post")

    def post(self, post_id):

        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/%s' % post_id)
        else:
            error = "Enter both a subject and content"
            self.render("editpost.html", subject=subject,
                        content=content, error=error)

class DeleteComment(BlogHandler):
    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id), parent = blog_key())
            c = db.get(key)
            if c.user_id == self.user.key().id():
                c.delete()
                self.redirect("/blog/" + post_id + "?deleted_comment_id=" +
                              comment_id)
            else:
                self.redirect("/blog/", post_id +
                              "?error=You dont have access to edit this comment.")
        else:
            self.redirect("/login?error=You need to be logged in to delete your post")


class EditComment(BlogHandler):
    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
            c1 = db.key(key)
            if c1.user_id == self.user.key().id():
                self.render("editcomment.html", comment=c1.comment)
            else:
                self.redirect("/blog/" + post_id + "?error=You dont have access "
                              + "to edit this comment")
        else:
            self.redirect("/login?error=you need to be logged in to edit your comment")

    def post(self, post_id, comment_id):
        if not self.user:
            self.redirect('/blog')

        comment = self.request.get('comment')

        if comment:
            key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
            c = db.get(key)
            c.comment = comment
            c.put()
            self.redirect('/blog/%s' % post_id)
        else:
           self.redirect("/blog/" + post_id + "?error=You dont have access "
                              + "to edit this comment")

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    # validate the signup
    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That username is not valid"
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That password is not valid"
            have_error = True

        elif self.password != self.verify:
            params['error_verify'] = "Your passwords did not match"
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That email is not valid"
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        # check to see if the user already exists
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog/newpost')


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html', error=self.request.get('error'))

    def post(self):
        # validate the Login
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog/newpost')
        else:
            msg = 'Invalid Login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/login')


app = webapp2.WSGIApplication([
                                ('/?', BlogFront),
                                ('/blog/([0-9]+)', PostPage),
                                ('/blog/newpost', NewPost),
                                ('/blog/deletepost/([0-9]+)', DeletePost),
                                ('/blog/editpost/([0-9]+)', EditPost),
                                ('/blog/deletecomment/([0-9]+)/([0-9]+)',
                                 DeleteComment),
                                ('/blog/editcomment/([0-9]+)/([0-9]+)',
                                 EditComment),
                                ('/signup', Register),
                                ('/login', Login),
                                ('/logout', Logout),
                                ],
                            debug = True)