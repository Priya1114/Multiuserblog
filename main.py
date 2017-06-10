
import os
import re
import hashlib
import hmac
from google.appengine.ext import db
from string import letters

import jinja2
import webapp2

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# secret message to hash password
SECRET = "itssecret"


# methods for password hashing
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(val):
    return '%s|%s' % (val, hash_str(val))


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def posts_key(name='default'):
    return db.Key.from_path('posts', name)


# model for post database
class Posts(db.Model):
    title = db.StringProperty(required=True)
    imageurl = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes = db.IntegerProperty(required=True)


def users_key(group='default'):
    return db.Key.from_path('users', group)


# Model for user database
class UserDB(db.Model):
    username = db.StringProperty(required=True)
    email = db.StringProperty()
    password_hash = db.StringProperty(required=True)

    @classmethod
    def by_name(cls, uname):
        u = UserDB.all().filter("username =", uname).get()
        return u

    @classmethod
    def by_email(cls, email):
        u = UserDB.all().filter('email =', email).get()
        return u

    @classmethod
    def register(cls, username, password, email):
        passwd_hash = hash_str(password)
        return UserDB(parent=users_key(),
                      username=username,
                      password_hash=passwd_hash,
                      email=email)


# Model for likes database
class Likes(db.Model):
    userId = db.IntegerProperty(required=True)


# Model for comments database
class Comments(db.Model):
    username = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (str(name), str(cookie_val)))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('username', str(user.username))
        self.redirect('/')

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'username=; Path=/')

    def logged(self):
        return self.read_secure_cookie("username")

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uname = self.read_secure_cookie('username')
        self.user = uname and UserDB.by_name(uname)

    def is_liked(self, username, post_key):
        if username:
            user = db.GqlQuery("SELECT * FROM UserDB WHERE username = :user",
                               user=username)
            user_id = user.get().key().id()
            like = Likes.all()
            like.ancestor(post_key)
            like.filter("userId = ", user_id)
            like = like.get()
            if like:
                return like
            else:
                return False
        else:
            return False


# regex expressions to check for validations
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{1,10}$")


def valid_username(username):
    return username and USER_RE.match(username)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


# handler to manage signup page
class Signup(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        username = self.request.get("username")
        email = self.request.get("email")
        password = self.request.get("password")
        verify_password = self.request.get("verify_password")
        params = dict()
        params['username'] = username
        params['email'] = email
        params['password'] = password

        # server side validations
        # for required values
        if (username == "" or password == "" or verify_password == ""):
            params['error'] = "Required Fields can't be Empty"
            self.render("signup.html", **params)

        # for valid username
        if not valid_username(username):
            params['error'] = "That's not a valid username."
            self.render("signup.html", **params)

        # for valid email
        if email != "" and not valid_email(email):
            params['error'] = "That's not a valid email."
            self.render("signup.html", **params)

        # for password
        if password != verify_password and password != "" \
                and verify_password != "":
            params['error'] = "Your passwords didn't match."
            self.render("signup.html", **params)

        # for checking user in database
        if UserDB.by_name(username):
            params['error'] = "Username already taken"
            self.render("signup.html", **params)
        elif email != "" and UserDB.by_email(email):
            params['error'] = "Email id already in use by another user"
            self.render("signup.html", **params)
        else:
            u = UserDB.register(username, password, email)
            u.put()

            self.login(u)
            self.redirect('/')


class Login(Handler):
    def get(self):
        if self.logged():
            self.redirect("/")
        else:
            self.render("login.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("passwd")
        params = dict()

        # validation for valid username
        if not valid_username(username):
            params['error'] = "That's not a valid username."
            self.render("login.html", **params)
        else:
            user = UserDB.by_name(username)
            if not user:
                params['error'] = """User with this username don't exists.
                Please Signup First"""
                self.render("login.html", **params)
            else:
                password_hash = hash_str(password)
                if user.password_hash != password_hash:
                    params['error'] = "Incorrect password"
                    self.render("login.html", **params)
                else:
                    self.login(user)
                    self.redirect('/')


# Handler to logout user
class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/')


# Handler to add new post
class NewPost(Handler):
    def get(self):
        if self.logged():
            self.render("new_post.html", user=self.logged())
        else:
            self.redirect("/login")

    def post(self):

        if not self.logged():
            return self.redirect("/login")

        title = self.request.get("post_title")
        image_url = self.request.get("image_url")
        post_content = self.request.get("post_content")
        likes = 0

        params = dict(user=self.logged(),
                      post_title=title,
                      post_image_url=image_url,
                      post_content=post_content)

        if (title and image_url and post_content):
            post_content = post_content.replace('\n', '<br>')
            p = Posts(parent=posts_key(),
                      title=title,
                      imageurl=image_url,
                      content=post_content,
                      author=self.logged(),
                      likes=likes)

            p.put()
            self.redirect('/post/%s' % str(p.key().id()))

        else:
            params['error'] = "All fields are required"
            self.render("new_post.html", **params)


# Handler for Detailed Post
class PostDetail(Handler):
    def get(self, post_id):
        user = self.logged()

        key = db.Key.from_path('Posts', int(post_id), parent=posts_key())
        post = db.get(key)
        error = self.request.get('error')

        if not post:
            self.write("Error 404")
            return

        comments = Comments.all()
        comments.ancestor(key)
        comments.order('created')

        self.render("post_detail.html",
                    user=user,
                    post=post,
                    comments=comments,
                    error=error,
                    showBackButton=True)


# Handler for adding comments
class AddComment(Handler):
    def post(self, post_id):
        user = self.logged()

        key = db.Key.from_path('Posts', int(post_id), parent=posts_key())
        post = db.get(key)

        if not post:
            self.write("Error 404")
            return

        if user:
            comment = self.request.get('comment')
            if comment:
                comment.replace('\n', '<br>')
                newComment = Comments(parent=key,
                                      username=user,
                                      content=comment)
                newComment.put()
                self.redirect('/post/%s' % str(post.key().id()))
            else:
                self.redirect('/post/%s?error=Empty Comment' % str(post_id))
        else:
            self.redirect("""/post/%s?error=Please Login to comment on the
            post.""" % str(post_id))


# Handler for Deleting comment
class DeleteComment(Handler):
    def get(self, post_id, comment_id):
        user = self.logged()
        if user:
            key = db.Key.from_path('Posts', int(post_id), parent=posts_key())
            post = db.get(key)

            if not post:
                self.write("Error 404")
                return

            comment_key = db.Key.from_path('Comments',
                                           int(comment_id), parent=key)
            comment = db.get(comment_key)

            if user == comment.username or user == 'admin':
                comment.delete()
                self.redirect('/post/%s' % str(post_id))

            else:
                self.redirect("""/post/%s?error=You can only delete
                your own comment""" % str(post_id))

        else:
            self.redirect("""/post/%s?error=Please Login to
            delete your comment""" % str(post_id))


# Handler for Editing comment
class EditComment(Handler):
    def get(self, post_id, comment_id):
        user = self.logged()
        if user:
            key = db.Key.from_path('Posts', int(post_id), parent=posts_key())
            post = db.get(key)

            if not post:
                self.write("Error 404")
                return

            comment_key = db.Key.from_path('Comments',
                                           int(comment_id), parent=key)
            comment = db.get(comment_key)

            if user == comment.username or user == 'admin':
                self.render("post_detail.html", user=user, post=post,
                            postcomment=comment.content,
                            comment=comment)

            else:
                self.redirect("""/post/%s?error=You can only edit
                your own comment.""" % str(post_id))
        else:
            self.redirect("""/post/%s?error=Please login to
            edit your comment.""" % str(post_id))

    def post(self, post_id, comment_id):
        user = self.logged()

        key = db.Key.from_path('Posts', int(post_id), parent=posts_key())
        post = db.get(key)

        if not post:
            self.write("Error 404")
            return

        comment_key = db.Key.from_path('Comments', int(comment_id), parent=key)
        comment = db.get(comment_key)

        if user == comment.username or user == 'admin':
            content = self.request.get('comment')
            if content:
                content.replace('\n', '<br>')
                comment.content = content
                comment.put()
                self.redirect('/post/%s' % str(post.key().id()))
            else:
                self.redirect("""/post/%s?error=Empty
                Comment""" % str(post_id))
        else:
            self.redirect("""/post/%s?error=You can only
            edit your own comment.""" % str(post_id))


# Handler to edit post
class EditPost(Handler):
    def get(self, post_id):
        user = self.logged()
        if not user:
            self.redirect('/login')

        key = db.Key.from_path('Posts', int(post_id), parent=posts_key())
        post = db.get(key)

        if not post:
            self.write("Error 404")
            return
        if user != post.author and user != 'admin':
            self.redirect("""/post/%s?error=Cannot edit post. Only the
            owner can edit the post""" % str(post_id))
        else:
            content = post.content.replace('<br>', '\n')
            post.content = content
            self.render("edit_post.html", user=user, post=post)

    def post(self, post_id):
        user = self.logged()
        if not user:
            self.redirect("/")

        title = self.request.get("post_title")
        image_url = self.request.get("image_url")
        post_content = self.request.get("post_content")

        if (title and image_url and post_content):
            key = db.Key.from_path('Posts', int(post_id), parent=posts_key())
            post = db.get(key)

            if not post:
                self.write("Error 404")
                return
            if user != post.author and user != 'admin':
                self.redirect("""/post/%s?error=Cannot edit post.
                Only the owner can edit the post""" % str(post_id))
            else:
                post_content = post_content.replace('\n', '<br>')
                post.content = post_content
                post.imageurl = image_url
                post.title = title
                post.put()
                self.redirect('/post/%s' % str(post_id))

        else:
            error = "All fields are required"
            content = post.content.replace('<br>', '\n')
            post.content = content
            self.render("new_post.html", user=user,
                        post=post, error=error)


# Handler to delete post
class DeletePost(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Posts', int(post_id), parent=posts_key())
        post = db.get(key)
        user = self.logged()

        if not post:
            self.write("Error 404")
            return
        elif user == post.author or user == 'admin':
            post.delete()
            self.redirect('/')
        else:
            self.redirect("""/post/%s?error=Cannot delete post. Only the
            owner can delete the post""" % str(post_id))


# Handler to like post
class Like(Handler):
    def get(self, post_id):
        user = self.logged()
        key = db.Key.from_path('Posts', int(post_id), parent=posts_key())
        post = db.get(key)

        if user:
            if not post:
                self.write("Error 404, Post not found")
                return

            else:
                is_liked = self.is_liked(user, key)
                if not is_liked:
                    user = UserDB.all().filter(" username =", user).get()
                    user_id = user.key().id()
                    if post.author == self.logged():
                        self.redirect("""/post/%s?error=You cannot like
                        your own post""" % str(post_id))

                    else:
                        new_like = Likes(parent=key, userId=user_id)
                        new_like.put()
                        post.likes += 1
                        post.put()
                        self.redirect('/post/%s' % post_id)
                else:
                    is_liked.delete()
                    post.likes -= 1
                    post.put()
                    self.redirect('/post/%s' % post_id)

        else:
            self.redirect("""/post/%s?error=Please Login First to
            like the post""" % str(post_id))


class MainPage(Handler):

    def get(self):
        posts = db.GqlQuery("""SELECT * FROM Posts ORDER BY
        created DESC LIMIT 10""")
        self.render("post.html", user=self.logged(),
                    Posts=posts)


app = webapp2.WSGIApplication([
    ('/?', MainPage),
    ('/signup', Signup),
    ('/login', Login),
    ('/logout', Logout),
    ('/new', NewPost),
    ('/post/(\d+)', PostDetail),
    ('/edit/(\d+)', EditPost),
    ('/delete/(\d+)', DeletePost),
    ('/like/(\d+)', Like),
    ('/addcomment/(\d+)', AddComment),
    ('/deletecomment/(\d+)/(\d+)', DeleteComment),
    ('/editcomment/(\d+)/(\d+)', EditComment)
], debug=True)
