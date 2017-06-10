from google.appengine.ext import ndb

class Post(ndb.Model):
    post_title = ndb.StringProperty(required = True)
    post_content = ndb.TextProperty(required = True)
    post_author = ndb.StringProperty(required = True)
    post_created = ndb.DateTimeProperty(auto_now_add = True)
    post_last_updated = ndb.DateTimeProperty(auto_now = True)

    @classmethod
    def addPost(cls, title, content, author):
        p = Post(post_title = title, post_content = content,
                 post_author = author)
        p.put()
        return p.key.id()

    @classmethod
    def editPost(cls, title, content, author, post_id):
        post = Post.get_by_id(int(post_id))
        if post:
            if post.post_author == author:
                post.post_title = title
                post.post_content = content
                post.put()
                return post.key.id()

    @classmethod
    def getPost(cls, post_id):
        return Post.get_by_id(int(post_id))

    @classmethod
    def deletePost(cls, post_id):
        post = Post.get_by_id(int(post_id))
        if post:
            post.key.delete()
            return True
        else:
            return False

#ndb.delete_multi(Post.query().fetch(keys_only=True))



class User(ndb.Model):
    user_name = ndb.StringProperty(required = True)
    user_password_hash = ndb.TextProperty(required = True)

    @classmethod
    def addUser(cls, name, password_hash):
        u = User(user_name = name, user_password_hash = password_hash)
        u.put()
        return u.key.id()

    @classmethod
    def getUserByName(cls, name):
        user = User.query(User.user_name==name).fetch(1)
        for u in user:
            return u
            
    @classmethod
    def getUserById(cls, user_id):
        return User.get_by_id(int(user_id))

    @classmethod
    def getUserByNameAndPassword(cls, name, password_hash):
        user = User.query(User.user_name==name).fetch(1)
        for u in user:
            if u.user_password_hash == password_hash:
                return u
            else:
                return False

    @classmethod
    def getUserId(cls, user):
        return user.key.id()


class LikePost(ndb.Model):
    like_post = ndb.StringProperty(required = True)
    like_author = ndb.StringProperty(required = True)
    like_create = ndb.DateTimeProperty(auto_now_add = True)

    @classmethod
    def addLike(cls, post_id, author):
        l = LikePost(like_post = str(post_id),
                     like_author = str(author))
        l.put()
        return l.key.id()

    @classmethod
    def getLikeByPostAndAuthor(cls, post_id, author):
        likes = LikePost.query(LikePost.like_post == post_id and 
                               LikePost.like_author == author).fetch(1)
        for l in likes:
            return l

    @classmethod
    def countByPost(cls, post_id):
        likes = LikePost.query(LikePost.like_post == post_id)
        return likes.count()

    @classmethod
    def deleteLike(cls, like_id):
        like = LikePost.get_by_id(int(like_id))
        if like:
            like.key.delete()
            return True
        else:
            return False



class Comment(ndb.Model):
    comment_post = ndb.StringProperty(required = True)
    comment_text = ndb.StringProperty(required = True)
    comment_author = ndb.StringProperty(required = True)
    comment_created = ndb.DateTimeProperty(auto_now_add = True)

    @classmethod
    def getCommentsByPostId(cls, post_id):
        return Comment.query(Comment.comment_post==post_id)

    @classmethod
    def getComment(cls, comment_id):
        return Comment.get_by_id(int(comment_id))

    @classmethod
    def addComment(cls, post_id, text, author):
        c= Comment(comment_post = str(post_id), 
                   comment_text = str(text), 
                   comment_author = str(author))
        c.put()
        return c.key.id()

    @classmethod
    def deleteComment(cls, comment_id):
        comment = Comment.get_by_id(int(comment_id))
        if comment:
            comment.key.delete()
            return True
        else:
            return False