from google.appengine.ext import db
from google.appengine.api import users

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    country = db.StringProperty(required = True)
    month = db.StringProperty(required = True)
    day = db.StringProperty(required = True)
    year =db.StringProperty(required = True)
  
  
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u
    
    @classmethod
    def by_email(cls, email):
        e = User.all().filter('email =', email).get()
        return e

    @classmethod
    def register(cls, name, pw, email = None, country = None, month = None, day = None, year = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email,
                    country = country,
                    month = month,
                    day = day,
                    year = year)
	

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
        	return u