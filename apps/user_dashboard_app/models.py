from django.db import models
import re
from django.utils import timezone

# Create your models here.
class UserManager(models.Manager) :
    def validator(self, postData) :
        errors = {}

        # email : required, valid Pattern,
        email = postData['email']
        if (len(email) == 0) :
            errors['email'] = "Email field is required"
        else :
            EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9.+_-]+\.[a-zA-z]+$')
            if not EMAIL_REGEX.match(email) :
                errors['email'] = "Email should be valid format"
            else : # check uniqueness
                users = User.objects.filter(email=email)
                if (len(users) > 0) :
                    errors['email'] = "Email already exists"

        # first_name : required, at least 2 characters,
        first_name = postData['first_name']
        if (len(first_name) == 0) :
            errors['first_name'] = "First Name field is required"
        elif (len(first_name) < 2) :
            errors['first_name'] = "First Name should be at least 2 characters"

        # last_name : required, at least 2 characters,
        last_name = postData['last_name']
        if (len(last_name) == 0) :
            errors['last_name'] = "Last Name field is required"
        elif (len(last_name) < 2) :
            errors['last_name'] = "Last Name should be at least 2 characters"

        # password : required, at least 8 character, matching pair
        password = postData['password']
        if (len(password) == 0) :
            errors['password'] = "Password field is required"
        elif (len(password) < 8) :
            errors['password'] = "Password should be at least 8 characters"
        else :
            confirm_pw = postData['confirm_password']
            if (not password == confirm_pw) :
                errors['confirm_password'] = "Password should match!"

        return errors

class User(models.Model) :
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    description = models.TextField()
    user_level = models.IntegerField()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()

class MessageManager(models.Manager) :
    def validator(self, postData) :
        errors = {}

        # content
        content = postData['message']
        if (len(content) < 5) :
            errors['message'] = "Message content should be at least 5 characters"

        return errors

class Message(models.Model) :
    content = models.TextField()
    user_from = models.ForeignKey(User, related_name="messages_received")
    user_to = models.ForeignKey(User, related_name="messages_sent")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = MessageManager()

class CommentManager(models.Manager) :
    def validator(self, postData) :
        errors = {}

        # content
        content = postData['comment']
        if (len(content) < 5) :
            errors['message'] = "Comment content should be at least 5 characters"

        return errors

class Comment(models.Model) :
    content = models.TextField()
    message = models.ForeignKey(Message, related_name="comments")
    user_commented = models.ForeignKey(User, related_name="comments_posted")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = CommentManager()