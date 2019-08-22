from django.shortcuts import render, redirect, HttpResponse
from django.contrib import messages
from apps.user_dashboard_app.models import *
import bcrypt

# Create your views here.
def index(request) :
    return render(request, "user_dashboard_app/index.html")


# login page
def login(request) :
    return render(request, "user_dashboard_app/login.html")

# logout
def logout(request) :
    request.session.clear()
    return redirect('/')

# login validate
def login_validate(request) :
    email = request.POST['email']
    try :
        user = User.objects.get(email=email)
        if bcrypt.checkpw(request.POST['password'].encode(), user.password.encode()) :
            # print ("here")
            request.session['user_id'] = user.id
            request.session['user_fname'] = user.first_name
            request.session['user_lname'] = user.last_name
            request.session['user_level'] = user.user_level
            # messages.add_message(request, messages.SUCCESS, 'Successfully logged in!')

            # go to appropriate dashboard according to their user_level
            if (user.user_level == 9) : # 9 : admin
                return redirect('/dashboard/admin')
            else : # normal user    
                return redirect('/dashboard')
        else :
            messages.add_message(request, messages.ERROR, 'Invalid user information - not correct password', extra_tags='login')
    except :
        print ("you're here")
        messages.add_message(request, messages.ERROR, 'Invalid user information', extra_tags='login')
    return redirect('/login')

# register page
def register(request) :
    return render(request, "user_dashboard_app/register.html")

# register validate
def register_validate(request) :
    errors = User.objects.validator(request.POST) 
    if (len(errors) > 0) :
        for key, val in errors.items() :
            messages.add_message(request, messages.ERROR, val, extra_tags='register')
        temp_inputs={"first_name":request.POST['first_name'],
                    "last_name":request.POST['last_name'],
                    "email":request.POST['email']}
        request.session['temp_inputs'] = temp_inputs

        return redirect('/register')
    else :
        # create user
            # first user? => admin
        user_level = 1 # only 9 is admin
        if len(User.objects.all()) == 0 :
            user_level = 9
        # description ?
        description = ""
        if 'description' in request.POST :
            description = request.POST['description']
        hashed_pw = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
        user = User.objects.create(first_name=request.POST['first_name'],
                                    last_name=request.POST['last_name'],
                                    email=request.POST['email'],
                                    password=hashed_pw,
                                    description=description,
                                    user_level=user_level,
                                    )
        # login this user
        messages.add_message(request, messages.SUCCESS, "Successfully registered!")
        request.session['user_id'] = user.id
        request.session['user_fname'] = user.first_name
        request.session['user_lname'] = user.last_name
        request.session['user_level'] = user.user_level

        # go to appropriate dashboard according to their user_level
        if (user.user_level == 9) : # 9 : admin
            return redirect('/dashboard/admin')
        else : # normal user    
            return redirect('/dashboard')

    # return redirect('/register')


# dashboard_admin
def dashboard_admin(request) :
    if 'user_id' not in request.session.keys() :
        return redirect('/')

    if request.session['user_level'] != 9 :
        return redirect('/dashboard')

    users = User.objects.all()
    context = {"users":users}
    return render(request, "user_dashboard_app/dashboard_admin.html", context)

# admin - edit user
def user_edit(request, user_id) :
    if 'user_id' not in request.session.keys() :
        return redirect('/')
    user = User.objects.get(id=user_id)
    context = {"user" : user}
    return render(request, "user_dashboard_app/edit_user_admin.html", context)

# admin - edit user - form
def edit_user_info_admin(request, user_id) :
    if 'user_id' not in request.session.keys() :
        return redirect('/')
    # edit and reroute with msg
    user = User.objects.get(id=user_id)
    user.email = request.POST['email']
    user.first_name = request.POST['first_name']
    user.last_name = request.POST['last_name']
    if (request.POST['user_level'] == "Admin") :
        user.user_level = 9
    else :
        user.user_level = 1
    user.save()
    messages.add_message(request, messages.SUCCESS, "user information updated successfully", extra_tags="register")
    
    return redirect(f"/users/edit/{user_id}")

# admin - change user password - from
def change_user_pw_admin(request, user_id) :
    if 'user_id' not in request.session.keys() :
        return redirect('/')
    # change pw and reroute with ms
    password = request.POST['password']
    confirm_password = request.POST['confirm_password']
    if (len(password) < 8) :
        messages.add_message(request, messages.ERROR, "Password should be at least 8 characters", extra_tags="change_pw")
    elif (confirm_password != password) :
        messages.add_message(request, messages.ERROR, "Password should match!", extra_tags="change_pw")
    else :
        # update password
        hashed_pw = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
        user = User.objects.get(id=user_id)
        user.password = hashed_pw
        user.save()
        messages.add_message(request, messages.SUCCESS, "Password updated successfully.", extra_tags="change_pw")
    
    return redirect(f"/users/edit/{user_id}")

# admin - remove user
def user_delete(request, user_id) :
    if 'user_id' not in request.session.keys() :
        return redirect('/')
    # delete - ask one more
    
    User.objects.get(id=user_id).delete()
    return redirect('/dashboard/admin')

# admin - add new user
def add_new_user(request) :
    if 'user_id' not in request.session.keys() :
        return redirect('/')
    return render(request, "user_dashboard_app/new_user_admin.html")

# admin - add new user method
def add_new_user_admin(request) :
    if 'user_id' not in request.session.keys() :
        return redirect('/')
    errors = User.objects.validator(request.POST) 
    if (len(errors) > 0) :
        for key, val in errors.items() :
            messages.add_message(request, messages.ERROR, val, extra_tags='register')
        temp_inputs={"first_name":request.POST['first_name'],
                    "last_name":request.POST['last_name'],
                    "email":request.POST['email']}
        request.session['temp_inputs'] = temp_inputs
        return redirect('/users/new')
    else :
        # create user
            # first user? => admin
        user_level = 1 # only 9 is admin
        if len(User.objects.all()) == 0 :
            user_level = 9
        # description ?
        description = ""
        if 'description' in request.POST :
            description = request.POST['description']
        hashed_pw = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
        user = User.objects.create(first_name=request.POST['first_name'],
                                    last_name=request.POST['last_name'],
                                    email=request.POST['email'],
                                    password=hashed_pw,
                                    description=description,
                                    user_level=user_level,
                                    )
        return redirect('/dashboard/admin')


# dashboard_normal
def dashboard_normal(request) :
    if 'user_id' not in request.session.keys() :
        return redirect('/')
    users = User.objects.all()
    context = {"users":users}
    return render(request, "user_dashboard_app/dashboard_normal.html", context)


# normal user - edit profile
def user_edit_profile(request) :
    if 'user_id' not in request.session.keys() :
        return redirect('/')
    user = User.objects.get(id=request.session['user_id'])
    context = {"user":user}
    return render(request, "user_dashboard_app/edit_profile_normal.html", context)

# normal user - edit profile <- form
def user_edit_profile_normal(request, user_id) :
    if 'user_id' not in request.session.keys() :
        return redirect('/')

    # edit and reroute with msg
    user = User.objects.get(id=user_id)
    user.email = request.POST['email']
    user.first_name = request.POST['first_name']
    user.last_name = request.POST['last_name']
    user.save()
    messages.add_message(request, messages.SUCCESS, "user information updated successfully", extra_tags="register")
    
    return redirect(f"/users/edit")

# edit profile - change pw - normal user
def user_change_pw_normal(request, user_id) :
    if 'user_id' not in request.session.keys() :
        return redirect('/')
    # change pw and reroute with ms
    password = request.POST['password']
    confirm_password = request.POST['confirm_password']
    if (len(password) < 8) :
        messages.add_message(request, messages.ERROR, "Password should be at least 8 characters", extra_tags="change_pw")
    elif (confirm_password != password) :
        messages.add_message(request, messages.ERROR, "Password should match!", extra_tags="change_pw")
    else :
        # update password
        hashed_pw = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
        user = User.objects.get(id=user_id)
        user.password = hashed_pw
        user.save()
        messages.add_message(request, messages.SUCCESS, "Password updated successfully.", extra_tags="change_pw")
    
    return redirect(f"/users/edit")

# edit profile - change description -normal user
def user_update_desc_normal(request, user_id) :
    if 'user_id' not in request.session.keys() :
        return redirect('/')
    user = User.objects.get(id=user_id)
    user.description = request.POST['description']
    user.save()

    messages.add_message(request, messages.SUCCESS, "user description updated successfully", extra_tags="description")
    return redirect(f"/users/edit")

# show profile of user
def show_profile(request, user_id) :
    if 'user_id' not in request.session.keys() :
        return redirect('/')
    user = User.objects.get(id=user_id)
    
    context = {"user" : user
                }
    return render(request, "user_dashboard_app/show_profile.html", context)


# send message to profile of user from currently logged in user
def send_message(request, user_id) :
    if 'user_id' not in request.session.keys() :
        return redirect('/')
    user_from = User.objects.get(id=user_id)
    user_to = User.objects.get(id=request.session['user_id'])
    content = request.POST['message']
    Message.objects.create(user_to=user_to, user_from=user_from, content=content)
    return redirect(f"/users/show/{user_id}")

# send comment to a message
def send_comment(request, message_id, user_id) :
    if 'user_id' not in request.session.keys() :
        return redirect('/')
    message = Message.objects.get(id=message_id)
    comment = Comment.objects.create(
                            content=request.POST['comment'],
                            user_commented = User.objects.get(id=request.session['user_id']),
                            message = message
                            )
    return redirect(f"/users/show/{user_id}")