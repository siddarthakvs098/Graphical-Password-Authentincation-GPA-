from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, logout, login
from django.contrib.auth.models import User
from django.core.mail import EmailMessage
from graphical_pwd_auth.settings import N, TBA, EMAIL_HOST_USER, ALLOWED_HOSTS
from .models import LoginInfo
import random, uuid
import hashlib
data ={}

def get_pwd_imgs():
    # These images are just to confuse the attacker
    images = random.sample(range(1, 39), N * N)
    print(images)
    p_images = []
    for i in range(0, N * N, N):
        p_images.append(images[i:i+N])
    print(p_images)
    return p_images
    

def update_login_info(user, didSuccess):
    if didSuccess:
        user.logininfo.fails = 0
    else:
        user.logininfo.fails += 1
    
    user.logininfo.save()
    print('{} Failed attempts: {}'.format(user.username, user.logininfo.fails))


def isBlocked(username):
    try:
        user = User.objects.get(username=username)
    except Exception:
        return None
    print('isBlocked: {} - {}'.format(user.logininfo, TBA))
    if user.logininfo.fails >= TBA:
        return True
    else:
        return False


def sendLoginLinkMailToUser(username):
    user = User.objects.get(username=username)
    # send email only id user.logininfo.login_link is not None
    if user.logininfo.login_link is None:
        link = str(uuid.uuid4())
        user.logininfo.login_link = link
        user.logininfo.save()
        email = EmailMessage(
            subject='Link to Log in to your account',
            body='''
            Someone tried to bruteforce on your account.
            Click the Link to Login to your account directly.
            The link is one-time clickable
            link: http://{}:8000/login/{}
            '''.format(ALLOWED_HOSTS[-1], link), # might wanna change the allowd_host
            from_email=EMAIL_HOST_USER,
            to=[user.email],
        )
        email.send()
        print('LOGIN LINK EMAIL SENT')


def sendPasswordResetLinkToUser(username):
    # send reset link everytime user requests
    try:
        user = User.objects.get(username=username)
    except Exception:
        return False
    
    link = str(uuid.uuid4())
    user.logininfo.reset_link = link
    user.logininfo.save()
    email = EmailMessage(
        subject='Link to Rest your Password',
        body='''
        You have requested to reset your password.
        Click the Link to reset your password directly.
        The link is one-time clickable
        link: http://{}:8000/reset/{}
        '''.format(ALLOWED_HOSTS[-1], link), # might wanna change the allowd_host
        from_email=EMAIL_HOST_USER,
        to=[user.email],
    )
    email.send()
    print('PWD RESET LINK EMAIL SENT')
    return True


def home_page(request):
    return render(request, 'home.html')


def register_page(request):
    # data = {
    #         'p_images': get_pwd_imgs(),
    #     }
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        print(username, password)
        print("Hellooo")
        print("Helloo",type(password))
        print("yyyyyyyy")
        print("Post",globals()["data"])
        # for i in password:
        #     print(i+"     ")
        l = list(password.split(','))
        print(l)
        d = globals()["data"]
        print("-------")
        image_nums=[]
        print(d)
        for st in l:
            x=int(st[0])
            y=int(st[1])
            o = d['p_images'][x][y]
            image_nums.append(o)
            print(o)
        print(image_nums)
        image_nums = ["/Users/siddarthakvs/Downloads/Graphical-Password-User-Authentincation-master/static/img/pwd/"+str(x)+".png" for x in image_nums]
        print(image_nums)
        p=""
        for filename in image_nums:
            with open(filename,"rb") as f:
                bytes = f.read() # read entire file as bytes
                readable_hash = hashlib.sha256(bytes).hexdigest();
                p+=readable_hash
                print(readable_hash)
        print("Pass ", p)
        
        print("Helllllllllllll000000000000")
        try:
            # create user and loginInfo for him
            user = User.objects.create_user(email=email, username=username, password=p)
            login_info = LoginInfo(user=user, fails=0)
            login_info.save()
            messages.success(request, 'Account created successfully!')
        except Exception:
            messages.warning(request, 'Error while creating Account!')
        
        return redirect('home')
    else:
        print("Not in post")
        globals()["data"]  = {
            'p_images': get_pwd_imgs(),
        }
        
        # for i in globals()["data"]['p_images']:
        #     print(i)
    return render(request, 'register.html', context=data)


def login_page(request):
    print("Ddddddddddddddd")
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        print(username, password)
        l = list(password.split(','))
        # print(l)
        image_nums=[]
        d = globals()["data"]
        print(d)
        for st in l:
            x=int(st[0])
            y=int(st[1])
            if(not d):
                print("Globals()['data'] is empty")
            else:
                o = d['p_images'][x][y]
                image_nums.append(o)
                print(o)
        print(">>>>>>>>>>>>>>>>")
        
        # for filename in image_nums:
            # with open(filename,"rb") as F:
            #     bytes = F.read() # read entire file as bytes
            #     readable_hash = hashlib.sha256(bytes).hexdigest();
            #     p+=readable_hash
            #     print(readable_hash)
        # print("Pass ", p)image_nums = ["/Users/siddarthakvs/Downloads/Graphical-Password-User-Authentincation-master/static/img/pwd/"+str(x)+".png" for x in image_nums]
        print(image_nums)
        image_nums = ["/Users/siddarthakvs/Downloads/Graphical-Password-User-Authentincation-master/static/img/pwd/"+str(x)+".png" for x in image_nums]
        print(image_nums)
        p=""
        for filename in image_nums:
            with open(filename,"rb") as f:
                bytes = f.read() # read entire file as bytes
                readable_hash = hashlib.sha256(bytes).hexdigest();
                p+=readable_hash
                print(readable_hash)
        print("Pass ", p)
        # image_nugetms = ["/Users/siddarthakvs/Downloads/Graphical-Password-User-Authentincation-master/static/img/pwd/"+str(x)+".png" for x in image_nums]
        # print(image_nums)
        print("Hellllllllllll")
        block_status = isBlocked(username)
        if block_status is None:
            # No user exists
            messages.warning(request, 'Account doesn\'t Exist')
            return redirect('login')

        elif block_status == True:
            # Blocked - send login link to email
            # check if previously sent, if not send
            sendLoginLinkMailToUser(username)
            messages.warning(request, 'Your account is Blocked, please check your Email!')
            return redirect('login')
        else:
            # Not Blocked
            user = authenticate(username=username, password=p, request=request)
            if user is not None:
                login(request, user)
                update_login_info(user, True)
                messages.success(request, 'Login successfull!')
                return redirect('home')
            else:
                user = User.objects.get(username=username)
                update_login_info(user, False)
                messages.warning(request, 'Login Failed!')
                return redirect('login')

    else:
        globals()["data"] = {
            'p_images': get_pwd_imgs(),
        }
        print(globals()["data"])
        
    return render(request, 'login.html', context=data)


def login_from_uid(request, uid):
    try:
        # get user from the uid and reset the Link to 'NO_LINK' again
        login_info = LoginInfo.objects.get(login_link=uid)
        user = login_info.user
        login(request, user)
        update_login_info(user, True)
        login_info.login_link = None
        login_info.save()
        messages.success(request, 'Login successfull!')
    except Exception:
        messages.warning(request, 'Invalid Link. Please check again!')

    return redirect('home')


def reset_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        print(username)
        if sendPasswordResetLinkToUser(username):
            messages.success(request, 'Password Reset Link sent to you email!')
        else:
            messages.warning(request, 'User doesn\'t exist!')
        return redirect('home')
    else:
        return render(request, 'reset_request.html')


def reset_from_uid(request, uid):
    print('hello')
    if request.method == 'POST':
        print('hi-post')
        password = request.POST['password']
        try:
            # get user from the uid and reset the Link to 'NO_LINK' again
            login_info = LoginInfo.objects.get(reset_link=uid)
            user = login_info.user
            # reset pwd
            user.set_password(password)
            login_info.reset_link = None
            login_info.save()
            user.save()
            messages.success(request, 'Password Changed Successfully!')
        except Exception:
            messages.warning(request, 'Invalid Link. Please check again!')
        return redirect('home')
    else:
        print('hi-else')
        try:
            # To make sure the link is valid
            print(uid)
            login_info = LoginInfo.objects.get(reset_link=uid)
            data = {
                'p_images': get_pwd_imgs(),
            }
            return render(request, 'reset.html', context=data)
        except Exception:
            messages.warning(request, 'Invalid Link. Please check again!')
            return redirect('home')


def logout_page(request):
    logout(request)
    messages.warning(request, 'You\'ve been logged out!')
    return redirect('home')

