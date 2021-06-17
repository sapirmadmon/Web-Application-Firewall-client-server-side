import csv
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt, csrf_protect

from DBwaf.user import validation_email, check_strong_password
from main.models import Logger, UsersDemo, User_value, FlagWaf
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from main.Serializers import LogPostSerializer
from datetime import datetime
from connectionWithDockerModel.main import xss_proccesor, predict_sqli_attack
from django.template import loader
from django.db.models import Q

from django.core.cache import cache

regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
XSS_THRESHOLD = 0.45
SQL_THRESHOLD = 0.5
waf = FlagWaf()

def set_waf_flag_cookie(request):
    print("COOKIES: ",request.COOKIES)
    select = request.POST.get('radio')
    print('#set_waf_flag_cookie#')
    if request.session['waf_flag'] is None or select == 'no_protection':
        request.session['waf_flag'] = False
        print("request.user: ",request.user)
        request.session['threshold_xss'] = XSS_THRESHOLD
        request.session['threshold_sql'] = SQL_THRESHOLD
        waf.flag_waf = False
        request.session.save()
        #for key, value in request.session.items(): print('{} => {}'.format(key, value))

    elif select == 'protection':  # run the WAF system
        request.session['waf_flag'] = True
        waf.flag_waf = True
        #flag.flag_waf = True
        if request.POST.get('threshold_xss') != '':
            request.session['threshold_xss'] = request.POST.get('threshold_xss')
        if request.POST.get('threshold_sql') != '':
            request.session['threshold_sql'] = request.POST.get('threshold_sql')
        request.session.save()
        print('Request[waf_flag]=True')
        #for key, value in request.session.items(): print('{} => {}'.format(key, value))

    return request


def export_logger_csv(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="logger.csv"'

    writer = csv.writer(response)
    writer.writerow(['Email', 'Date', 'Threshold', 'Type Attack', 'Command', 'If Warn'])

    log = Logger.objects.all().values_list('email', 'date', 'threshold', 'type_attack', 'command', 'if_warn')
    for l in log:
        writer.writerow(l)

    return response


def demo_site(request):
    return render(request, template_name='main/base_demo_site.html')


def demo_setting(request):
    context = {}
    try:
        request = set_waf_flag_cookie(request)
    except:
        request.session['waf_flag'] = None
        request.session.save()
        request = set_waf_flag_cookie(request)

    if request.method == 'GET':
        if request.session['waf_flag'] is True:
            context = {'message_waf': 'The site is protected by WAF'}
        else:
            context = {'message_waf': 'The site is unprotected by WAF'}

        return render(request, 'main/setting_demo.html', context)

    if request.method == 'POST':

        if request.session['waf_flag'] is False:  # don't run the WAF system
            messages.success(request, "The site is unprotected now by WAF")
            context = {'message_waf': 'The site is unprotected by WAF'}
        elif request.session['waf_flag'] is True:  # run the WAF system
            messages.success(request, "The site is protected now by WAF")
            context = {'message_waf': 'The site is protected by WAF'}

    return render(request, 'main/setting_demo.html', context)


def if_text_vulnerable(text, request):
    res = xss_proccesor(text)
    cur_email = request.user.get_username()

    if res > float(request.session['threshold_xss']):
        Logger.objects.create(
            email=cur_email, date=datetime.now(), threshold=res * 100,
            type_attack="Reflected XSS", command=text, if_warn=True)
        print('save true XSS to logger ****')
        return True

    else:
        Logger.objects.create(
            email=cur_email, date=datetime.now(), threshold=res * 100,
            type_attack="Reflected XSS", command=text, if_warn=False)
        print('save false XSS to logger ****')
        return False


# def if_text_vulnerable_dom(text):
#
#     print('into method if_text_vulnerable_dom')
#     res = xss_proccesor(text)
#     cur_email = 'Client'
#     if res > float(request.session['threshold_xss']):
#         save_to_log = Logger.objects.create(
#             email=cur_email, date=datetime.now(), threshold=res*100,
#             type_attack="Reflected XSS", command=text, if_warn=True)
#         print('save true XSS to logger ****')
#         return True
#
#     else:
#         save_to_log = Logger.objects.create(
#             email=cur_email, date=datetime.now(), threshold=res*100,
#             type_attack="Reflected XSS", command=text, if_warn=False)
#         print('save false XSS to logger ****')
#         return False

def if_text_vulnerable_sql(text, request):
    res = predict_sqli_attack(text)
    cur_email = request.user.get_username()
    print(res, "sql result")
    if res > float(request.session['threshold_sql']):
        Logger.objects.create(
            email=cur_email, date=datetime.now(), threshold=res * 100,
            type_attack="SQL", command=text, if_warn=True)
        print('save true SQL to logger ****')
        return True
    else:
        Logger.objects.create(
            email=cur_email, date=datetime.now(), threshold=res * 100,
            type_attack="SQL", command=text, if_warn=False)
        print('save false SQL to logger ****')
        return False


@csrf_exempt
def my_view(request):
    @csrf_protect
    def change_password_protected(request):
        print("*change_password_protected*")
        if request.method == 'GET':
            return render(request, template_name='main/change_password.html')

        elif request.method == 'POST':
            new_pss = request.POST.get('new_pass')
            if check_strong_password(new_pss) is False:
                messages.error(request, 'The password must contain: '
                                        'alphabets between [a-z],'
                                        'At least one alphabet of Upper Case [A-Z],'
                                        'At least 1 number or digit between [0-9],'
                                        'At least 1 special character.')
                return redirect('change_pass')
            else:
                print("User name!!")
                print(cache.get('user'))
                u = User.objects.get(username=cache.get('user'))
                u.set_password(new_pss)
                u.save()
                messages.success(request, "Password changed! login again with the new password")
                cur_email = cache.get('user')
                Logger.objects.create(
                email=cur_email, date=datetime.now(), threshold=None,
                type_attack="CSRF", command='CSRF attack attempt', if_warn=True)
                cache.delete('user')
                logout(request)
                return render(request, template_name='main/home.html')
    print('request flag waf is: ', waf.flag_waf)
    if waf.flag_waf is True:
        return change_password_protected(request)

    else:
        return change_password(request)


def change_password(request):
    print("*change_password*")
    if request.method == 'GET':
        return render(request, template_name='main/change_password.html')

    elif request.method == 'POST':
        new_pss = request.POST.get('new_pass')
        if check_strong_password(new_pss) is False:
            messages.error(request, 'The password must contain: '
                                    'alphabets between [a-z],'
                                    'At least one alphabet of Upper Case [A-Z],'
                                    'At least 1 number or digit between [0-9],'
                                    'At least 1 special character.')
            return redirect('change_pass')
        else:
            print("User name!!")
            print(cache.get('user'))
            u = User.objects.get(username=cache.get('user'))
            u.set_password(new_pss)
            u.save()
            messages.success(request, "Password changed! login again with the new password")
            logout(request)
            cache.delete('user')
            return render(request, template_name='main/home.html')


def demo_sql(request):
    context = {}

    if request.method == 'GET':
        if request.session['waf_flag'] is True:
            context = {'message_waf': 'The site is protected by WAF'}
        else:
            context = {'message_waf': 'The site is unprotected by WAF'}
        return render(request, 'main/sql_demo.html', context)

    if request.method == 'POST':

        user_name = request.POST.get('username')
        user_password = request.POST.get('password')

        # cur_user = UsersDemo.objects.raw('SELECT * FROM main_usersDemo WHERE username = %s
        # AND password = %s', [user_name,user_password])
        sql = f"SELECT * FROM main_usersDemo WHERE username = '{user_name}' AND password = '{user_password}'"
        print(sql)

        if request.session['waf_flag'] is True:
            context = {'message_waf': 'The site is protected by WAF'}
            print('start Sql injection *with* WAF')
            res_userName = if_text_vulnerable_sql(user_name, request)
            res_userPassword = if_text_vulnerable_sql(user_password, request)

            if res_userName or res_userPassword:
                messages.error(request, "sql injection!")
                return render(request, 'main/sql_demo.html', context)
            else:
                cur_user = UsersDemo.objects.raw(sql)
        else:
            context = {'message_waf': 'The site is unprotected by WAF'}
            print('start Sql injection *without* WAF')
            cur_user = UsersDemo.objects.raw(sql)
        try:
            print('user found! username: ', cur_user[0].username, ' pass: ', cur_user[0].password)
            messages.success(request, "user found")
        except IndexError:
            messages.error(request, "user not found")
            print('user *not* found! username: ', user_name, ' pass: ', user_password)
        except Exception as e:
            print(e.__class__)
            return render(request, 'main/sql_demo.html', context)
            # pass  # no rows returned

        return render(request, 'main/sql_demo.html', context)


def homepage(request):
    return render(request, template_name='main/home.html')


def logger_page(request):
    current_email = request.user.get_username()
    if request.method == 'GET':
        loggers = Logger.objects.filter(email=current_email)
        return render(request, template_name='main/logger.html', context={'loggers': loggers})

    if request.method == 'POST':
        select_attack_type = request.POST.get('radio')
        select = request.POST.get('if_alerted')

        if select == 'on':
            loggers1 = Logger.objects.filter(email=current_email, if_warn=True)
        else:
            loggers1 = Logger.objects.filter(email=current_email)

        if select_attack_type == 'sqli':
            loggers1_sql = loggers1.filter(type_attack='SQL')
            return render(request, template_name='main/logger.html', context={'loggers': loggers1_sql})
        elif select_attack_type == 'xss':
            loggers1_xss = loggers1.filter(
                Q(type_attack='Reflected XSS') | Q(type_attack='Stored XSS') | Q(type_attack='Dom XSS'))
            return render(request, template_name='main/logger.html', context={'loggers': loggers1_xss})
        elif select_attack_type == 'csrf':
            loggers1_csrf = loggers1.filter(type_attack='CSRF')
            return render(request, template_name='main/logger.html', context={'loggers': loggers1_csrf})

        return render(request, template_name='main/logger.html', context={'loggers': loggers1})


# Log json example:
# {
# 	"email":"user1@gmail.com",
#  	"date": "2021-03-13",
# 	"threshold":85,
# 	"type_attack":"XSS",
# 	"command":"dfgfhgf",
# 	"if_warn": true
# }
@api_view(['POST'])
def api_create_log_view(request):
    if request.method == 'POST':
        serializer = LogPostSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def login_page(request):
    if request.method == 'GET':
        return render(request, template_name='main/login.html')

    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        if validation_email(email) is False:
            messages.error(request, 'email must be in the format of example@example.com')
            return redirect('login')

        elif check_strong_password(password) is False:
            messages.error(request, 'The password must contain: '
                                    'alphabets between [a-z],'
                                    'At least one alphabet of Upper Case [A-Z],'
                                    'At least 1 number or digit between [0-9],'
                                    'At least 1 special character.')
            return redirect('login')

        # else:
        #user_session.user = authenticate(username=email, password=password)
        cache.set('user',authenticate(username=email, password=password))
        print(cache.get('user'))
        if cache.get('user') is not None:

            login(request, cache.get('user'))
            messages.success(request, f'You are logged in as {cache.get("user")}')
            return redirect('home')

        else:
            messages.error(request, 'The combination of the user name and the password is wrong!')
            return redirect('login')


def logoutpage(request):
    logout(request)
    cache.delete('user')
    messages.success(request, f'You have been logged out!')
    return redirect('home')


# help methods
# def check_strong_password(password):
#     # Primary conditions for password validation :
#         # Minimum 8 characters.
#         # The alphabets must be between [a-z]
#         # At least one alphabet should be of Upper Case [A-Z]
#         # At least 1 number or digit between [0-9].
#         # At least 1 special character
#
#     if len(password) >= 8:
#         if not re.search("[a-z]", password):
#             return False
#         elif not re.search("[0-9]", password):
#             return False
#         elif not re.search("[A-Z]", password):
#             return False
#         elif not re.search("[@_!#$%^&*()<>?/\|}{~:]", password):
#             return False
#         elif re.search("\s", password):
#             return False
#         else:
#             return True  # Valid Password
#     else:
#         print("Password must be at least 8 characters long")
#         return False
#
#
# def validation_email(email):
#     # pass the regular expression and the string in search() method
#     if re.search(regex, email):
#         return True
#     else:
#         return False


def index(request):
    return render(request, 'form.html')


def if_text_vulnerable_xss_from_resonse(text, username, request):
    res = xss_proccesor(str(text))
    cur_email = username
    if res > float(request.session['threshold_xss']):
        Logger.objects.create(
            email=cur_email, date=datetime.now(), threshold=res * 100,
            type_attack="Stored XSS", command=text, if_warn=True)
        return True
    else:
        Logger.objects.create(
            email=cur_email, date=datetime.now(), threshold=res * 100,
            type_attack="Stored XSS", command=text, if_warn=False)
        return False


def search(request):
    try:
        if request.method == 'GET':
            from django.contrib.auth.models import User

            all_users = list(User.objects.values())
            if request.session['waf_flag'] is True:
                desired_keys = ["username", "first_name", "last_name", "email"]
                for user in all_users:
                    for key, value in user.items():
                        if key in desired_keys and len(value) > 0:
                            if if_text_vulnerable_xss_from_resonse(value, user['username'], request) is True:
                                user[key] = 'XSS ATTACK'
                return render(request, 'main/form.html', {'users': all_users,
                                                          'message_waf': 'The site is protected by WAF'})
            else:
                return render(request, 'main/form.html', {'users': all_users,
                                                          'message_waf': 'The site is unprotected by WAF'})

    except Exception as e:
        print(e.__class__)
        return HttpResponse(e.__class__)


def xss_output(request):
    if request.method == 'GET':
        return render(request, template_name='main/xss_demo_output.html')


def demo_xss(request):
    if request.method == 'GET':
        if request.session['waf_flag'] is True:
            context = {'message_waf': 'The site is protected by WAF'}
        else:
            context = {'message_waf': 'The site is unprotected by WAF'}

        return render(request, 'main/xss_demo.html', context)

    if request.method == 'POST':
        print(request.POST)
        search_id: object = request.POST.get('txtName')

        if request.session['waf_flag'] is True:
            if if_text_vulnerable(search_id, request) is True:
                context = {'text': "XSS ATTACK", 'message_waf': 'The site is protected by WAF'}
                template = loader.get_template('main/xss_demo_output.html')
                return HttpResponse(template.render(context, request))
            else:
                html = search_id
                context = {'text': html, 'message_waf': 'The site is protected by WAF'}
                return render(request, 'main/xss_demo_output.html', context)
        else:
            html = search_id
            context = {'text': html, 'message_waf': 'The site is unprotected by WAF'}
            return render(request, 'main/xss_demo_output.html', context)

# def demo_xss_dom(request):
#     context = {}
#
#     if request.method == 'GET':
#         if get_flag_waf() is True:
#             context = {'message_waf': 'The site is protected by WAF'}
#             #predict_sqli_attack()
#             #xss_proccesor()
#             list = (scancoomandsfromfile.makeCommands())
#             print(list)
#             for l in list:
#                 if len(l)>1:
#                     xss_res = if_text_vulnerable_dom(l)
#                     if xss_res:
#                         Logger.objects.create(
#                             email='client', date=datetime.now(), threshold=xss_res * 100,
#                             type_attack="Dom XSS", command=l, if_warn=True)
#                         print(l +" = XSS ATTACK")
#         else:
#             context = {'message_waf': 'The site is unprotected by WAF'}
#
#         return HttpResponse(request, context)
