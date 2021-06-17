from django.urls import path
from main import views

urlpatterns = [
    path('', views.homepage, name='home'),
    path('login/', views.login_page, name='login'),
    path('logout/', views.logoutpage, name='logout'),
    path('logger/', views.logger_page, name='logger'),
    path('change_password/', views.my_view, name='change_pass'),
    path('create', views.api_create_log_view, name="create"),
    # path('demo_site', views.demo_site, name="demo"),
    path('demo_site', views.demo_setting, name="setting"),
    path('demo_site/xss', views.demo_xss, name="demo_xss"),
    #path('demo_site/xss/dom', views.demo_xss_dom, name="demo_xss_dom"),
    path('demo_site/sql', views.demo_sql, name="sql_demo"),
    path('demo_site/search', views.search, name="search"),
    path('demo_site/index', views.index, name="index"),
    path('export_logger_csv/', views.export_logger_csv, name="export"),
    path('demo_site/xss/output', views.xss_output, name="xss_output"),
]