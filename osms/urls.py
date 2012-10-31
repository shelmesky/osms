#from django.conf.urls.defaults import patterns, include, url
# coding: utf-8
from django.conf.urls.defaults import *


# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = patterns('views',
    (r'^$','login_page'),
    (r'^logout/$','logout_page'),
)

urlpatterns += patterns('admins.views',
    (r'^admins/$','admin.index'),
    (r'^admins/right/$','admin.right'),
    (r'^admins/left/$','admin.left'),
    (r'^device/$','device.device_view'),
    (r'^device/search/$','device.device_search'),
    (r'^device/adddev/$','device.device_add'),
    (r'^device/deldev/$','device.device_del'),
    (r'^device/chndev/$','device.device_change'),
    (r'^system/$','system.system_main'),
    (r'^system/status/$','system.system_status'),
    (r'^system/run_command/$','system.system_run_command'),
    (r'^system/auto_install/$','system.system_autoinstall'),
    (r'^system/auto_install_status/$','system.system_autoinstall_status'),
    (r'^system/auto_install_package/$','system.system_autoinstall_package_management'),
    (r'^system/cron/$','system.system_cron'),
    (r'^system/shutdown/$','system.system_shutdown'),
    (r'^system/action/(\w+)/(.*)/$','system.system_action'),
    (r'^system/whois/$','system.system_whois'),
    (r'^system/dig/$','system.system_dig'),
    (r'^useradd/$','user.useradd'),
    (r'^usermgm/$','user.usermgm'),
    (r'^userdel/$','user.userdel'),
    (r'^userchpasswd/$','user.change_password'),
)
