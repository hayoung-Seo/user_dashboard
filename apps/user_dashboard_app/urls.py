from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index),
    url(r'^login$', views.login),
    url(r'^register$', views.register),
    url(r'^logout$', views.logout),

    url(r'^login_validate$', views.login_validate),
    url(r'^register_validate$', views.register_validate),

    url(r'^dashboard/admin$', views.dashboard_admin),
    url(r'^dashboard$', views.dashboard_normal),

    url(r'^users/edit/(?P<user_id>\d+)$', views.user_edit),
    url(r'^users/delete/(?P<user_id>\d+)$', views.user_delete),
    url(r'^users/new$', views.add_new_user),
    url(r'^add_new_user_admin$', views.add_new_user_admin),
    url(r'^edit_user_info/admin/(?P<user_id>\d+)$', views.edit_user_info_admin),
    url(r'^change_user_pw/admin/(?P<user_id>\d+)$', views.change_user_pw_admin),

    url(r'^users/edit$', views.user_edit_profile),
    url(r'^edit_profile/(?P<user_id>\d+)$', views.user_edit_profile_normal),
    url(r'^change_pw/(?P<user_id>\d+)$', views.user_change_pw_normal),
    url(r'^edit_description_normal/(?P<user_id>\d+)$', views.user_update_desc_normal),

    url(r'^users/show/(?P<user_id>\d+)$', views.show_profile),

    url(r'^send_message/(?P<user_id>\d+)$', views.send_message),
    url(r'^send_comment/(?P<message_id>\d+)/(?P<user_id>\d+)$', views.send_comment)
]