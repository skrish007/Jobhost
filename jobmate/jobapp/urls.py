from . import views
from django.urls import path
from django.conf.urls.static import static
from django.contrib.auth.views import LoginView
from django.urls import path, include
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('',views.home,name='home'),
    path('home',views.home,name='home'),
    path('login', views.login_view, name='login'),
    path('userdash', views.success_view, name='userdash'),
    path('companydash', views.success_view, name='companydash'),
    path('admindash', views.success_view, name='admindash'),
    
    path('register',views.register,name='register'),
    path('companyreg',views.companyreg,name='companyreg'),
    path('logout', views.logout_view, name='logout'),
    path('seekerpro', views.seekerpro, name='seekerpro'),
    path('search', views.search_seeker, name='search-view'),
    path('search2', views.search_jobs, name='search-view2'),
    path('search3', views.search_loc, name='search-view3'),

    # URL pattern for the 'seeker_profile_update' view
    path('seekerupdate', views.seeker_profile_update, name='seekerupdate'),
    path('providerpro', views.providerpro, name='providerpro'),

    path('provider_profile_update', views.provider_profile_update, name='provider_profile_update'),
    path('verification_pending', views.verification_pending, name='verification_pending'),
    
    path('ad',views.admin,name='ad'),
    path('postjob', views.post_job, name='postjob'),
    path('seekerlist', views.seekerlist, name='seekerlist'),
    path('companydash', views.seekerview, name='companydash'),
    path('companylist', views.companylist, name='companylist'),
    path('viewpostedjobs', views.posted_jobs, name='viewpostedjobs'),
    path('job/<int:job_id>', views.viewjobdetails, name='viewjobdetails'),
    path('companyview', views.companyview, name='copmanyview'),

    #---------------Change pw------------------------------
    
    path('changepw_seeker', views.changepw_seeker, name='changepw_seeker'),
    path('changepw_pro', views.changepw_pro, name='changepw_pro'),

    path('password_reset/', auth_views.PasswordResetView.as_view(), name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),

    path('verifymail', views.verifymail, name='verifymail'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('companyjobs', views.companyjobs, name='companyjobs'),
    path('edit_job/<int:job_id>', views.edit_job, name='edit_job'),

    path('updatestatus/<int:job_id>', views.companyjobs, name='edit_job'),
    path('delete_job_by_company/<int:job_id>/', views.delete_job_by_company, name='delete_job_by_company'),
    
    path('accounts/', include('allauth.urls')),
    path('updatestatus/<int:user_id>', views.update_status, name='update_status'),
    path('updateproviderstatus/<int:user_id>', views.update_provider_status, name='update_provider_status'),


    path('applyjob/<int:job_id>', views.applyjob, name='applyjob'),   
    path('applied_jobs', views.appliedjobs, name='applied_jobs'),
    path('delete_job/<int:job_id>', views.delete_job, name='delete_job'),
    path('view_applicants', views.view_applicants, name='view_applicants'),
    path('save_job/<int:job_id>', views.save_job, name='save_job'),
    path('unsave_job/<int:job_id>/', views.unsave_job, name='unsave_job'),
    path('view_saved_jobs', views.view_saved_jobs, name='view_saved_jobs'),
    path('add-review1', views.add_review1, name='add_review1'),
    path('add-review2', views.add_review2, name='add_review2'),

    path('update-avg-rating', views.update_user_avg_rating, name='update_user_avg_rating'),
    path('all-ratings', views.view_all_ratings, name='all_ratings'),

    path('view_applicants/<int:job_id>/', views.view_applicants, name='view_applicants'),



# MAIN
path('schedule-interview/<int:application_id>/', views.schedule_interview, name='schedule_interview'),

path('edit_interview/<int:application_id>/', views.edit_interview, name='edit_interview'),

path('resumescreen1', views.resume_scrn, name='resumescreen1'),
path('resume_screening_result', views.resume_scrn, name='resume_screening_result'),

path('reject/<int:application_id>', views.reject_candidate, name='reject_candidate'),
path('thankyou', views.logout_error_page, name='thankyou'),


path('list_interviews', views.interview_list, name='list_interviews'),

]


    