from django.contrib import admin
from .models import Job_Seekers, Job_Providers,User,PostJobs,SavedJob,Rating,Interview,ApplyJob


class Job_SeekersAdmin(admin.ModelAdmin):
    list_display = ( 'user','seeker_id','gender','phone','loc','qual',)  # Add the fields you want to display

class Job_ProvidersAdmin(admin.ModelAdmin):
    list_display = ('cname', 'ctype', 'status')
     # Add the fields you want to display

# Register the models with their respective admin classes
admin.site.register(Job_Seekers, Job_SeekersAdmin)
admin.site.register(Job_Providers, Job_ProvidersAdmin)
admin.site.register(User)
admin.site.register(PostJobs)
admin.site.register(SavedJob)
admin.site.register(Rating)
admin.site.register(ApplyJob)
admin.site.register(Interview)