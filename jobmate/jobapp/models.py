
from django.db import models
from PIL import Image
from django.contrib.auth.decorators import login_required

from datetime import date
from django.urls import reverse
#Admin
from django.contrib.auth.models import AbstractUser
# Create your models here.
# models.py
from django.core.validators import MaxValueValidator, MinValueValidator
from django.core.mail import send_mail
import random
from django.utils import timezone


from django.contrib.auth.tokens import PasswordResetTokenGenerator


class User(AbstractUser):
    email = models.EmailField(max_length=100, unique=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'username']

    class Role(models.TextChoices):
        JOBPROVIDER = 'jobprovider', 'Job Provider'
        JOBSEEKER = 'jobseeker', 'Job Seeker'
        ADMIN = 'admin', 'Admin'

    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.JOBSEEKER,
    )

    is_verified = models.BooleanField(default=False)

class TokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            str(user.pk) + str(timestamp) +
            str(user.is_verified)
        )

account_activation_token = TokenGenerator()

GENDER_CHOICES = [
    ('male', 'Male'),
    ('female', 'Female'),
    ('not-specified', 'Prefer not to say'),
]

class Job_Seekers(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    seeker_id = models.AutoField(primary_key=True)
    dob = models.DateField("Date of Birth", default=date.today)
    loc = models.CharField("Location", max_length=50)
    phone = models.CharField("Phone No", max_length=10)
    qual = models.CharField("Qualification", max_length=25)
    oqual = models.CharField("Other Qualification", max_length=25)
    exp = models.CharField("Work Experience", max_length=25)
    skills = models.CharField("Skills", max_length=150)
    resume = models.FileField("Upload Resume", upload_to='seeker/resume/', max_length=254, default=0)
    aadhaar = models.CharField("Aadhaar No", max_length=25)
    pro_pic = models.FileField("Upload Photos", upload_to='seeker/images/', max_length=254, default=0)
    gender = models.CharField("Gender", max_length=20, choices=GENDER_CHOICES, default='not-specified')


class Job_Providers(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    pro_id = models.AutoField(primary_key=True)
    cname = models.CharField('Name', max_length=50)
    ceoname = models.CharField('CEO Name', max_length=50)
    caddress = models.CharField('Company Address', max_length=150)
    ctype = models.CharField('Company Type', max_length=25)
    otherctype = models.CharField('Other Company Type', max_length=25, blank=True, null=True)
    cdescription = models.CharField('Company Description', max_length=500)
    cphone = models.CharField('Company Phone Number', max_length=10)
    website = models.CharField('Company Website', max_length=100)
    empno = models.IntegerField('No Of Employees')
    fyear = models.DateField('Founded Date')
    logo = models.ImageField('Company Logo in jpg/png Format', upload_to='provider/logo')
    clicense = models.CharField('License number', max_length=100)
    licensefile = models.FileField('Company Licence in pdf Format', upload_to='provider/license/')
    status = models.BooleanField('Status',default=False)
 

    def send_verification_email(self):
        self.user.send_verification_email()


class PostJobs(models.Model):
    ONLINE = 'Online'
    OFFLINE = 'Offline'
    BOTH = 'Both'

    MODE_CHOICES = [
        (ONLINE, 'Online'),
        (OFFLINE, 'Offline'),
        (BOTH, 'Both'),
    ]

    FULL_TIME = 'Full-Time'
    PART_TIME = 'Part-Time'
    CONTRACT = 'Contract'

    TYPE_CHOICES = [
        (FULL_TIME, 'Full-Time'),
        (PART_TIME, 'Part-Time'),
        (CONTRACT, 'Contract'),
    ]
    job_id = models.IntegerField(primary_key=True)
    title = models.CharField(max_length=255)
    type = models.CharField(max_length=20, choices=TYPE_CHOICES, default=FULL_TIME)
    location = models.CharField(max_length=255)
    description = models.TextField()  # Job Description
    requirements = models.TextField()  # Job Requirements
    minexp = models.CharField(max_length=10, default='Fresher')
    pro_id = models.ForeignKey(Job_Providers, on_delete=models.CASCADE)
    status = models.CharField(max_length=20)  # Job Status, e.g., Open, Closed
    timestamp = models.DateTimeField(auto_now_add=True)  # Automatically set to the current time
    min_salary = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
    max_salary = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
    deadline = models.DateTimeField(null=True)  # Application Deadline
    mode = models.CharField(max_length=10, choices=MODE_CHOICES, default=ONLINE)  # Online, Offline, Both

    def __str__(self):
        return self.title

class ApplyJob(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    job_id = models.ForeignKey(PostJobs, on_delete=models.CASCADE)
    pro_id = models.ForeignKey(Job_Providers, on_delete=models.CASCADE)
    seeker_id = models.ForeignKey(Job_Seekers, on_delete=models.CASCADE)
    application_date = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=20, default='Pending')  # Use this field for interview status as well
   
    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name} - {self.job_id.title} Application"


class Interview(models.Model):
    application = models.ForeignKey(ApplyJob, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    job_id = models.ForeignKey(PostJobs, on_delete=models.CASCADE)
    pro_id = models.ForeignKey(Job_Providers, on_delete=models.CASCADE)
    seeker_id = models.ForeignKey(Job_Seekers, on_delete=models.CASCADE)

    scheduled_date = models.DateTimeField()
   
    mode = models.CharField(max_length=20, choices=[('Online', 'Online'), ('Offline', 'Offline')], default='Offline')
    platform = models.CharField(max_length=50, blank=True)
    link = models.URLField(blank=True)
    venue = models.CharField(max_length=100, blank=True)
    notes = models.TextField(blank=True)
    helpline = models.BigIntegerField(blank=True, null=True)

class SavedJob(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    seeker_id = models.ForeignKey(Job_Seekers, on_delete=models.CASCADE, null=True, blank=True)
    pro_id = models.ForeignKey(Job_Providers, on_delete=models.CASCADE, null=True, blank=True)
    job_id = models.ForeignKey(PostJobs, on_delete=models.CASCADE)
    stime = models.DateTimeField(default=timezone.now)
    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name} - Saved Job: {self.job_id.title}"

from django.core.validators import MaxValueValidator, MinValueValidator

class Rating(models.Model):
   MAX_STARS = 5

   user = models.ForeignKey(User, on_delete=models.CASCADE)
   title = models.CharField(max_length=255, blank=True, null=True)
   stars = models.DecimalField(
       max_digits=3,
       decimal_places=2,
       validators=[MinValueValidator(0), MaxValueValidator(MAX_STARS)]
   )
   comment = models.TextField(blank=True, null=True)
   timestamp = models.DateTimeField(auto_now_add=True)

   def __str__(self):
        return f"{self.user.username} rated - {self.stars} stars"

class ResumeScreening(models.Model):
    resume_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    
    #seeker_id = models.ForeignKey(Job_Seekers, on_delete=models.CASCADE)
    resume_file = models.FileField(upload_to='resume_screening/resumes/')
    job_role = models.CharField(max_length=100)  # Add field for desired job role
    industry = models.CharField(max_length=100)  # Add field for industry interest
    job_description = models.TextField()  # Add field for job description
    score = models.FloatField(default=0.0)  # Field for resume score
    pdf_file = models.FileField(upload_to='resume_screening/pdf/', blank=True, null=True)
    generated_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Resume Screening for {self.user.first_name} {self.user.last_name} - Job: {self.job_id.title}"
