from django.shortcuts import render, redirect, HttpResponse, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required,user_passes_test
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import authenticate, login
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.utils.encoding import force_bytes, force_str
from django.utils.encoding import force_str
from django.utils.html import strip_tags


from django.contrib.auth.tokens import PasswordResetTokenGenerator
from datetime import datetime

from django.contrib.auth import logout
import hashlib
from django.utils import timezone
from datetime import timedelta
from django.views.decorators.cache import never_cache

from .models import Job_Seekers, Job_Providers,User,PostJobs,Interview,account_activation_token,ApplyJob,Rating,SavedJob
def home(request):
    return render(request, "home.html")

from datetime import datetime
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import JsonResponse



class TokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return f"{user.pk}{timestamp}{user.is_active}"

generate_token = TokenGenerator()

def register(request):
    if request.method == 'POST':
        # Extract form data
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email = request.POST['email']
        password = request.POST['password']
        dob = request.POST['dob']  # Assuming dob is in 'YYYY-MM-DD' format
        gender = request.POST['gender']
        loc = request.POST['loc']
        phone = request.POST['phone']
        qual = request.POST['qual']
        oqual = request.POST['oqual']
        skills = request.POST['skills']
        exp = request.POST['exp']
        aadhaar = request.POST['aadhaar']
        pro_pic = request.FILES.get('pro_pic')
        resume = request.FILES.get('resume')
      

        if User.objects.filter(email=email).exists():
            messages.error(request, 'User with this email already exists. Please use a different email.')
        else:
            # Create a user instance
            user = User.objects.create_user(username=email, password=password, first_name=first_name, last_name=last_name, email=email)

            # Create a JobSeeker instance
            seeker = Job_Seekers(
                user=user, dob=dob, gender=gender, loc=loc, phone=phone,
                qual=qual, oqual=oqual, skills=skills, exp=exp,
                aadhaar=aadhaar, pro_pic=pro_pic, resume=resume
            )
            seeker.save()

            # Generate a token for this user
            token = account_activation_token.make_token(user)

            # Get current site
            current_site = get_current_site(request)

            # Create email body
            mail_subject = 'Activate your account.'
            message = render_to_string('emailactivate.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': token,
            })

            # Send email
            send_mail(mail_subject, message, 'jobmate2023@gmail.com', [email])

            messages.success(request, 'Registration successful. Check your email for verification.')
            return redirect('login')

    return render(request, 'register.html')

def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
        if account_activation_token.check_token(user, token):
            user.is_verified = True
            user.save()
            messages.success(request, 'Email confirmed. You can now login.')
            return redirect('login')
        else:
            messages.error(request, 'Activation link is invalid!')
            return redirect('login')
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        messages.error(request, 'Activation link is invalid!')
        return redirect('login')


from django.core.mail import send_mail  # Add this import statement

def companyreg(request):
    if request.method == 'POST':
        # Extract form data
        cname = request.POST.get('cname', '')
        email = request.POST.get('email', '')
        password = request.POST.get('password', '')
        ceoname = request.POST.get('ceoname')
        caddress = request.POST.get('caddress')
        ctype = request.POST.get('ctype')
        otherctype = request.POST.get('otherctype')
        cdescription = request.POST.get('cdescription')
        cphone = request.POST.get('cphone')
        website = request.POST.get('website')
        empno = request.POST.get('empno')
        fyear = request.POST.get('fyear')
        clicense = request.POST.get('clicense')
        licensefile = request.FILES.get('licensefile')
        logo = request.FILES.get('logo')

        # Check if a user with this email already exists
        if User.objects.filter(email=email).exists():
            messages.error(request, 'User with this email already exists. Please sign in.')
        else:
            # Create a user instance
            user = User.objects.create_user(username=email, password=password, first_name=cname, role=User.Role.JOBPROVIDER, email=email)

            
            # Create a JobProvider instance
            provider = Job_Providers(
                user=user,
                cname=cname,
                ceoname=ceoname,
                caddress=caddress,
                ctype=ctype,
                otherctype=otherctype,
                cdescription=cdescription,
                cphone=cphone,
                website=website,
                empno=empno,
                fyear=fyear,
                clicense=clicense,
                licensefile=licensefile,
                logo=logo,
            )
            provider.save()

            # Get current site
            current_site = get_current_site(request)

            # Create email body
            mail_subject = 'Activate your account.'
            message = render_to_string('emailactivate.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
            })

            # Send email
            send_mail(mail_subject, message, 'jobmate2023@gmail.com', [email])

            messages.success(request, 'Registration successful. Check your email for verification.')
            return redirect('login')

    return render(request, 'companyreg.html')




#from django.contrib.sessions.models import Session
#Session.objects.all().delete()

@never_cache
def login_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, email=email, password=password)

        if user is not None:
            if user.role == User.Role.ADMIN:
                login(request, user)
                request.session['user_role'] = user.role
                return redirect('admindash')
            elif user.role == User.Role.JOBSEEKER:
                login(request, user)
                request.session['user_id'] = user.id
                request.session['f_name'] = f"{user.first_name} {user.last_name}"
                request.session['user_role'] = 'jobseeker'
                seeker, created = Job_Seekers.objects.get_or_create(user=user)
                pro_pic_url = seeker.pro_pic.url
                request.session['userimg'] = pro_pic_url
                return redirect('userdash')
            elif user.role == User.Role.JOBPROVIDER:
                #if not user.is_verified:
                 #   messages.success(request, 'Please verify your email to continue.')
                  #  request.session.flush()
                   # logout(request)
                    #return render(request, 'login.html')

                if not user.is_active:
                    messages.warning(request, 'Your registration is awaiting approval by the Administrator.')
                    return render(request, 'verification_pending.html')

                login(request, user)
                request.session['user_id'] = user.id
                request.session['user_name'] = user.first_name
                request.session['user_role'] = 'jobprovider'
                
                try:
                    provider = Job_Providers.objects.get(user=user)
                    logo_url = provider.logo.url
                    is_active = user.is_active
                    request.session['userimg'] = logo_url
                    request.session['status'] = is_active

                    if is_active:
                        return redirect('companydash')
                    else:
                        messages.warning(request, 'Your registration is awaiting approval by the Administrator.')
                        return render(request, 'verification_pending.html')

                except Job_Providers.DoesNotExist:
                    messages.warning(request, 'Job Provider details not found.')
                    return render(request, 'verification_pending.html')
            
        else:
            messages.warning(request, 'Invalid email or password. Please try again.')

    return render(request, 'login.html')

@login_required
def logout_view(request):
    logout(request)
    request.session.flush()
    return redirect('/')


@login_required
def success_view(request):
    user = request.user

    if user.role == User.Role.ADMIN:
        return render(request, 'admindash.html')
    elif user.role == User.Role.JOBPROVIDER:
        try:
            provider = Job_Providers.objects.get(user=user)
            return render(request, 'companydash.html')
        except Job_Providers.DoesNotExist:
            
            provider = Job_Providers.objects.create(user=user)
            return render(request, 'companydash.html')
    elif user.role == User.Role.JOBSEEKER:
        try:
            seeker = Job_Seekers.objects.get(user=user)
            return render(request, 'userdash.html')
        except Job_Seekers.DoesNotExist:
            # If Job_Seekers profile doesn't exist, you might want to handle this
            # differently for social logins. For now, let's create a new Job_Seekers
            # profile for the user.
            seeker = Job_Seekers.objects.create(user=user)
            return render(request, 'userdash.html')
    else:
        messages.error(request, 'Invalid user role.')
        return redirect('login')



from django.contrib.auth.decorators import login_required

@login_required
def seekerpro(request):
    # Get the user's profile information based on the currently logged-in user
    user = request.user  # Assuming the user is logged in
    try:
        seeker = Job_Seekers.objects.get(user=user)
    except Job_Seekers.DoesNotExist:
        profile = None



    return render(request, 'seekerpro.html',{'seeker': seeker})

@login_required
def seeker_profile_update(request):
    if request.method == 'POST':
        # Update the user's information
        user = request.user
        user.first_name = request.POST['first_name']
        user.last_name = request.POST['last_name']
        user.email = request.POST['email']
        user.save()

        # Update or create the JobSeeker profile
        seeker, created = Job_Seekers.objects.get_or_create(user=user)
        seeker.dob = request.POST['dob']
        seeker.gender = request.POST['gender']
        seeker.loc = request.POST['loc']
        seeker.phone = request.POST['phone']
        seeker.qual = request.POST['qual']
        seeker.oqual = request.POST['oqual']
        seeker.skills = request.POST['skills']
        seeker.exp = request.POST['exp']
        seeker.aadhaar = request.POST['aadhaar']
        
        pro_pic = request.FILES.get('pro_pic')
        if pro_pic:
            seeker.pro_pic = pro_pic
        
        resume = request.FILES.get('resume')
        if resume:
            seeker.resume = resume

        seeker.save()

        messages.success(request, 'Profile updated successfully.')
        return redirect('userdash')  # Redirect to the user's dashboard on success

    user_id = request.session.get('user_id')
    seeker = Job_Seekers.objects.get(user_id=user_id)
    return render(request, 'seekerupdate.html',{'seeker': seeker})  

@login_required
def providerpro(request):
    # Get the user's profile information based on the currently logged-in user
    user = request.user  # Assuming the user is logged in
    try:
        provider = Job_Providers.objects.get(user=user)
    except Job_Providers.DoesNotExist:
        profile = None

    context = {
        'provider': provider,
    }

    return render(request, 'providerpro.html', context)
@login_required
def provider_profile_update(request):
    # Get the job provider's profile based on the currently logged-in user
    provider = Job_Providers.objects.get(user=request.user)

    if request.method == 'POST':
        # Update the job provider's profile attributes
        provider.cname = request.POST.get('cname')
        provider.ceoname = request.POST.get('ceoname')
        provider.caddress = request.POST.get('caddress')
        provider.ctype = request.POST.get('ctype')
        provider.otherctype = request.POST.get('otherctype')
        provider.cdescription = request.POST.get('cdescription')
        provider.cphone = request.POST.get('cphone')
        provider.website = request.POST.get('website')
        provider.empno = request.POST.get('empno')
        provider.fyear = request.POST.get('fyear')

        # You can handle file uploads (e.g., logo and license file) here
        logo = request.FILES.get('logo')
        if logo:
            provider.logo = logo
        
        licensefile = request.FILES.get('licensefile')
        if licensefile:
            provider.licensefile = licensefile
        # Save the updated profile
        provider.save()

        return redirect('companydash')  # Redirect to the user's profile page (modify the URL as needed)

    return render(request, 'provider_profile_update.html', {'provider': provider})

def verification_pending(request):
    # Your view logic here
    return render(request, 'verification_pending.html')

@never_cache

@login_required

def seekerlist(request):
    seekers = Job_Seekers.objects.all()
    # Implement any custom logic here
    return render(request, 'seekerlist.html', {'seekers': seekers})
@never_cache
@login_required
# views.py
def search_jobs(request):
    if request.method == 'POST':
        search_query = request.POST.get('search_query', '')
        jobs = PostJobs.objects.filter(title__icontains=search_query)
        return render(request, 'searchjobs.html', {'query': search_query, 'jobs': jobs})
    else:
        return render(request, 'searchjobs.html', {})
@never_cache
@login_required
def search_seeker(request):
    if request.method == 'POST':
        search_query = request.POST.get('search_query', '')
        seekers = Job_Seekers.objects.filter(skills__icontains=search_query)
        return render(request, 'searchcandi.html', {'query': search_query, 'seekers': seekers})
    else:
        return render(request, 'searchcandi.html', {})

#def search_loc(request):
 #   if request.method == 'POST':
  #      search_query = request.POST.get('search_query', '')
   #     jobs = PostJobs.objects.filter(location__icontains=search_query)
    #    return render(request, 'searchloc.html', {'query': search_query, 'jobs': jobs})
    #else:
     #   return render(request, 'searchloc.html', {})

from django.db.models import Q
@login_required
@never_cache
def search_loc(request):
    if request.method == 'POST':
        search_query_job = request.POST.get('search_query_job', '')
        search_query_loc = request.POST.get('search_query_loc', '')

        # Use Q objects to combine multiple queries
        combined_query = Q()

        # Check if title search term is present
        if search_query_job:
            combined_query &= Q(title__icontains=search_query_job)

        # Check if location search term is present
        if search_query_loc:
            combined_query &= Q(location__icontains=search_query_loc)

        # Use the combined Q object in the filter
        jobs = PostJobs.objects.filter(combined_query)

        return render(request, 'searchloc.html', {'query_job': search_query_job, 'query_loc': search_query_loc, 'jobs': jobs})
    else:
        return render(request, 'searchloc.html', {})
@never_cache
@login_required
def seekerview(request):
    seekers = Job_Seekers.objects.all()
    # Implement any custom logic here
    return render(request, 'companydash.html', {'seekers': seekers})

@never_cache
@login_required
def post_job(request):
    user_id = request.session.get('user_id')
    
    # Check if the user is logged in
    if not user_id:
        return HttpResponse("User not logged in.")  # You can customize this response

    # Check if the Job_Providers profile exists for the logged-in user
    try:
        job_provider = Job_Providers.objects.get(user_id=user_id)
    except Job_Providers.DoesNotExist:
        return HttpResponse("Job_Providers profile does not exist. Please create your profile first.")

    if request.method == 'POST':
        # Get the form data from the POST request
        title = request.POST.get('title')
        type = request.POST.get('type')
        location = request.POST.get('location')
        description = request.POST.get('description')
        requirements = request.POST.get('requirements')
        experience_required = request.POST.get('experience_required')
        category = request.POST.get('category')
        status = request.POST.get('status')
        min_salary = request.POST.get('min_salary')
        max_salary = request.POST.get('max_salary')
        deadline = request.POST.get('deadline')
        mode = request.POST.get('mode')

        # Create and save a new PostJobs instance with the form data
        post_job = PostJobs(
            title=title,
            type=type,
            location=location,
            description=description,
            requirements=requirements,
            minexp=experience_required,
            pro_id=job_provider,  # Assign the Job_Providers instance
            status=status,
            min_salary=min_salary,
            max_salary=max_salary,
            deadline=deadline,
            mode=mode
        )

        post_job.save()
        # Optionally, you can perform additional actions here, like sending email notifications or performing other logic.
        return redirect('companydash')  # You can customize the response message

    return render(request, 'postjob.html')


@never_cache
@login_required
def posted_jobs(request):
    jobs = PostJobs.objects.all()
    return render(request, 'viewpostedjobs.html', {'jobs': jobs})


@login_required
def admin(request):
    candidates=Job_Seekers.objects.count()
    companies=Job_Providers.objects.count()
@login_required
def companylist(request):
    

    companies = Job_Providers.objects.all()
    return render(request, 'companylist.html', {'companies': companies})


from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login

from django.contrib.auth import authenticate, login
@login_required
def changepw_seeker(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')  # Redirect to login if the user is not authenticated

    b = Job_Seekers.objects.filter(user_id=user_id).first()

    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        current_password = request.POST.get('current_password')
        confirm_password = request.POST.get('confirm_password')
       

        if new_password != confirm_password:
            context = {'msg': 'Passwords do not match', 'msg_type': 'error'}
            return render(request, 'changepw_seeker.html', {'b': b, 'msg': context})
        if current_password == new_password:
            context = {'msg': 'Please use a different password than your old password', 'msg_type': 'error'}
            return render(request, 'changepw_seeker.html', {'b': b, 'msg': context})

        user = authenticate(request, email=b.user.email, password=current_password)

        if user is not None:
            user.set_password(new_password)
            user.save()

            # Re-authenticate the user with the new credentials
            user = authenticate(request, email=b.user.email, password=new_password)

            if user is not None:
                login(request, user)
                context = {'msg': 'Password Changed Successfully', 'msg_type': 'success'}
                return render(request, 'login.html', {'b': b, 'msg': context})
            else:
                context = {'msg': 'Failed to re-authenticate after changing the password', 'msg_type': 'error'}
                return render(request, 'changepw_seeker.html', {'b': b, 'msg': context})
        else:
            context = {'msg': 'Your Old Password is Wrong', 'msg_type': 'error'}
            return render(request, 'changepw_seeker.html', {'b': b, 'msg': context})

    return render(request, 'changepw_seeker.html', {'b': b})


from django.contrib.auth import authenticate, login
@login_required
def changepw_pro(request):
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')  # Redirect to login if the user is not authenticated

    b = Job_Providers.objects.filter(user_id=user_id).first()

    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        current_password = request.POST.get('current_password')
        confirm_password = request.POST.get('confirm_password')
        

        if new_password != confirm_password:
            context = {'msg': 'Passwords do not match', 'msg_type': 'error'}
            return render(request, 'changepw_pro.html', {'b': b, 'msg': context})
        if current_password == new_password:
            context = {'msg': 'Please use a different password than your old password', 'msg_type': 'error'}
            return render(request, 'changepw_pro.html', {'b': b, 'msg': context})
        user = authenticate(request, email=b.user.email, password=current_password)

        if user is not None:
            user.set_password(new_password)
            user.save()

            # Re-authenticate the user with the new credentials
            user = authenticate(request, email=b.user.email, password=new_password)

            if user is not None:
                login(request, user)
                context = {'msg': 'Password Changed Successfully', 'msg_type': 'success'}
                return render(request, 'login.html', {'b': b, 'msg': context})
            else:
                context = {'msg': 'Failed to re-authenticate after changing the password', 'msg_type': 'error'}
                return render(request, 'changepw_pro.html', {'b': b, 'msg': context})
        else:
            context = {'msg': 'Your Old Password is Wrong', 'msg_type': 'error'}
            return render(request, 'changepw_pro.html', {'b': b, 'msg': context})

    return render(request, 'changepw_pro.html', {'b': b})
@never_cache
@login_required
def delete_job(request, job_id):
    job = get_object_or_404(PostJobs, job_id=job_id, pro_id__user=request.user)
    
    if request.method == 'POST':
        job.delete()
        return redirect('companyjobs')
        
    return render(request, 'deletejob.html', {'job': job})
@never_cache
@login_required
def viewjobdetails(request, job_id):
    job = get_object_or_404(PostJobs, job_id=job_id)
    return render(request, 'jobdetails.html', {'job': job})

@never_cache 
@login_required  
def edit_job(request, job_id):
    job = get_object_or_404(PostJobs, job_id=job_id, pro_id__user=request.user)

    if request.method == 'POST':
        # Handle form data directly in the view
        job.title = request.POST.get('title')
        job.type = request.POST.get('type')
        job.location = request.POST.get('location')
        job.description = request.POST.get('description')
        job.requirements = request.POST.get('requirements')
        job.minexp = request.POST.get('minexp')
        job.status = request.POST.get('status')
        job.min_salary = request.POST.get('min_salary')
        job.max_salary = request.POST.get('max_salary')
        job.deadline = request.POST.get('deadline')
        job.mode = request.POST.get('mode')

        job.save()
        return redirect('companyjobs')
        messages.warning(request, 'Updated successfully.')


    return render(request, 'editjob.html', {'job': job})

@never_cache
@login_required
def delete_job_by_company(request, job_id):
    # Get the job instance or return a 404 response if not found
    job = get_object_or_404(PostJobs, job_id=job_id)

    if request.method == 'POST':
        # Check if the logged-in user is the owner of the job
        job.delete()
        messages.success(request, 'Job deleted successfully.')
        return redirect('companyjobs')
    else:
        # Render a confirmation page or handle the logic accordingly
        return redirect('companydash')


@never_cache
@login_required
def companyjobs(request):
    # Get the currently logged-in company
    company = Job_Providers.objects.get(user=request.user)

    # Filter jobs based on the logged-in company
    company_jobs = PostJobs.objects.filter(pro_id=company)
    print(company_jobs)
    return render(request, 'companyjobs.html', {'jobs': company_jobs})



def verifymail(request):
    if request.method == 'POST':
        verification_code = request.POST.get('verification_code')

        # Check if the user is authenticated
        if request.user.is_authenticated:
            user = request.user

            # Check if the user has otp and the entered OTP matches
            stored_otp = 123456
            stored_otp_created_at = request.session.get('otp_created_at')

            print(f"Stored OTP: {stored_otp}, Entered Code: {verification_code}")

            if stored_otp is not None and str(stored_otp) == verification_code:
                # Check if the OTP has expired (adjust the expiration time as needed)
                # expiration_time = stored_otp_created_at + timezone.timedelta(minutes=5)
                # if timezone.now() <= expiration_time:
                # OTP is valid
                user.is_verified = True
                user.save()
                messages.success(request, 'Email verification successful. You can now log in.')

                # Clear the OTP-related session data after successful verification
                # request.session.pop('otp', None)
                # request.session.pop('otp_created_at', None)

                return render(request, 'login.html')
                # else:
                # messages.error(request, 'The verification code has expired. Please request a new one.')
            else:
                messages.error(request, 'Invalid verification code. Please try again.')
        else:
            messages.error(request, 'User is not authenticated. Please log in.')

    return render(request, 'verifymail.html')





    # Redirect to the appropriate page after updating the status
    return HttpResponse('Status updated successfully')  


@login_required
def update_status(request, user_id):
    user = User.objects.get(pk=user_id)
    user.is_active = not user.is_active
    user.save()
    return redirect('seekerlist')  # Replace 'your_redirect_view_name' with the actual name of your view
@login_required
def update_provider_status(request, user_id):
    user = User.objects.get(pk=user_id)
    user.is_active = not user.is_active
    user.save()
    return redirect('companylist')

from django.utils import timezone
from datetime import datetime
@never_cache
@login_required
def applyjob(request, job_id):
    job = get_object_or_404(PostJobs, pk=job_id)

    if request.method == 'POST':
        # Check if the user is authenticated
        if request.user.is_authenticated:
            # Check if the user has already applied for the job
            if ApplyJob.objects.filter(user=request.user, job_id=job).exists():
                messages.warning(request, "You have already applied for this job.")
                return redirect('applied_jobs')  # Redirect to the job listing page

            # Get the associated Job_Seekers instance for the authenticated user
            job_seeker = Job_Seekers.objects.get(user=request.user)

            # Check if the application deadline has passed
 

            current_time = timezone.now()  # Use Django's timezone to get an offset-aware datetime
            if current_time > job.deadline:
                messages.warning(request, 'Application deadline has passed. You cannot apply for this job.')
                return redirect('viewpostedjobs')
       

            # Create a new ApplyJob instance
            application = ApplyJob.objects.create(
                user=request.user,
                job_id=job,
                pro_id=job.pro_id,
                seeker_id=job_seeker,
                application_date=current_time,
                status='Pending',
            )

            messages.success(request, "Application submitted successfully!")
            return redirect('applied_jobs')  # Redirect to the job listing page
        else:
            messages.error(request, "Please log in to apply for the job.")
            return redirect('viewpostedjobs')  # Redirect to the job listing page

    return render(request, 'viewpostedjobs.html', {'job': job})
@login_required
@never_cache
def appliedjobs(request):
    print("hello")
    jobs = ApplyJob.objects.filter(user=request.user)
    for job in jobs:
        interview = Interview.objects.filter(application_id=job.id).first()
        job.interview = interview  # Add interview details to the job instance
    return render(request, 'appliedjobs.html', {'applied_jobs': jobs})
@login_required
@never_cache
def companyview(request):     
    companies = Job_Providers.objects.all()

    return render(request, 'companyview.html', {'companies': companies})
@never_cache  
@login_required
def delete_job(request, job_id):
    job = get_object_or_404(ApplyJob, id=job_id)

    job.delete()
    return redirect('viewpostedjobs')
@never_cache
@login_required
def view_applicants(request):
    # Get the currently logged-in company
    company = Job_Providers.objects.get(user=request.user)

    # Get jobs posted by the logged-in company
    company_jobs = PostJobs.objects.filter(pro_id=company)

    # Initialize an empty dictionary to hold job titles and corresponding applications
    job_applications = {}

    # Get the search query if it exists
    search_name = request.GET.get('search_name')

    # Get the application status filter if it exists
    status_filter = request.GET.get('status')
    type_filter = request.GET.get('type')
    mode_filter = request.GET.get('mode')

    # Iterate over each job posted by the company
    for job in company_jobs:
        # Get all applications for the current job
        applications = ApplyJob.objects.filter(job_id=job)

        # Filter applications by name if search query exists
        if search_name:
            applications = applications.filter(seeker_id__user__first_name__icontains=search_name)

        # Filter applications by status if status filter exists
        if status_filter and status_filter != 'All':
            applications = applications.filter(status=status_filter)

        # Filter applications by type if type filter exists
       

        # Filter applications by mode if mode filter exists
        

        # Add the job title and corresponding applications to the dictionary
        job_applications[job.title] = applications

    # Render the 'view_applicants.html' template with the job_applications context
    return render(request, 'view_applicants.html', {'job_applications': job_applications, 'status_filter': status_filter, 'type_filter': type_filter, 'mode_filter': mode_filter})


from django.http import JsonResponse
@login_required
@never_cache
def save_job(request, job_id):
  user = request.user
  job = PostJobs.objects.get(job_id=job_id)

  if SavedJob.objects.filter(user=user, job_id=job).exists():
      messages.warning(request, 'Job is already saved.')
  else:
      SavedJob.objects.create(user=user, job_id=job)
      return redirect('view_saved_jobs') 


  return redirect('viewpostedjobs') 
@never_cache
@login_required
def unsave_job(request, job_id):
  user = request.user
  job = PostJobs.objects.get(job_id=job_id)
  SavedJob.objects.filter(user=user, job_id=job).delete()
  messages.warning(request, 'Job has been unsaved.')
  return redirect('view_saved_jobs') 
@never_cache
@login_required
def view_saved_jobs(request):
    user = request.user
    saved_jobs = SavedJob.objects.filter(user=user)
    job_list = [job.job_id for job in saved_jobs]
    return render(request, 'viewsavedjobs.html', {'jobs': job_list})

@never_cache
@login_required
def add_review1(request):
    # Check if the user has already submitted a review
    if request.method == 'POST':
       title = request.POST['title']
       stars = request.POST['stars']
       comment = request.POST['comment']
       # Get the user instance (assuming the user is logged in)
       user = request.user
       if Rating.objects.filter(user=user).exists():
            messages.warning(request, "You have already submitted feedback.")
       else:
       # Create a new Rating instance
            rating = Rating(user=user, title=title, stars=stars, comment=comment)
       # Save the new Rating instance to the database
            rating.save()
            return redirect('userdash')

            messages.success(request, "Thank you for your review! Your feedback has been submitted.")

       
    else:
       return render(request, 'seekerrating.html')
@never_cache
@login_required
def add_review2(request):
    if request.method == 'POST':
       title = request.POST['title']
       stars = request.POST['stars']
       comment = request.POST['comment']
       # Get the user instance (assuming the user is logged in)
       user = request.user
       if Rating.objects.filter(user=user).exists():
            messages.warning(request, "You have already submitted feedback.")
       else:
       # Create a new Rating instance
            rating = Rating(user=user, title=title, stars=stars, comment=comment)
       # Save the new Rating instance to the database
            rating.save()
            return redirect('companydash')

            messages.success(request, "Thank you for your review! Your feedback has been submitted.")

       
    else:
       return render(request, 'prorating.html')
@never_cache
@login_required
def update_user_avg_rating(user):
    # Update the average star rating for the user based on all reviews
    avg_rating = Rating.objects.filter(user=user).aggregate(Avg('stars'))['stars__avg']
    user.avg_rating = avg_rating
    user.save()
@login_required
@never_cache
def view_all_ratings(request):
    ratings = Rating.objects.all()
    return render(request, 'all_ratings.html', {'ratings': ratings})

from .models import Interview
from django.http import HttpResponseRedirect


from django.core.mail import send_mail
from django.conf import settings
from django.shortcuts import render, redirect
from django.contrib import messages
from datetime import datetime
from .models import ApplyJob, Interview
@login_required
def schedule_interview(request, application_id):
    if request.method == 'POST':
        application_id = request.POST.get('application_id')
        # Get other form data
        mode = request.POST.get('mode')
        platform = request.POST.get('platform')
        link = request.POST.get('link')
        venue = request.POST.get('venue')
        scheduled_datetime = request.POST.get('datetime')
        notes = request.POST.get('notes')
        helpline = request.POST.get('helpline')

        # Get the corresponding ApplyJob instance
        application = ApplyJob.objects.get(id=application_id)
        pro_id = application.pro_id

        # Save interview details to Interview table
        interview = Interview.objects.create(
            application_id=application_id,
            user=application.user,
            job_id=application.job_id,
            pro_id=pro_id,
            seeker_id=application.seeker_id,
            scheduled_date=scheduled_datetime,
            mode=mode,
            platform=platform,
            link=link,
            venue=venue,
            notes=notes,
            helpline=helpline
        )
        application.status = 'Scheduled'
        application.save()

        # Format the scheduled datetime for display
        formatted_date = datetime.strptime(scheduled_datetime, '%Y-%m-%dT%H:%M')
        formatted_date_str = formatted_date.strftime("%d / %m / %Y")

        subject = 'Interview Scheduled'
        message = f'Dear {application.user.first_name} {application.user.last_name},\n\n' \
                  f'Your interview for the job "{application.job_id.title}" at {pro_id.cname} ' \
                  f'has been scheduled on {formatted_date_str}.\n\n' \
                  f'Please log in to JobMate to view more information.'

        # Send email to the job seeker
        from_email = settings.EMAIL_HOST_USER
        to_email = [application.user.email]
        send_mail(subject, message, from_email, to_email, fail_silently=False)

        # Redirect to a success page
        messages.success(request, 'Interview scheduled successfully.')
        return redirect('view_applicants')

    # Handle GET request (not allowed in this case)
    return render(request, 'error.html', {'message': 'Method Not Allowed'})

    





from django.shortcuts import get_object_or_404

from django.core.exceptions import MultipleObjectsReturned
from django.shortcuts import render, redirect
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from .models import Interview # Assuming Interview is your model
from django.core.mail import send_mail
from django.conf import settings
from datetime import datetime
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Interview
@login_required
def edit_interview(request, application_id):
    if request.method == 'POST':
        try:
            # Attempt to get a single Interview object
            application = Interview.objects.get(application_id=application_id)
        except Interview.DoesNotExist:
            # Handle the case where no Interview is found
            messages.error(request, 'No interview found for the given application ID.')
            return redirect('view_applicants')
        except Interview.MultipleObjectsReturned:
            # If multiple objects are returned, get the first one
            application = Interview.objects.filter(application_id=application_id).first()

        # Update the interview details based on the form data
        scheduled_datetime = request.POST.get('datetime')
        application.scheduled_date = scheduled_datetime
        application.notes = request.POST.get('notes')
        application.platform = request.POST.get('platform')
        application.link = request.POST.get('link')
        application.mode = request.POST.get('mode')
        application.venue = request.POST.get('venue')
        application.helpline = request.POST.get('helpline')

        # Save the updated interview details
        application.save()
        messages.success(request, 'Interview schedule updated successfully.')
        
        # Format the scheduled date for display in the email
        formatted_date = datetime.strptime(scheduled_datetime, '%Y-%m-%dT%H:%M').strftime("%d / %m / %Y")
        
        # Send an email notification
        subject = 'Interview Rescheduled'
        message = f'Dear {application.user.first_name} {application.user.last_name},\n\n' \
                  f'Your interview for the job "{application.job_id.title}" at {application.pro_id.cname} ' \
                  f'has been scheduled on {formatted_date}.\n\n' \
                  f'Please log in to JobMate to view more information.'
        from_email = settings.EMAIL_HOST_USER
        to_email = [application.user.email]
        send_mail(subject, message, from_email, to_email, fail_silently=False)

        # Display a success message
        messages.success(request, 'Please Check your Email.')

        # Redirect to a page displaying the updated interview details
        return redirect('view_applicants')
    else:
        # Handle GET request (not allowed in this case)
        return render(request, 'error.html', {'message': 'Method Not Allowed'})


import spacy
from django.shortcuts import render
from .models import ResumeScreening



def resume_scrn(request):
    if request.method == 'POST':
        resume_file = request.FILES.get('resume')
        job_role = request.POST.get('jobRole')
        industry = request.POST.get('industry')
        job_description = request.POST.get('jobDescription')

        # Process uploaded resume file
        if resume_file:
            try:
                # Try decoding as utf-8
                resume_text = "".join([chunk.decode("utf-8") for chunk in resume_file.chunks()])
            except UnicodeDecodeError:
                # Try decoding as latin-1
                resume_text = "".join([chunk.decode("latin-1") for chunk in resume_file.chunks()])

        # Load spaCy English model
        nlp = spacy.load("en_core_web_sm")

        # Process resume text
        doc = nlp(resume_text)

        # Tokenize job role, industry, and job description
        job_role_tokens = nlp(job_role.lower())
        industry_tokens = nlp(industry.lower())
        job_description_tokens = nlp(job_description.lower())

        # Calculate match score based on text similarity
        role_similarity = doc.similarity(job_role_tokens)
        industry_similarity = doc.similarity(industry_tokens)
        description_similarity = doc.similarity(job_description_tokens)

        # Average similarity score
        match_score = (role_similarity + industry_similarity + description_similarity) / 3

        # Convert match score to percentage
        match_score_percentage = match_score * 100

        # Save screening details to database
        resume_screening = ResumeScreening.objects.create(
            user=request.user,
            resume_file=resume_file,
            job_role=job_role,
            industry=industry,
            job_description=job_description,
            score=match_score_percentage
        )

        # Identify key areas for improvement and provide recommendations
        recommendations = analyze_resume(doc, job_role_tokens, industry_tokens, job_description_tokens, match_score_percentage)

        # Pass the data to the template
        context = {
            'match_score': match_score_percentage,
            'recommendations': recommendations,
            'resume_screening': resume_screening,
            # Add other data and analytics as needed
        }
        return render(request, 'resume_screening_result.html', context)

    return render(request, 'resumescreen.html')

# Helper function to analyze the resume and provide recommendations
def analyze_resume(resume_doc, job_role_tokens, industry_tokens, job_description_tokens, match_score):
    recommendations = []

    # Example recommendation based on job role, industry, and job description similarity
    if (resume_doc.similarity(job_role_tokens) * 100 < 60) and \
       (resume_doc.similarity(industry_tokens) * 100 < 50) and \
       (resume_doc.similarity(job_description_tokens) * 100 < 70) and \
       (match_score < 70):
        recommendations.append("Improve your resume to better match the job role, industry, and job description requirements.")

    # Recommendations based on match score
    if match_score >= 70:
        recommendations.append("Your resume aligns well with the job requirements. Great job!")
    elif match_score >= 60 and match_score < 70:
        recommendations.append("Your resume is a good match for the job, but there is room for improvement.")
    elif match_score >= 40 and match_score < 60:
        recommendations.append("Your resume could be improved to better align with the job requirements.")
    elif match_score < 40:
        recommendations.append("Your resume needs significant improvements to match the job requirements. It is not suitable for the position.")

    return recommendations

@never_cache
@login_required
def reject_candidate(request, application_id):
    if request.method == 'POST':
        application = ApplyJob.objects.get(id=application_id)
        application.status = 'Rejected'
        application.save()

        # Send rejection email to the candidate
        subject = 'Your Application Update from JOBMATE'
        html_message = render_to_string('rejection_email.html', {'name': application.seeker_id.user.first_name, 'company': application.pro_id.cname, 'title': application.job_id.title})
        plain_message = strip_tags(html_message)
        from_email = settings.EMAIL_HOST_USER
        to_email = application.user.email
        send_mail(subject, plain_message, from_email, [to_email], html_message=html_message)

        # Show success message
        messages.error(request, 'Candidate Rejected and Email Sent Successfully')

        # Redirect to a page
        return redirect('view_applicants')  # Assuming 'view_applicants' is the name of the URL pattern for viewing applicants

    else:
        return HttpResponseBadRequest('Invalid Request')







from datetime import date

from datetime import datetime

def interview_list(request, pro_id=None):
    if request.user.is_authenticated and request.user.role == 'jobprovider':
        # Check if the user is a job provider
        logged_in_provider = get_object_or_404(Job_Providers, user=request.user)
        # Retrieve the logged-in job provider

        # Get the start and end dates for the range if they exist
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')

        # Get the sort parameter if it exists
        sort_by = request.GET.get('sort')

        # Filter interviews by the logged-in job provider and date range
        scheduled_interviews = Interview.objects.filter(
    pro_id=logged_in_provider,  # Filter by the logged-in job provider
    scheduled_date__gte=start_date if start_date else date.today(),  # Filter by start date if provided, else filter by today's date
    scheduled_date__lte=end_date if end_date else datetime.max,  # Filter by end date if provided, else filter by maximum date
    application__status='Scheduled'  # Filter by application status='Scheduled'
).select_related('user', 'job_id', 'seeker_id', 'application')


        # Sort interviews by scheduled date in ascending order if the sort parameter is 'date_asc'
        if sort_by == 'date_asc':
            scheduled_interviews = scheduled_interviews.order_by('scheduled_date')
        # Sort interviews by scheduled date in descending order if the sort parameter is 'date_desc'
        elif sort_by == 'date_desc':
            scheduled_interviews = scheduled_interviews.order_by('-scheduled_date')

        if not scheduled_interviews:
            messages.error(request, 'No interviews scheduled for the selected date range or the dates are invalid.')

        # Pass scheduled_interviews, sort_by, start_date, and end_date to the template context for rendering
        return render(request, 'list_interviews.html', {
            'scheduled_interviews': scheduled_interviews,
            'sort_by': sort_by,
            'start_date': start_date,
            'end_date': end_date
        })

@login_required
def logout_error_page(request):
    return render(request, 'thankyou')
