from django.shortcuts import render
from django.contrib.auth.models import AnonymousUser

class CheckLogoutMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        try:
            # Check if the user is logged out and trying to access a page via browser history
            if not request.user.is_authenticated and response.status_code == 200:
                # Exclude the home page and login page from redirection
                if request.path not in ['/', '/login', '/register', '/resume_screening_result', '/companyreg','/admin/login/?next=/admin/']:
                    # Redirect to a custom error page
                    return render(request, 'thankyou.html')  # Adjust 'thankyou.html' to the path of your custom error page template
        except Exception as e:
            # Catch any exception
            if isinstance(request.user, AnonymousUser) and 'role' in str(e):
                return render(request, 'thankyou.html')  # Adjust 'thankyou.html' to the path of your custom error page template

        return response
