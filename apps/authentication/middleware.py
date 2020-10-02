import re

from psalm import settings
from django.contrib.auth.decorators import login_required

class AuthVerificationMiddleware(object):
    def process_exception(self, request, exception):
        return None