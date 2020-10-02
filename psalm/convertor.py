from django.utils.encoding import force_bytes, force_text, smart_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode


class PKConverter:
    regex = '[a-zA-Z0-9_.-]+'

    def to_python(self, value):
        value = urlsafe_base64_decode(value).decode()
        return str(value)

    def to_url(self, value):
        value = urlsafe_base64_encode(force_bytes(value)).decode()
        return str(value)