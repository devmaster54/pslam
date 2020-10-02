from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.translation import ugettext_lazy as _

from apps.authentication.models import User, UserProfile, UserTwoFactor, Passphrase

admin.site.site_header = 'Psalm'

class UserAdmin(UserAdmin):
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal Info'), {'fields': ('first_name','last_name','phone_number')}),
        (_("Permissions"), {'fields': ('is_active', 'is_staff', 'is_superuser',
                                       'groups', 'user_permissions')}),
        (_("Important Dates"), {'fields': ('last_login', 'date_joined')}),
    )

admin.site.register(User,UserAdmin)
admin.site.register(UserProfile)
admin.site.register(UserTwoFactor)
admin.site.register(Passphrase)