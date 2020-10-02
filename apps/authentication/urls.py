from django.urls import path
from django.urls import reverse, reverse_lazy
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from apps.authentication.views import (RegistrationView, ConfirmSignUpView, UserProfileFormView,
                                       UserProfileView, UserProfileUpdate, AboutView, WelcomeView, TwoFactorToggleview, 
                                       TwoFactorAuthenticationView, VerifyPhone, ResendOTP, ToggleAccess, Mnemonicgenerator,
                                       PasswordResetView, PasswordResetConfirmView,PasswordResetFormView)
app_name = 'auth'
urlpatterns = [
    path('signup/', RegistrationView.as_view(), name='signup'),
    path('login/', auth_views.LoginView.as_view(template_name='authentication/login.html'),
         name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='/'), name='logout'),
    path('profile/', UserProfileFormView.as_view(), name='userprofile'),
    path('view_profile/', UserProfileView.as_view(), name='userprofileview'),
    path('user_profile_update/', UserProfileUpdate.as_view(),
         name='userprofileupdate'),
    path('phoneverify', VerifyPhone.as_view(), name='phoneverify'),
    path('email-confirmation/<uidb64>/<token>/', ConfirmSignUpView.as_view(
    ), name="email_confirmation"),
    path('password_reset/', PasswordResetView.as_view(), name='password_reset'),
    path('password_reset_confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(
        template_name='authentication/password_reset_done.html'), name='password_reset_done'),
    path('reset/',
         PasswordResetFormView.as_view(), name='password_reset_form'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(),
         name='password_reset_complete'),
    path('password_change/', login_required(auth_views.PasswordChangeView.as_view(
        template_name='authentication/password_change_form.html', success_url='done')), name='password_change'),
    path('password_change/done/',
         (auth_views.PasswordChangeDoneView.as_view(template_name='authentication/password_change_done.html')), name='password_change_done'),
    path('otp/', TwoFactorAuthenticationView.as_view(), name='otp'),
    path('resendotp', ResendOTP.as_view(), name='resendotp'),
    path('toggle2factor', TwoFactorToggleview.as_view(), name='toggle2factor'),
    path('toggleaccess/<slug:slug>/', ToggleAccess.as_view(), name='toggleaccess'),
    path('mnemonic_gen', Mnemonicgenerator.as_view(), name='mnemonicgen'),

]
