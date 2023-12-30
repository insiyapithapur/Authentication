from django.urls import path , include
from rest_framework import routers
from UserAuth import views
from rest_framework_simplejwt.views import TokenObtainPairView , TokenRefreshView

urlpatterns = [
    path('Signup/',views.UserRegistrationView.as_view()),
    path('Login/',views.UserLoginView.as_view()),
    path('verifyotp/',views.verifyOTP.as_view()),
    path('updatepassword/',views.UpdatePassword.as_view()),
    path('ForgetPassword/',views.ForgetPasswordView.as_view()),
    path('Logout/',views.UserLogoutView.as_view()),

    # this will generate access token and refreh token when user first login
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # this will help you to give new access and refresh token after expiry of previous one
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh')
]