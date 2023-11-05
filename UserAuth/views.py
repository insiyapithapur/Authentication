from random import randint
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from UserAuth import models 
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import AllowAny , IsAuthenticated
from django.contrib.auth import login , logout
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.core.mail import send_mail
from Authentication import settings

# JWT Aithentication
# update Password


class UserRegistrationView(APIView):   
    authentication_classes = []
    permission_classes = [AllowAny]
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        # email = request.data.get('email')
    
        mob_exists = User.objects.filter(username=username).exists()
        if mob_exists == True:
            return Response({"message":"Mobile Number already exists"},status=404)
        else:
            user = User.objects.create_user(username=username,password=password)
            if user is not None:
                user.save()
                return Response({"message":"User Registered"},status=200)
            else:
                return Response({"message":"Something went wrong"},status=404)
         
class UserLoginView(APIView):   
    authentication_classes = []
    permission_classes = [AllowAny]
    def post(self, request):
        username = request.data.get('username')
        print(username)
        password = request.data.get('password')
        print(password)
        try:
            user = authenticate(username=username, password=password)
            print(user)
            print("jkjegbdjw")

            random_code = randint(100000, 999999)
            print(random_code)
            # email_sent = send_mail.delay(random_code, username)
            # print(email_sent)
            # email_result = email_sent.get()
            subject = 'OTP'
            message = f'{user.username}, Your otp is {random_code}'
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [user.username]
            print(recipient_list)
            # sotp = models.otp.objects.create(username=username,code=random_code)
            # print(sotp)
            send_mail( subject, message, email_from, recipient_list )
            # models.otp.objects.create(username=username , code = random_code)
            try:
                user = User.objects.get(username=username)
                print(user)
            except User.DoesNotExist:
                # Handle the case when the user doesn't exist
                return Response({"message": "User does not exist"}, status=400)
            otp_obj = models.otp.objects.create(username=user, code=random_code)
            # refresh = RefreshToken.for_user(user) 
            return Response({"message": "Successfully Email has been sent"}, status=200)
        except Exception:
            return Response({"message": "Invalid Credentials"}, status=400)

class verifyOTP(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    def post(self, request):
        username = request.POST.get('username')
        code = request.POST.get('code')

        if username and code:
            try:
                user = User.objects.get(username=username)
                print(user)
                new_user = models.otp.objects.get(username = user)
                print(new_user)
                # login(request,user)
                # Access the tokens
                refresh = RefreshToken.for_user(user)
                refresh_token = str(refresh)
                access_token = str(refresh.access_token)
                new_user.delete()
                return Response({
                    "message": "Successfully logged in",
                    "refresh_token": refresh_token,
                    "access_token": access_token
                }, status=200)
            except:
                return Response({'message': 'Invalid code'} , status= 400)
        else:
            return Response({'message': 'missed info'},status = 400)


class ForgetPasswordView(APIView):   
    print("bjhsg")
    # if he is not login then how he/she is authenticated?
    authentication_classes = []
    permission_classes = [AllowAny]
    def post(self,request):
        print("zbxjavxj")
        username = request.data.get('username')
        Newpassword = request.data.get('Newpassword')
        user = User.objects.filter(username=username).first()
        if user:
        # print(user)

            # ------> forgetpassword request(username,Newpassword) if authenticated create and send otp to email
            # <------ yes autehticated it is there in database move towards verify otp
            # ------> verify otp if it is matched with that username or not or it is expired
            # <------ if verified then done if not then not done if expired then send it is expired
            # ------> resend otp new otp generate with that username and update its expiry then resend it to mail
            # ------> verify otp if it is done with that username 
            # <------ Successfully updated

            user.set_password(Newpassword)
            user.save()
            return Response({"message" : "Successfully Updated"},status=200)
        else:
            return Response({"message":"User Not Found"},status=404)
  
# update password 


class UserLogoutView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def post(self, request):
        user = request.user
        print(request.user)
        if user.is_authenticated:
            # Get the user's token
            try:
                logout(request)
                # token = Token.objects.get(user=user)
                # token.delete()  # Delete the token from the database
                return Response({"message": "Logged out successfully"}, status=200)
            except Token.DoesNotExist:
                return Response({"message": "No token found for the user"}, status=400)
        else:
            return Response({"message": "User is not authenticated"}, status=400)
