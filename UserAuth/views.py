# backend Authentication project ::  social media authentication , logout and 
# forgetpassword functionality ----> 07th dec

# frontend Authentication project ::: signup screen , login screen , otp verification
# screen , update password screen , forget password screen , set password screen ,,,,
# total approx  :::: 06 to 07 screen---->  11 to 14th  dec

# Full Ready ---> 15 or 16th of December

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
        email = request.data.get('email')
        password = request.data.get('password')
    
        email_exists = User.objects.filter(username=email).exists()
        if email_exists == True:
            return Response({"message":"Email already exists"},status=404)
        else:
            user = User.objects.create_user(username=email,password=password)
            if user is not None:
                user.save()
                return Response({"message":"User Registered"},status=200)
            else:
                return Response({"message":"Something went wrong"},status=404)
            

# server had registered the user and he/she had to do login  
# user had provided login credentials to server --> server checks into db that login
# credentials has match correctly --> if mtched then it send otp to email
#                                 --> if not then it response that user doesn't exist
# otp sent to mail --> verifyotp user with otp --> if match them it provide token and 
#                                                  logedin the user
#                                              --> if not then invalid code/otp
class UserLoginView(APIView):   
    authentication_classes = []
    permission_classes = [AllowAny]
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        
        try:
            user = authenticate(username=email, password=password)
            print(user)
            random_code = randint(100000, 999999)
            subject = 'OTP'
            message = f'Your otp is {random_code}'
            email_from = settings.EMAIL_HOST_USER
            recipient_list = [user.username]
            send_mail( subject, message, email_from, recipient_list)
            
            user = User.objects.get(username=email)
            otp_obj = models.otp.objects.create(username=user, code=random_code)
            
            return Response({"message": "Successfully Email has been sent"}, status=200)
        except Exception:
            return Response({"message": "Invalid Credentials or User Doesn't Exist"}, status=400)

class verifyOTP(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    def post(self, request):
        email = request.POST.get('email')
        code = request.POST.get('code')
        try:
                user = User.objects.get(username=email)
                new_user = models.otp.objects.get(username = user,code=code)
                login(request,user)

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

# in updatepassword the jwt_token will pass in header and other in body --> jwt_token.id==user.id
                                                                                # then updated
class UpdatePassword(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def post(self, request):
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            user = User.objects.get(username=email)
            user_id = user.id            
            jwt_token = request.auth
            user_id_from_token = jwt_token.get('user_id', None)
           
            user.set_password(password)
            user.save()
            if user_id == user_id_from_token : 
                return Response({"message" : "Successfully Updated"} , status = 200)
            else :
                return Response({'message' : "User Id is not matching with token"} , status=404)
        except:
            return Response({"message": "User Doesn't exist"} , status= 400)


class ForgetPasswordView(APIView):   
    authentication_classes = []
    permission_classes = [AllowAny]
    def post(self,request):
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
