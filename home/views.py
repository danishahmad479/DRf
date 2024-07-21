from django.shortcuts import render , HttpResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.contrib.auth.models import User
from rest_framework.views import APIView
from home.serializers import *
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
# from rest_framework_simplejwt.authentication import JWTAuthentication
# from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.urls import reverse
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
# Create your views here.



Base_url = "http://127.0.0.1:8000"    

class index(APIView):
    permission_classes = [IsAuthenticated]
    def get(self,request):
        return Response({'status':200,'message':'Hello'})



class RegisterApi(APIView):
    def post(self,request):
        try:
            data = request.data
            serializer = RegisterSerializer(data = data)
            if serializer.is_valid():
                serializer.save()
                user = User.objects.get(username = serializer.data['username'])
                refresh = RefreshToken.for_user(user) 
                return Response({'status' : status.HTTP_200_OK,
                                "payload" : serializer.data,
                                'refresh': str(refresh),
                                'access': str(refresh.access_token),
                                'message' : "your data is saved"
                                },status = status.HTTP_200_OK)  
            else:
                return Response(serializer.errors)
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'message': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LoginApi(APIView):
    def post(self,request):
        try:
            data = request.data
            serializer = LoginSerializer(data = data)
            if serializer.is_valid():
                user = authenticate(username = serializer.data['username'] , password = serializer.data['password'])
                print(user)
                if user:            
                    refresh = RefreshToken.for_user(user)
                    return Response({
                        'status': status.HTTP_200_OK,
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                        'message': 'Login successful',
                    },status= status.HTTP_200_OK)
                else:
                    return Response({'status':status.HTTP_401_UNAUTHORIZED,'message':'Invalid Credentials'},status=status.HTTP_401_UNAUTHORIZED)
            else:
                return Response({'status':status.HTTP_401_UNAUTHORIZED,'message':"Invalid Credentials!.Please Register"})
        except Exception as e:
                return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'message': str(e)},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class PasswordReset(APIView):

    def post(self, request):
        try:
            data = request.data
            serializer = EmailSerializer(data=data)  
            if serializer.is_valid():
                email = serializer.validated_data["email"]
                user = User.objects.filter(email=email).first()
                
                if user:
                    encoded_pk = urlsafe_base64_encode(force_bytes(user.pk))
                    token = PasswordResetTokenGenerator().make_token(user)
                    reset_url = reverse(
                        "reset-password",
                        kwargs={"encoded_pk": encoded_pk, "token": token},
                    )
                    reset_link = f"{Base_url}{reset_url}"

                    # Set expiry time (5 minutes from now)
                    expiry_time = timezone.now() + timedelta(minutes=5)
                    user.password_reset_expiry = expiry_time
                    user.save()

                    # Send the reset_link as mail to the user.
                    subject = 'Password Reset Link'
                    message = f"Someone has requested a password reset for the following account:\n\n Site Name: Museum of You\n\n Username: {user.username}\n\n If this was a mistake, ignore this email and nothing will happen.\n\nTo reset your password, visit the following address:\n\n {reset_link}"
                    from_email = settings.EMAIL_HOST_USER
                    to_email = [user.email]
                    send_mail(subject, message, from_email, to_email, fail_silently=False)
                    
                    return Response(
                        {
                            'status': status.HTTP_200_OK,
                            "message": f"Your password reset link: {reset_link}"
                        },
                        status=status.HTTP_200_OK
                    )
                else:
                    return Response(
                        {'status': status.HTTP_400_BAD_REQUEST, "message": "User doesn't exist"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            else:
                return Response(serializer.errors)  
        except Exception as e:
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'message': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ResetPasswordAPI(APIView):
    def patch(self, request, *args, **kwargs):
        try:
            data = request.data
            serializer = ResetPasswordSerializer(data=data, context={"kwargs": kwargs})
            if serializer.is_valid():
                return Response(
                    {"message": "Password reset complete"},
                    status=status.HTTP_200_OK,
                )
            else:
                return Response({'status':status.HTTP_400_BAD_REQUEST,'message':"The reset token is Expired or Invalid"},
                                status=status.HTTP_400_BAD_REQUEST)

        except Exception as e :
            return Response({'status': status.HTTP_500_INTERNAL_SERVER_ERROR, 'message': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR)