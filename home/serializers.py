from rest_framework import serializers
from django.contrib.auth.models import User
import re
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode


class RegisterSerializer(serializers.Serializer):
    username =  serializers.CharField()
    first_name = serializers.CharField()
    email =  serializers.EmailField()
    password = serializers.CharField()

    def validate(self,data):
        if data['username']:
            if User.objects.filter(username = data['username']).exists():
                raise serializers.ValidationError('username already exists!.. Try new')
            
        if data['email']:
            if User.objects.filter(email = data['email']).exists():
                raise serializers.ValidationError('email already exists!.. Try new')
            
        #Password validation    
        password = data.get('password', '')
        if len(password) < 12:
            raise serializers.ValidationError('Password must be at least twelve characters long.')
        if not re.search(r'[A-Z]', password):
            raise serializers.ValidationError('Password must contain at least one uppercase letter.')
        if not re.search(r'[a-z]', password):
            raise serializers.ValidationError('Password must contain at least one lowercase letter.')
        if not re.search(r'\d', password):
            raise serializers.ValidationError('Password must contain at least one digit.')
        if not re.search(r'[!@#$%^&*()_+{}|:"<>?]', password):
            raise serializers.ValidationError('Password must contain at least one symbol like ! " ? $ % ^ & @).')
        
        return data

         
    def create(self, validated_data):
        user = User.objects.create(username =  validated_data['username'],email = validated_data['email'],first_name= validated_data['first_name'] , password = validated_data['password'])
        user.set_password(validated_data['password'])
        user.save()
        print(validated_data)
        return validated_data
        

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        if not data['username']:
            raise serializers.ValidationError("please enter the usename")
        
        if not data['password']:
            raise serializers.ValidationError("please enter the password")

        return data
    




class EmailSerializer(serializers.Serializer):
    """
    Reset Password Email Request Serializer.
    """

    email = serializers.EmailField()

    class Meta:
        fields = ("email",)



class ResetPasswordSerializer(serializers.Serializer):
    """
    Reset Password Serializer.
    """

    password = serializers.CharField(
        write_only=True,
        min_length=10,
    )

    class Meta:
        field = ("password")

    def validate(self, data):
        password = data.get("password")
        token = self.context.get("kwargs").get("token")
        encoded_pk = self.context.get("kwargs").get("encoded_pk")

        if token is None or encoded_pk is None:
            raise serializers.ValidationError("Missing data.")

        pk = urlsafe_base64_decode(encoded_pk).decode()
        user = User.objects.get(pk=pk)
        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError("The reset token is Expired or Invalid")
        
        if len(password) < 12:
            raise serializers.ValidationError('Password must be at least twelve characters long.')
        if not re.search(r'[A-Z]', password):
            raise serializers.ValidationError('Password must contain at least one uppercase letter.')
        if not re.search(r'[a-z]', password):
            raise serializers.ValidationError('Password must contain at least one lowercase letter.')
        if not re.search(r'\d', password):
            raise serializers.ValidationError('Password must contain at least one digit.')
        if not re.search(r'[!@#$%^&*()_+{}|:"<>?]', password):
            raise serializers.ValidationError('Password must contain at least one symbol like ! " ? $ % ^ & @).')

        user.set_password(password)
        user.save()
        return data