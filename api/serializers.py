from rest_framework import serializers
from .models import User, Organisation
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = self.get_token(self.user)
        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)
        
        # Add extra responses here
        data['user'] = {
            "userId": self.user.id,
            "firstName": self.user.firstName,
            "lastName": self.user.lastName,
            "email": self.user.email,
            "phone": self.user.phone
        }
        return data


class UserSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = User
        fields = ['id', 'firstName', 'lastName', 'email', 'phone', 'password']
        extra_kwargs = {
            'password': {'write_only': True},
            'id': {'read_only': True}
        }

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(trim_whitespace=False)


class OrganisationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organisation
        fields = ['id', 'name', 'description']
        extra_kwargs = {'id': {'read_only': True}}

class CreateOrganisationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organisation
        fields = ['id', 'name', 'description']
        extra_kwargs = {'id': {'read_only': True}}

    def validate_name(self, value):
        if not value:
            raise serializers.ValidationError("Name is required and cannot be null.")
        return value

class AddUserToOrganisationSerializer(serializers.Serializer):
    id = serializers.IntegerField()

    def validate_id(self, value):
        try:
            User.objects.get(id=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this ID does not exist.")
        return value

    def create(self, validated_data):
        user = User.objects.get(id=validated_data['id'])
        organisation = self.context['organisation']
        
        if user in organisation.users.all():
            raise serializers.ValidationError("User is already in the organisation.")
        
        organisation.users.add(user)
        return {'user': user, 'organisation': organisation}