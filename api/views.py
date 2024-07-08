from django.shortcuts import render
from rest_framework import status, generics, serializers
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.core.exceptions import PermissionDenied
from .models import User, Organisation
from .serializers import UserSerializer, OrganisationSerializer, LoginSerializer,CreateOrganisationSerializer, AddUserToOrganisationSerializer
from .utils import generate_token, get_user_from_token
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from django.contrib.auth import login, authenticate, get_user_model




class RegisterView(generics.CreateAPIView):
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        # Create default organisation
        org_name = f"{user.firstName}'s Organisation"
        org = Organisation.objects.create(name=org_name, creator=user)
        org.users.add(user)

        # token = generate_token(user)
        # return Response({
        #     "status": "success",
        #     "message": "Registration successful",
        #     "data": {
        #         "accessToken": token,
        #         "user": UserSerializer(user).data
        #     }
        # }, status=status.HTTP_201_CREATED)

        refresh = RefreshToken.for_user(user)
        return Response({
            "status": "success",
            "message": "Registration successful",
            "data": {
                # "refresh": str(refresh),
                "accessToken": str(refresh.access_token),
                "user": UserSerializer(user).data
            }
        }, status=status.HTTP_201_CREATED)



class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            user = authenticate(request, email=email, password=password)

            if user is not None:
                # token = generate_token(user)
                # print(f"Generated token: {token}")
                login(request, user)
                refresh = RefreshToken.for_user(user)
                return Response({
                    "status": "success",
                    "message": "Login successful",
                    "data": {
                        # "accessToken":token,
                        # "user": UserSerializer(user).data
                        
                        'accessToken': str(refresh.access_token),
                        "user":  {
                            "userId": user.userId,
                            "firstName": user.firstName,
                            "lastName": user.lastName,
                            "email": user.email,
                            "phone":user.phone
                        }
                    }
                })
            return Response({
                "status": "Bad request",
                "message": "Authentication failed",
                "statusCode": 401
        }, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        

class UserDetailView(generics.RetrieveAPIView):
    # permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer
    queryset = User.objects.all()
    lookup_field = 'userId'

class OrganisationListCreateView(generics.ListCreateAPIView):
    # permission_classes = [IsAuthenticated]
    serializer_class = OrganisationSerializer

    def get_queryset(self):
        if self.request.user.is_authenticated:
            return Organisation.objects.filter(users=self.request.user)
        return Organisation.objects.none()

    def list(self, request, *args, **kwargs):
        # if not request.user.is_authenticated:
        #     return Response({
        #         "status": "Unauthorized",
        #         "message": "Authentication credentials were not provided.",
        #         "statusCode": 401
        #     }, status=status.HTTP_401_UNAUTHORIZED)

        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            "status": "success",
            "message": "Organisations retrieved successfully",
            "data": {
                "organisations": serializer.data
            }
        }, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        # if not request.user.is_authenticated:
        #     return Response({
        #         "status": "Unauthorized",
        #         "message": "Authentication credentials were not provided.",
        #         "statusCode": 401
        #     }, status=status.HTTP_401_UNAUTHORIZED)

        serializer = CreateOrganisationSerializer(data=request.data)
        if serializer.is_valid():
            organisation = serializer.save(creator=request.user)
            organisation.users.add(request.user)
            return Response({
                "status": "success",
                "message": "Organisation created successfully",
                "data": OrganisationSerializer(organisation).data
            }, status=status.HTTP_201_CREATED)
        return Response({
            "status": "Bad Request",
            "message": "Client error",
            "statusCode": 400
        }, status=status.HTTP_400_BAD_REQUEST)


class OrganisationDetailView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = OrganisationSerializer
    lookup_field = 'orgId'

    def get_queryset(self):
        return Organisation.objects.filter(users=self.request.user)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response({
            "status": "success",
            "message": "Organisation retrieved successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)


class AddUserToOrganisationView(generics.CreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = AddUserToOrganisationSerializer

    def create(self, request, *args, **kwargs):
        userId = self.kwargs.get('userId')
        organisation = get_object_or_404(Organisation, userId=userId)
        
        serializer = self.get_serializer(data=request.data, context={'organisation': organisation})
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({
            "status": "success",
            "message": "User added to organisation successfully",
        }, status=status.HTTP_200_OK)

    def handle_exception(self, exc):
        if isinstance(exc, serializers.ValidationError):
            return Response({
                "status": "Bad Request",
                "message": exc.detail,
                "statusCode": 400
            }, status=status.HTTP_400_BAD_REQUEST)
        return super().handle_exception(exc)


