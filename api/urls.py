from django.urls import path
from .views import (
    RegisterView, LoginView, UserDetailView,
    OrganisationListCreateView, OrganisationDetailView,
    AddUserToOrganisationView
)
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path('auth/register', RegisterView.as_view(), name='register'),
    path('auth/login', LoginView.as_view(), name='login'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/users/<str:userId>', UserDetailView.as_view(), name='user-detail'),
    path('api/organisations', OrganisationListCreateView.as_view(), name='organisation-list-create'),
    path('api/organisations/<str:orgId>', OrganisationDetailView.as_view(), name='organisation-detail'),
    path('api/organisations/<str:orgId>/users', AddUserToOrganisationView.as_view(), name='add-user-to-organisation'),

    
]