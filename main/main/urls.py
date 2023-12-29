from django.contrib import admin
from django.urls import path
from user.views import ChatbotView, Register, Login, Logout

urlpatterns = [
    path('admin/', admin.site.urls),
    path("register/", Register.as_view(), name="register"),
    path("login/", Login.as_view(), name="login"),
    path("logout/", Logout, name="logout"),
    path("", ChatbotView.as_view(), name="home")
]
