from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class SignUpForm(UserCreationForm):
    email = forms.CharField(max_length=254, required=True, widget=forms.EmailInput())
    security_question = forms.CharField(max_length=254, required=True, widget=forms.TextInput())
    answer = forms.CharField(max_length=254, required=True, widget=forms.TextInput())

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2', 'security_question', 'answer')
