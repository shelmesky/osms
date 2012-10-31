from django import forms
import re

class LoginForm(forms.Form):
    username = forms.CharField(min_length=2)
    password = forms.CharField(min_length=8,widget=forms.PasswordInput())

    def clean_username(self):
        username = self.cleaned_data['username']
        if len(username)<=2:
            raise forms.ValidationError("username must more than 2 at least.")
        for k in username:
            if not re.match('[a-z|A-Z|0-9]',k):
                raise forms.ValidationError("Inlegal!")
        return username
    
    def clean_password(self):
        password = self.cleaned_data['password']
        if len(password)<=8:
            raise forms.ValidationError("password must more than 8 at least.")
        return password
