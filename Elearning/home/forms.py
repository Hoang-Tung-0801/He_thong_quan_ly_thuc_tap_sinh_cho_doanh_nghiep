from django import forms
from .models import Recruitment,Interview,Communication
from django.utils import timezone
from .models import Profile

class RecruitmentForm(forms.ModelForm):
    class Meta:
        model = Recruitment
        fields = ['position', 'description', 'requirements', 'location', 'salary_range', 'deadline']
        
    def clean_deadline(self):
        deadline = self.cleaned_data.get('deadline')
        if deadline < timezone.now().date():
            raise forms.ValidationError("Hạn nộp không được ở trong quá khứ.")
        return deadline
    
class InterviewForm(forms.ModelForm):
    class Meta:
        model = Interview
        fields = ['interview_date', 'interview_time', 'candidate', 'location', 'notes']
        widgets = {
            'interview_date': forms.DateInput(attrs={'type': 'date'}),
            'interview_time': forms.TimeInput(attrs={'type': 'time'}),
        }

class CommunicationForm(forms.ModelForm):
    class Meta:
        model = Communication
        fields = ['receiver', 'message', 'feedback_type']
        widgets = {
            'message': forms.Textarea(attrs={'rows': 3}),
        }


class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = "__all__"