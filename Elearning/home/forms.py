from django import forms
from .models import Recruitment,Interview,Feedback
from django.utils import timezone
from django.contrib.auth.models import User

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
class FeedbackForm(forms.ModelForm):
    class Meta:
        model = Feedback
        fields = ['receiver', 'content', 'feedback_type']
        widgets = {
            'content': forms.Textarea(attrs={'rows': 4, 'cols': 40}),
            'feedback_type': forms.Select(choices=Feedback.FEEDBACK_TYPES),
        }

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super(FeedbackForm, self).__init__(*args, **kwargs)
        if user:
            self.fields['receiver'].queryset = User.objects.exclude(id=user.id)
