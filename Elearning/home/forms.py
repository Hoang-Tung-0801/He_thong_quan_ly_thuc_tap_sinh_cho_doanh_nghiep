from django import forms
from .models import Recruitment, Interview, Communication, Profile
from django.utils import timezone

class RecruitmentForm(forms.ModelForm):
    class Meta:
        model = Recruitment
        fields = ['position', 'description', 'requirements', 'location', 'salary_range', 'deadline']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 4}),
            'requirements': forms.Textarea(attrs={'rows': 4}),
        }
        labels = {
            'position': 'Vị trí tuyển dụng',
            'description': 'Mô tả công việc',
            'requirements': 'Yêu cầu ứng viên',
            'location': 'Địa điểm làm việc',
            'salary_range': 'Mức lương',
            'deadline': 'Hạn nộp hồ sơ',
        }

    def clean_deadline(self):
        deadline = self.cleaned_data.get('deadline')
        if deadline and deadline < timezone.now().date():
            raise forms.ValidationError("Hạn nộp không được ở trong quá khứ.")
        return deadline


class InterviewForm(forms.ModelForm):
    class Meta:
        model = Interview
        fields = ['interview_date', 'interview_time', 'candidate', 'location', 'notes']
        widgets = {
            'interview_date': forms.DateInput(attrs={'type': 'date'}),
            'interview_time': forms.TimeInput(attrs={'type': 'time'}),
            'notes': forms.Textarea(attrs={'rows': 3}),
        }
        labels = {
            'interview_date': 'Ngày phỏng vấn',
            'interview_time': 'Giờ phỏng vấn',
            'candidate': 'Ứng viên',
            'location': 'Địa điểm',
            'notes': 'Ghi chú',
        }


class CommunicationForm(forms.ModelForm):
    class Meta:
        model = Communication
        fields = ['receiver', 'message', 'feedback_type']
        widgets = {
            'message': forms.Textarea(attrs={'rows': 3, 'placeholder': 'Nhập nội dung tin nhắn...'}),
        }
        labels = {
            'receiver': 'Người nhận',
            'message': 'Nội dung',
            'feedback_type': 'Loại phản hồi',
        }


class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = "__all__"
        widgets = {
            'bio': forms.Textarea(attrs={'rows': 4, 'placeholder': 'Giới thiệu ngắn gọn về bạn...'}),
            'birth_date': forms.DateInput(attrs={'type': 'date'}),
        }
        labels = {
            'bio': 'Tiểu sử',
            'birth_date': 'Ngày sinh',
        }

    def clean_birth_date(self):
        birth_date = self.cleaned_data.get('birth_date')
        if birth_date and birth_date > timezone.now().date():
            raise forms.ValidationError("Ngày sinh không được ở trong tương lai.")
        return birth_date
