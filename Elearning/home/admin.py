from django.contrib import admin
from django.utils.html import format_html
from .models import (
    Department, Intern, Recruitment, TrainingProgram, Performance,
    Feedback, Task, Project, Attendance, Report, Event, Notification,
    JobPost, Candidate, Interview, CandidateEvaluation, UserPermission, Integration, Profile,
)

# Custom Admin Actions
@admin.action(description="Đánh dấu đã hoàn thành thực tập")
def mark_as_completed(modeladmin, request, queryset):
    queryset.update(status='completed')

@admin.action(description="Gửi thông báo cho thực tập sinh")
def send_notification(modeladmin, request, queryset):
    for intern in queryset:
        Notification.objects.create(
            user=intern.user,
            message=f"Thông báo mới cho {intern.full_name}",
            notification_type='info'
        )
    modeladmin.message_user(request, f"Đã gửi thông báo cho {queryset.count()} thực tập sinh.")

# ModelAdmin Classes
@admin.register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ('name', 'manager', 'created_at')
    search_fields = ('name', 'manager__username')
    list_filter = ('created_at',)
    list_per_page = 20
    ordering = ('name',)
    list_select_related = ('manager',)

@admin.register(Intern)
class InternAdmin(admin.ModelAdmin):
    list_display = ('full_name', 'email', 'phone', 'status', 'university', 'start_date', 'end_date', 'avatar_preview')
    search_fields = ('full_name', 'email', 'phone', 'university', 'major')
    list_filter = ('status', 'university', 'start_date', 'end_date', 'department')
    list_per_page = 20
    fieldsets = (
        ('Thông tin cá nhân', {
            'fields': ('user', 'first_name', 'last_name', 'email', 'phone', 'date_of_birth', 'address')
        }),
        ('Thông tin học vấn', {
            'fields': ('university', 'major')
        }),
        ('Thông tin thực tập', {
            'fields': ('start_date', 'end_date', 'status', 'department')
        }),
        ('Ảnh đại diện', {
            'fields': ('avatar',)
        }),
    )
    readonly_fields = ('full_name', 'created_at', 'updated_at')
    actions = [mark_as_completed, send_notification]
    list_select_related = ('user', 'department')
    raw_id_fields = ('user', 'department')

    def avatar_preview(self, obj):
        if obj.avatar:
            return format_html('<img src="{}" width="50" height="50" />', obj.avatar.url)
        return "Không có ảnh"
    avatar_preview.short_description = "Ảnh đại diện"

@admin.register(Recruitment)
class RecruitmentAdmin(admin.ModelAdmin):
    list_display = ('position', 'posted_by', 'posted_date', 'deadline', 'is_active')
    search_fields = ('position', 'posted_by__username', 'description', 'requirements')
    list_filter = ('posted_date', 'deadline', 'is_active')
    list_per_page = 20
    fieldsets = (
        ('Thông tin tuyển dụng', {
            'fields': ('position', 'description', 'requirements', 'location', 'salary_range')
        }),
        ('Thông tin người đăng', {
            'fields': ('posted_by', 'posted_date', 'deadline', 'is_active')
        }),
    )
    readonly_fields = ('posted_date',)
    list_select_related = ('posted_by',)
    raw_id_fields = ('posted_by',)

@admin.register(TrainingProgram)
class TrainingProgramAdmin(admin.ModelAdmin):
    list_display = ('name', 'start_date', 'end_date', 'trainer', 'location', 'max_participants', 'status')
    search_fields = ('name', 'trainer', 'location')
    list_filter = ('start_date', 'end_date', 'trainer', 'status')
    list_per_page = 20
    fieldsets = (
        ('Thông tin chương trình', {
            'fields': ('name', 'description', 'start_date', 'end_date', 'location', 'trainer', 'max_participants', 'status')
        }),
        ('Thực tập sinh tham gia', {
            'fields': ('interns',)
        }),
    )
    filter_horizontal = ('interns',)
    list_select_related = ()

@admin.register(Performance)
class PerformanceAdmin(admin.ModelAdmin):
    list_display = ('intern', 'evaluator', 'evaluation_period', 'score', 'rating', 'is_final_evaluation')
    search_fields = ('intern__full_name', 'evaluator__username', 'evaluation_period')
    list_filter = ('evaluation_period', 'is_final_evaluation', 'evaluator')
    list_per_page = 20
    fieldsets = (
        ('Thông tin đánh giá', {
            'fields': ('intern', 'evaluator', 'evaluation_period', 'score', 'comments', 'is_final_evaluation', 'rating')
        }),
    )
    list_select_related = ('intern', 'evaluator')
    raw_id_fields = ('intern', 'evaluator')

@admin.register(Feedback)
class FeedbackAdmin(admin.ModelAdmin):
    list_display = ('intern', 'feedback_date', 'is_resolved', 'response_date')
    search_fields = ('intern__full_name', 'content')
    list_filter = ('feedback_date', 'is_resolved', 'response_date')
    list_per_page = 20
    fieldsets = (
        ('Thông tin phản hồi', {
            'fields': ('intern', 'content', 'is_resolved')
        }),
        ('Phản hồi từ quản lý', {
            'fields': ('response', 'response_date')
        }),
    )
    list_select_related = ('intern',)
    raw_id_fields = ('intern',)

@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
    list_display = ('title', 'assigned_to', 'status', 'priority', 'due_date', 'project')
    search_fields = ('title', 'assigned_to__username', 'description')
    list_filter = ('status', 'priority', 'due_date', 'project')
    list_per_page = 20
    list_select_related = ('assigned_to', 'project')
    raw_id_fields = ('assigned_to', 'project')

@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ('name', 'start_date', 'end_date', 'manager', 'status')
    search_fields = ('name', 'manager__username', 'description')
    list_filter = ('start_date', 'end_date', 'status')
    list_per_page = 20
    list_select_related = ('manager',)
    raw_id_fields = ('manager',)

@admin.register(Attendance)
class AttendanceAdmin(admin.ModelAdmin):
    list_display = ('intern', 'date', 'status', 'notes')
    search_fields = ('intern__full_name', 'notes')
    list_filter = ('date', 'status')
    list_per_page = 20
    list_select_related = ('intern',)
    raw_id_fields = ('intern',)

@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ('title', 'user', 'submitted_date', 'reviewed_by', 'review_date')
    list_filter = ('submitted_date', 'reviewed_by', 'review_date')
    search_fields = ('title', 'content', 'user__username')
    ordering = ['-submitted_date']  # Sắp xếp theo ngày nộp giảm dần
    readonly_fields = ('submitted_date',)
    date_hierarchy = 'submitted_date'
    list_select_related = ('user', 'reviewed_by')
    raw_id_fields = ('user', 'reviewed_by')

@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = ('title', 'start_time', 'end_time', 'location')
    search_fields = ('title', 'location', 'description')
    list_filter = ('start_time', 'end_time')
    list_per_page = 20
    date_hierarchy = 'start_time'

@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('user', 'message', 'notification_type', 'is_read', 'created_at')
    search_fields = ('user__username', 'message')
    list_filter = ('notification_type', 'is_read', 'created_at')
    list_per_page = 20
    list_select_related = ('user',)
    raw_id_fields = ('user',)

@admin.register(JobPost)
class JobPostAdmin(admin.ModelAdmin):
    list_display = ('title', 'platform', 'posted_by', 'posted_date')
    search_fields = ('title', 'description', 'posted_by__username')
    list_filter = ('platform', 'posted_date')
    list_per_page = 20
    list_select_related = ('posted_by',)
    raw_id_fields = ('posted_by',)

@admin.register(Candidate)
class CandidateAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'status', 'applied_date')
    search_fields = ('name', 'email')
    list_filter = ('status', 'applied_date')
    list_per_page = 20
    date_hierarchy = 'applied_date'

@admin.register(Interview)
class InterviewAdmin(admin.ModelAdmin):
    list_display = ('candidate', 'interview_date', 'interview_time', 'interviewer')
    search_fields = ('candidate__name', 'interviewer__username')
    list_filter = ('interview_date', 'interviewer')
    list_per_page = 20
    list_select_related = ('candidate', 'interviewer')
    raw_id_fields = ('candidate', 'interviewer')

@admin.register(CandidateEvaluation)
class CandidateEvaluationAdmin(admin.ModelAdmin):
    list_display = ('candidate', 'evaluator', 'evaluation_date', 'score')
    search_fields = ('candidate__name', 'evaluator__username')
    list_filter = ('evaluation_date', 'evaluator')
    list_per_page = 20
    list_select_related = ('candidate', 'evaluator')
    raw_id_fields = ('candidate', 'evaluator')

@admin.register(Integration)
class IntegrationAdmin(admin.ModelAdmin):
    list_display = ('system', 'integrated_by', 'integrated_date')
    search_fields = ('system', 'integrated_by__username')
    list_filter = ('system', 'integrated_date')
    list_per_page = 20
    list_select_related = ('integrated_by',)
    raw_id_fields = ('integrated_by',)

@admin.register(UserPermission)
class UserPermissionAdmin(admin.ModelAdmin):
    list_display = ('user', 'role', 'permission')
    search_fields = ('user__username', 'role')
    list_filter = ('role', 'permission')
    list_per_page = 20
    list_select_related = ('user',)
    raw_id_fields = ('user',)

@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ('id', 'full_name', 'dob', 'gender', 'email', 'phone', 'education', 'workExperience')
    search_fields = ('id', 'full_name', 'dob', 'gender', 'email', 'phone', 'education')
    list_filter = ('gender', 'education', 'dob')
    list_per_page = 20
    date_hierarchy = 'dob'
