from django.db import models
from django.contrib.auth.models import User
from django.core.validators import RegexValidator, MinValueValidator, MaxValueValidator
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils.text import slugify
from django.utils import timezone

# Validator cho số điện thoại
phone_validator = RegexValidator(
    regex=r'^\+?1?\d{9,15}$',
    message="Số điện thoại phải có định dạng hợp lệ."
)

class Department(models.Model):
    name = models.CharField(max_length=200, verbose_name="Tên phòng ban", unique=True)
    manager = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, verbose_name="Quản lý", related_name="managed_departments")
    description = models.TextField(blank=True, null=True, verbose_name="Mô tả")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Ngày tạo", editable=False)
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Ngày cập nhật", editable=False)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = "Phòng ban"
        verbose_name_plural = "Phòng ban"
        ordering = ['name']


class Intern(models.Model):
    # Thông tin cơ bản của thực tập sinh
    user = models.OneToOneField(User, on_delete=models.CASCADE, blank=True, null=True, verbose_name="Tài khoản", related_name="intern")
    first_name = models.CharField(max_length=100, verbose_name="Tên")
    last_name = models.CharField(max_length=100, verbose_name="Họ")
    full_name = models.CharField(max_length=200, blank=True, verbose_name="Họ và tên")
    email = models.EmailField(unique=True, verbose_name="Email", help_text="Nhập địa chỉ email hợp lệ", db_index=True)
    phone = models.CharField(max_length=15, validators=[phone_validator], verbose_name="Số điện thoại", help_text="Nhập số điện thoại theo định dạng quốc tế, ví dụ: +84123456789", db_index=True)
    address = models.TextField(verbose_name="Địa chỉ")
    date_of_birth = models.DateField(verbose_name="Ngày sinh")
    university = models.CharField(max_length=200, verbose_name="Trường đại học")
    major = models.CharField(max_length=200, verbose_name="Chuyên ngành")
    start_date = models.DateField(verbose_name="Ngày bắt đầu thực tập")
    end_date = models.DateField(verbose_name="Ngày kết thúc thực tập")
    avatar = models.ImageField(upload_to='interns/avatars/%Y/%m/', blank=True, null=True, verbose_name="Ảnh đại diện")
    status = models.CharField(
        max_length=20,
        choices=[
            ('active', 'Đang thực tập'),
            ('completed', 'Đã hoàn thành'),
            ('terminated', 'Đã chấm dứt'),
        ],
        default='active',
        verbose_name="Trạng thái",
        db_index=True
    )
    is_active = models.BooleanField(default=True, verbose_name="Đang hoạt động")
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True, verbose_name="Phòng ban", related_name="interns")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Ngày tạo", editable=False, db_index=True)
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Ngày cập nhật", editable=False)

    def __str__(self):
        return self.full_name if self.full_name else f"{self.first_name} {self.last_name}"

    def save(self, *args, **kwargs):
        self.full_name = f"{self.first_name} {self.last_name}"
        super().save(*args, **kwargs)

    def clean(self):
        if self.start_date and self.end_date and self.start_date > self.end_date:
            raise ValidationError("Ngày bắt đầu không thể lớn hơn ngày kết thúc.")

    def get_absolute_url(self):
        return reverse('intern_detail', args=[str(self.id)])

    def is_active_intern(self):
        return self.status == 'active' and self.is_active

    class Meta:
        verbose_name = "Thực tập sinh"
        verbose_name_plural = "Thực tập sinh"
        ordering = ['-created_at']


class Recruitment(models.Model):
    position = models.CharField(max_length=200, verbose_name="Vị trí tuyển dụng")
    slug = models.SlugField(unique=True, blank=True, verbose_name="Slug")
    description = models.TextField(verbose_name="Mô tả công việc")
    requirements = models.TextField(verbose_name="Yêu cầu")  # Sửa ở đây
    location = models.CharField(max_length=200, blank=True, null=True, verbose_name="Địa điểm")
    salary_range = models.CharField(max_length=100, blank=True, null=True, verbose_name="Mức lương")
    posted_by = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name="Người đăng", related_name="recruitments")
    posted_date = models.DateTimeField(auto_now_add=True, verbose_name="Ngày đăng", editable=False, db_index=True)
    deadline = models.DateField(verbose_name="Hạn nộp hồ sơ")
    is_active = models.BooleanField(default=True, verbose_name="Đang hoạt động", db_index=True)

    def __str__(self):
        return self.position

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.position)
        super().save(*args, **kwargs)

    def clean(self):
        # Lấy ngày hiện tại
        current_date = timezone.now().date()
        
        # Kiểm tra deadline không được ở quá khứ
        if self.deadline < current_date:
            raise ValidationError({
                'deadline': "Hạn nộp không được ở trong quá khứ."
            })
            
        # Kiểm tra deadline phải sau ngày đăng
        if self.pk:  # Nếu đã tồn tại trong DB
            posted_date = self.posted_date.date()
            if self.deadline < posted_date:
                raise ValidationError({
                    'deadline': "Hạn nộp phải sau ngày đăng bài."
                })
        else:  # Trường hợp tạo mới
            if self.deadline < current_date:
                raise ValidationError({
                    'deadline': "Hạn nộp phải sau ngày đăng bài."
                })

    def get_absolute_url(self):
        return reverse('recruitment_detail', args=[str(self.id)])

    def days_remaining(self):
        return (self.deadline - timezone.now().date()).days

    def get_status(self):
        current_date = timezone.now().date()
        if self.is_active:
            if self.deadline >= current_date:
                return "Đang hoạt động"
            else:
                return "Đã đóng"
        return "Đã đóng"

    class Meta:
        verbose_name = "Tuyển dụng"
        verbose_name_plural = "Tuyển dụng"
        ordering = ['-posted_date']


class TrainingProgram(models.Model):
    # Chương trình đào tạo
    name = models.CharField(max_length=200, verbose_name="Tên chương trình", unique=True)
    description = models.TextField(verbose_name="Mô tả")
    start_date = models.DateField(verbose_name="Ngày bắt đầu")
    end_date = models.DateField(verbose_name="Ngày kết thúc")
    location = models.CharField(max_length=200, blank=True, null=True, verbose_name="Địa điểm")
    trainer = models.CharField(max_length=200, verbose_name="Người đào tạo")
    max_participants = models.PositiveIntegerField(default=0, verbose_name="Số lượng tối đa")
    interns = models.ManyToManyField(Intern, related_name='training_programs', verbose_name="Thực tập sinh")
    status = models.CharField(
        max_length=20,
        choices=[
            ('active', 'Đang hoạt động'),
            ('completed', 'Đã hoàn thành'),
            ('cancelled', 'Đã hủy'),
        ],
        default='active',
        verbose_name="Trạng thái",
        db_index=True
    )

    def __str__(self):
        return self.name

    def clean(self):
        if self.start_date and self.end_date and self.start_date > self.end_date:
            raise ValidationError("Ngày bắt đầu không thể lớn hơn ngày kết thúc.")

    def get_absolute_url(self):
        return reverse('training_program_detail', args=[str(self.id)])

    def is_active_program(self):
        return self.status == 'active'

    class Meta:
        verbose_name = "Chương trình đào tạo"
        verbose_name_plural = "Chương trình đào tạo"
        ordering = ['-start_date']


class Performance(models.Model):
    # Đánh giá hiệu suất
    intern = models.ForeignKey(Intern, on_delete=models.CASCADE, verbose_name="Thực tập sinh", related_name="performances")
    evaluator = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name="Người đánh giá", related_name="evaluations")
    evaluation_date = models.DateField(auto_now_add=True, verbose_name="Ngày đánh giá", editable=False)
    evaluation_period = models.CharField(max_length=100, verbose_name="Kỳ đánh giá")
    score = models.DecimalField(max_digits=5, decimal_places=2, verbose_name="Điểm số", validators=[MinValueValidator(0), MaxValueValidator(100)])
    comments = models.TextField(verbose_name="Nhận xét")
    is_final_evaluation = models.BooleanField(default=False, verbose_name="Đánh giá cuối kỳ")
    rating = models.PositiveSmallIntegerField(
        choices=[
            (1, 'Rất kém'),
            (2, 'Kém'),
            (3, 'Trung bình'),
            (4, 'Tốt'),
            (5, 'Xuất sắc'),
        ],
        default=3,
        verbose_name="Đánh giá"
    )

    def __str__(self):
        return f"Đánh giá của {self.evaluator} cho {self.intern}"

    def average_score(self):
        return self.intern.performances.aggregate(models.Avg('score'))['score__avg']

    class Meta:
        unique_together = ['intern', 'evaluator', 'evaluation_period']  # Thêm dòng này
        verbose_name = "Đánh giá hiệu suất"
        verbose_name_plural = "Đánh giá hiệu suất"
        ordering = ['-evaluation_date']

class Feedback(models.Model):
    # Phản hồi từ thực tập sinh
    intern = models.ForeignKey(Intern, on_delete=models.CASCADE, verbose_name="Thực tập sinh", related_name="feedbacks")
    feedback_date = models.DateField(auto_now_add=True, verbose_name="Ngày phản hồi", editable=False)
    content = models.TextField(verbose_name="Nội dung phản hồi")
    response = models.TextField(blank=True, null=True, verbose_name="Phản hồi từ quản lý")
    response_date = models.DateField(blank=True, null=True, verbose_name="Ngày phản hồi")
    is_resolved = models.BooleanField(default=False, verbose_name="Đã giải quyết", db_index=True)

    def __str__(self):
        return f"Phản hồi từ {self.intern}"

    class Meta:
        verbose_name = "Phản hồi"
        verbose_name_plural = "Phản hồi"
        ordering = ['-feedback_date']


class Task(models.Model):
    # Công việc
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
    ]
    PRIORITY_CHOICES = [
        ('low', 'Thấp'),
        ('medium', 'Trung bình'),
        ('high', 'Cao'),
    ]

    title = models.CharField(max_length=255, verbose_name="Tiêu đề")
    description = models.TextField(verbose_name="Mô tả")
    assigned_to = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name="Người được giao", related_name='tasks')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending', verbose_name="Trạng thái", db_index=True)
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default='medium', verbose_name="Mức độ ưu tiên")
    project = models.ForeignKey('Project', on_delete=models.CASCADE, null=True, blank=True, verbose_name="Dự án", related_name="tasks")
    due_date = models.DateField(null=True, blank=True, verbose_name="Hạn chót")
    estimated_hours = models.PositiveIntegerField(default=0, verbose_name="Giờ ước tính")
    actual_hours = models.PositiveIntegerField(default=0, verbose_name="Giờ thực tế")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Ngày tạo", editable=False, db_index=True)
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Ngày cập nhật", editable=False)

    def __str__(self):
        return self.title

    def is_completed(self):
        return self.status == 'completed'

    class Meta:
        verbose_name = "Công việc"
        verbose_name_plural = "Công việc"
        ordering = ['-created_at']


class Project(models.Model):
    name = models.CharField(max_length=200, verbose_name="Tên dự án", unique=True)
    description = models.TextField(verbose_name="Mô tả")
    start_date = models.DateField(verbose_name="Ngày bắt đầu")
    end_date = models.DateField(verbose_name="Ngày kết thúc")
    manager = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, verbose_name="Quản lý dự án", related_name="managed_projects")
    interns = models.ManyToManyField(Intern, related_name='projects', verbose_name="Thực tập sinh")
    status = models.CharField(
        max_length=20,
        choices=[
            ('planned', 'Đã lên kế hoạch'),
            ('in_progress', 'Đang thực hiện'),
            ('completed', 'Đã hoàn thành'),
            ('cancelled', 'Đã hủy'),
        ],
        default='planned',
        verbose_name="Trạng thái",
        db_index=True
    )

    def __str__(self):
        return self.name

    def clean(self):
        if self.start_date and self.end_date and self.start_date > self.end_date:
            raise ValidationError("Ngày bắt đầu không thể lớn hơn ngày kết thúc.")

    def is_active_project(self):
        return self.status == 'in_progress'

    class Meta:
        verbose_name = "Dự án"
        verbose_name_plural = "Dự án"
        ordering = ['-start_date']


class Attendance(models.Model):
    intern = models.ForeignKey(Intern, on_delete=models.CASCADE, verbose_name="Thực tập sinh", related_name="attendances")
    date = models.DateField(verbose_name="Ngày điểm danh")
    status = models.CharField(
        max_length=20,
        choices=[
            ('present', 'Có mặt'),
            ('absent', 'Vắng mặt'),
            ('late', 'Đến muộn'),
        ],
        default='present',
        verbose_name="Trạng thái"
    )
    notes = models.TextField(blank=True, null=True, verbose_name="Ghi chú")

    def __str__(self):
        return f"{self.intern.full_name} - {self.date}"

    class Meta:
        verbose_name = "Điểm danh"
        verbose_name_plural = "Điểm danh"
        unique_together = ('intern', 'date')
        ordering = ['-date']


class Event(models.Model):
    title = models.CharField(max_length=200, verbose_name="Tiêu đề")
    description = models.TextField(verbose_name="Mô tả")
    start_time = models.DateTimeField(verbose_name="Thời gian bắt đầu")
    end_time = models.DateTimeField(verbose_name="Thời gian kết thúc")
    location = models.CharField(max_length=200, verbose_name="Địa điểm")
    participants = models.ManyToManyField(User, related_name='events', verbose_name="Người tham gia")

    def __str__(self):
        return self.title

    def clean(self):
        if self.start_time and self.end_time and self.start_time > self.end_time:
            raise ValidationError("Thời gian bắt đầu không thể lớn hơn thời gian kết thúc.")

    class Meta:
        verbose_name = "Sự kiện"
        verbose_name_plural = "Sự kiện"
        ordering = ['-start_time']


class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name="Người dùng", related_name="notifications")
    message = models.TextField(verbose_name="Nội dung thông báo")
    is_read = models.BooleanField(default=False, verbose_name="Đã đọc", db_index=True)
    notification_type = models.CharField(
        max_length=20,
        choices=[
            ('info', 'Thông tin'),
            ('warning', 'Cảnh báo'),
            ('error', 'Lỗi'),
            ('success', 'Thành công'),
        ],
        default='info',
        verbose_name="Loại thông báo"
    )
    link = models.URLField(blank=True, null=True, verbose_name="Liên kết")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Ngày tạo", editable=False, db_index=True)
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Ngày cập nhật", editable=False)

    def __str__(self):
        return f"Thông báo cho {self.user.username}"

    class Meta:
        verbose_name = "Thông báo"
        verbose_name_plural = "Thông báo"
        ordering = ['-created_at']


class JobPost(models.Model):
    title = models.CharField(max_length=200, verbose_name="Tiêu đề", null=False, blank=False)
    description = models.TextField(verbose_name="Mô tả", null=False, blank=False)
    platform = models.CharField(
        max_length=50,
        choices=[
            ('website', 'Trang web Công ty'),
            ('linkedin', 'LinkedIn'),
            ('indeed', 'Indeed'),
        ],
        verbose_name="Nền tảng",
        null=False,
        blank=False
    )
    posted_by = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name="Người đăng")
    posted_date = models.DateTimeField(auto_now_add=True, verbose_name="Ngày đăng")

    def __str__(self):
        return self.title


class Candidate(models.Model):
    name = models.CharField(max_length=200, verbose_name="Tên ứng viên")
    email = models.EmailField(verbose_name="Email")
    status = models.CharField(max_length=50, choices=[
        ('new', 'Ứng viên Mới'),
        ('interviewed', 'Đã Phỏng vấn'),
    ], default='new', verbose_name="Trạng thái")
    applied_date = models.DateTimeField(auto_now_add=True, verbose_name="Ngày ứng tuyển")

    def __str__(self):
        return self.name

class Interview(models.Model):
    candidate = models.ForeignKey(Candidate, on_delete=models.CASCADE, verbose_name="Ứng viên")
    interview_date = models.DateField(verbose_name="Ngày phỏng vấn")
    interview_time = models.TimeField(verbose_name="Thời gian phỏng vấn")
    interviewer = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name="Người phỏng vấn")
    location = models.CharField(max_length=200, verbose_name="Địa điểm", blank=True, null=True)  # Thêm trường location
    notes = models.TextField(verbose_name="Ghi chú", blank=True, null=True)  # Thêm trường notes

    def __str__(self):
        return f"Phỏng vấn {self.candidate.name} vào {self.interview_date}"


class CandidateEvaluation(models.Model):
    candidate = models.ForeignKey(Candidate, on_delete=models.CASCADE, verbose_name="Ứng viên")
    evaluator = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name="Người đánh giá")
    evaluation_date = models.DateTimeField(auto_now_add=True, verbose_name="Ngày đánh giá")
    score = models.PositiveIntegerField(verbose_name="Điểm số")
    comments = models.TextField(verbose_name="Nhận xét")

    def __str__(self):
        return f"Đánh giá {self.candidate.name} bởi {self.evaluator.username}"


class Integration(models.Model):
    system = models.CharField(max_length=50, choices=[
        ('hrm', 'HRM'),
        ('lms', 'LMS'),
    ], verbose_name="Hệ thống")
    integrated_by = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name="Người tích hợp")
    integrated_date = models.DateTimeField(auto_now_add=True, verbose_name="Ngày tích hợp")

    def __str__(self):
        return f"Tích hợp {self.get_system_display()} bởi {self.integrated_by.username}"


class UserPermission(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, verbose_name="Người dùng")
    role = models.CharField(max_length=50, choices=[
        ('hr', 'HR Manager'),
        ('coordinator', 'Internship Coordinator'),
        ('mentor', 'Mentor'),
    ], verbose_name="Vai trò")
    permission = models.CharField(max_length=50, choices=[
        ('read', 'Chỉ Đọc'),
        ('write', 'Đọc và Ghi'),
    ], verbose_name="Quyền Truy cập")

    def __str__(self):
        return f"{self.user.username} - {self.get_role_display()}"
    
class Report(models.Model):
    intern = models.ForeignKey(Intern, on_delete=models.CASCADE, verbose_name="Thực tập sinh", related_name="reports")
    title = models.CharField(max_length=200, verbose_name="Tiêu đề")
    content = models.TextField(verbose_name="Nội dung")
    submitted_date = models.DateTimeField(auto_now_add=True, verbose_name="Ngày nộp", editable=False)
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, verbose_name="Người đánh giá", related_name="reviewed_reports")
    review_date = models.DateTimeField(null=True, blank=True, verbose_name="Ngày đánh giá")
    review_notes = models.TextField(blank=True, null=True, verbose_name="Nhận xét")
    is_final = models.BooleanField(default=False, verbose_name="Báo cáo cuối kỳ", db_index=True)

    def __str__(self):
        return self.title

    class Meta:
        verbose_name = "Báo cáo"
        verbose_name_plural = "Báo cáo"
        ordering = ['-submitted_date']


class InternshipOffer(models.Model):
    candidate = models.ForeignKey(Candidate, on_delete=models.CASCADE)
    content = models.TextField()
    sent_by = models.ForeignKey(User, on_delete=models.CASCADE)
    sent_date = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=[('pending', 'Pending'), ('accepted', 'Accepted'), ('rejected', 'Rejected')], default='pending')

class Communication(models.Model):
    FEEDBACK_CHOICES = [
        ('positive', 'Tích cực'),
        ('negative', 'Tiêu cực'),
        ('neutral', 'Trung lập'),
    ]
    
    sender = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='sent_messages'
    )
    receiver = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='received_messages'
    )
    message = models.TextField()
    feedback_type = models.CharField(
        max_length=10,
        choices=FEEDBACK_CHOICES
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.sender} -> {self.receiver} ({self.get_feedback_type_display()})"