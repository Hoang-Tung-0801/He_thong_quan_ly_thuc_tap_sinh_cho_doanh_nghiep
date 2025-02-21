from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.models import User, Group
from django.core.mail import send_mail
from django.conf import settings
from django.core.signing import TimestampSigner, BadSignature
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.password_validation import validate_password
import logging
from .models import Intern, TrainingProgram, Task, Notification, Performance, Feedback, Department, Project, Attendance, Report, Event,Recruitment,JobPost,Candidate,Interview,CandidateEvaluation,UserPermission,Integration,Report,Communication,Profile
from django import forms
from .utils import get_user_groups_context
from .forms import RecruitmentForm
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from .forms import InterviewForm, CommunicationForm
import json
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.db import models
from django.utils.dateparse import parse_date, parse_time
from django.views.decorators.http import require_POST
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.core.exceptions import ObjectDoesNotExist
from .forms import ProfileForm
from django.db.models import Q

logger = logging.getLogger(__name__)

# Hàm gửi email xác thực tài khoản
def send_activation_email(user, request):
    try:
        signer = TimestampSigner()
        token = signer.sign(user.email)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        activation_link = f"http://{request.get_host()}/activate/{uid}/{token}/"
        
        subject = 'Kích hoạt tài khoản của bạn'
        message = f'Xin chào {user.username},\n\nVui lòng nhấp vào liên kết dưới đây để kích hoạt tài khoản của bạn:\n\n{activation_link}\n\nNếu bạn không yêu cầu điều này, vui lòng bỏ qua email này.'
        send_mail(subject, message, settings.EMAIL_HOST_USER, [user.email])
    except Exception as e:
        logger.error(f"Lỗi khi gửi email kích hoạt: {str(e)}")
        raise

# Hàm gửi email đặt lại mật khẩu
def send_password_reset_email(user, request):
    try:
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_link = f"http://{request.get_host()}/reset-password/{uid}/{token}/"
        
        subject = 'Yêu cầu đặt lại mật khẩu'
        message = f'Xin chào {user.username},\n\nBạn đã yêu cầu đặt lại mật khẩu. Vui lòng nhấp vào liên kết dưới đây để đặt lại mật khẩu:\n\n{reset_link}\n\nNếu bạn không yêu cầu điều này, vui lòng bỏ qua email này.'
        send_mail(subject, message, settings.EMAIL_HOST_USER, [user.email])
    except Exception as e:
        logger.error(f"Lỗi khi gửi email đặt lại mật khẩu: {str(e)}")
        raise

@login_required
def home(request):
    active_interns = Intern.objects.filter(is_active=True).count()
    training_programs = TrainingProgram.objects.count()
    completed_tasks = Task.objects.filter(status='completed').count()
    total_tasks = Task.objects.count()
    remaining_tasks = total_tasks - completed_tasks
    completion_rate = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
    latest_notifications = Notification.objects.all().order_by('-created_at')[:5]

    completed_training_programs = TrainingProgram.objects.filter(status='completed').count()
    remaining_training_programs = training_programs - completed_training_programs

    context = {
        'completed_training_programs': completed_training_programs,
        'remaining_training_programs': remaining_training_programs,
        'completed_tasks': completed_tasks,
        'remaining_tasks': remaining_tasks,
        'active_interns': active_interns,
        'training_programs': training_programs,
        'completion_rate': completion_rate,
        'latest_notifications': latest_notifications,
    }
    # Thêm thông tin nhóm người dùng vào context
    context.update(get_user_groups_context(request.user))
    return render(request, 'home/index.html', context)

# Kiểm tra xem người dùng có phải là HR không
def is_hr(user):
    return user.groups.filter(name='HR Managers').exists()

@login_required
@user_passes_test(lambda u: is_hr(u) or u.is_superuser)
def quanlituyendung(request):
    # Xử lý form tạo chiến dịch tuyển dụng
    if request.method == 'POST':
        form = RecruitmentForm(request.POST)
        if form.is_valid():
            recruitment = form.save(commit=False)
            recruitment.posted_by = request.user
            recruitment.full_clean()  # Gọi clean để kiểm tra validation
            recruitment.save()
            messages.success(request, '✅ Tạo chiến dịch thành công!')
            return redirect('quanlituyendung')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"🚨 {field}: {error}")
    else:
        form = RecruitmentForm()

    # Xử lý phân trang danh sách chiến dịch tuyển dụng
    recruitments_list = Recruitment.objects.all().order_by('-posted_date')
    paginator = Paginator(recruitments_list, 14)  # 14 items per page
    page = request.GET.get('page')
    
    try:
        recruitments = paginator.page(page)
    except PageNotAnInteger:
        recruitments = paginator.page(1)
    except EmptyPage:
        recruitments = paginator.page(paginator.num_pages)

    # Xử lý tìm kiếm và lọc ứng viên
    candidates = Candidate.objects.all().order_by('-applied_date')
    candidate_search = request.GET.get('candidateSearch', '')
    candidate_filter = request.GET.get('candidateFilter', 'all')

    # Tìm kiếm ứng viên theo tên
    if candidate_search:
        candidates = candidates.filter(name__icontains=candidate_search)

    # Lọc ứng viên theo trạng thái
    if candidate_filter == 'new':
        candidates = candidates.filter(status='new')
    elif candidate_filter == 'interviewed':
        candidates = candidates.filter(status='interviewed')

    # Phân trang danh sách ứng viên (chỉ cho phần quản lý ứng viên)
    candidate_paginator = Paginator(candidates, 4)  # 4 ứng viên mỗi trang
    candidate_page = request.GET.get('candidate_page')
    try:
        candidates = candidate_paginator.page(candidate_page)
    except PageNotAnInteger:
        candidates = candidate_paginator.page(1)
    except EmptyPage:
        candidates = candidate_paginator.page(candidate_paginator.num_pages)

    # Lấy tất cả ứng viên cho phần đánh giá
    all_candidates = Candidate.objects.all().order_by('-applied_date')

    # Lấy danh sách đánh giá ứng viên
    evaluations = CandidateEvaluation.objects.select_related('candidate', 'evaluator').all().order_by('-evaluation_date')

    # Lấy danh sách báo cáo
    reports = Report.objects.all().order_by('-submitted_date')

    # Chuẩn bị context
    context = {
        'form': form,
        'recruitments': recruitments,
        'candidates': candidates,  # Chỉ dùng cho phần quản lý
        'all_candidates': all_candidates,  # Dùng cho phần đánh giá
        'evaluations': evaluations,  # Danh sách đánh giá
        'candidate_search': candidate_search,
        'candidate_filter': candidate_filter,
        'reports': reports,  # Thêm biến reports vào context
    }
    context.update(get_user_groups_context(request.user))
    return render(request, 'Quanlituyendung/quanlituyendung.html', context)

# Trang lịch phỏng vấn (chỉ HR, Admin, và Internship Coordinators)
@user_passes_test(lambda u: is_hr(u) or u.groups.filter(name='Internship Coordinators').exists() or u.is_superuser)
def lichphongvan(request):
    context = get_user_groups_context(request.user)
    return render(request, 'Lichphongvan/lichphongvan.html', context)

# Trang chương trình đào tạo (chỉ HR, Admin, và Internship Coordinators)
@user_passes_test(lambda u: is_hr(u) or u.groups.filter(name='Internship Coordinators').exists() or u.is_superuser)
def chuongtrinhdaotao(request):
    context = get_user_groups_context(request.user)
    return render(request, 'Chuongtrinhdaotao/chuongtrinhdaotao.html', context)

# Trang theo dõi hiệu suất (chỉ HR, Admin, Mentors, và Internship Coordinators)
@user_passes_test(lambda u: is_hr(u) or u.groups.filter(name='Mentors').exists() or u.groups.filter(name='Internship Coordinators').exists() or u.is_superuser)
def theodoihieusuat(request):
    context = get_user_groups_context(request.user)
    return render(request, 'Theodoihieusuat/theodoihieusuat.html', context)

# Trang giao tiếp và phản hồi (Tất cả người dùng)
def giaotiepvaphanhoi(request):
    context = get_user_groups_context(request.user)
    return render(request, 'Giaotiepvaphanhoi/giaotiepvaphanhoi.html', context)

# Trang quản lý hồ sơ (chỉ HR, Admin, và Internship Coordinators)
@user_passes_test(lambda u: is_hr(u) or u.groups.filter(name='Internship Coordinators').exists() or u.is_superuser)
def quanlyhoso(request):
    context = get_user_groups_context(request.user)
    return render(request, 'Quanlyhoso/quanlyhoso.html', context)

# Trang báo cáo và phân tích (chỉ HR và Admin)
from django.shortcuts import render
from django.contrib.auth.decorators import user_passes_test
from .models import Intern, Performance, TrainingProgram, Project

@user_passes_test(lambda u: is_hr(u) or u.is_superuser)
def baocaovaphantich(request):
    # Lấy context từ get_user_groups_context
    context = get_user_groups_context(request.user)
    
    # Lấy dữ liệu từ các model
    total_interns = Intern.objects.count()
    active_interns = Intern.objects.filter(status='active').count()
    completed_interns = Intern.objects.filter(status='completed').count()
    terminated_interns = Intern.objects.filter(status='terminated').count()

    average_score = Performance.objects.aggregate(models.Avg('score'))['score__avg']
    excellent_performances = Performance.objects.filter(rating=5).count()
    good_performances = Performance.objects.filter(rating=4).count()
    average_performances = Performance.objects.filter(rating=3).count()
    poor_performances = Performance.objects.filter(rating=2).count()
    very_poor_performances = Performance.objects.filter(rating=1).count()

    total_training_programs = TrainingProgram.objects.count()
    active_training_programs = TrainingProgram.objects.filter(status='active').count()
    completed_training_programs = TrainingProgram.objects.filter(status='completed').count()
    cancelled_training_programs = TrainingProgram.objects.filter(status='cancelled').count()

    total_projects = Project.objects.count()
    active_projects = Project.objects.filter(status='in_progress').count()
    completed_projects = Project.objects.filter(status='completed').count()
    cancelled_projects = Project.objects.filter(status='cancelled').count()

    # Thêm dữ liệu thống kê vào context
    context.update({
        'total_interns': total_interns,
        'active_interns': active_interns,
        'completed_interns': completed_interns,
        'terminated_interns': terminated_interns,
        'average_score': average_score,
        'excellent_performances': excellent_performances,
        'good_performances': good_performances,
        'average_performances': average_performances,
        'poor_performances': poor_performances,
        'very_poor_performances': very_poor_performances,
        'total_training_programs': total_training_programs,
        'active_training_programs': active_training_programs,
        'completed_training_programs': completed_training_programs,
        'cancelled_training_programs': cancelled_training_programs,
        'total_projects': total_projects,
        'active_projects': active_projects,
        'completed_projects': completed_projects,
        'cancelled_projects': cancelled_projects,
    })

    return render(request, 'Baocaovaphantich/baocaovaphantich.html', context)

# Trang cấu hình hệ thống (chỉ admin)
@user_passes_test(lambda u: u.is_superuser)
def cauhinhhethong(request):
    context = get_user_groups_context(request.user)
    return render(request, 'Cauhinhhethong/cauhinhhethong.html', context)

# Trang bảo mật và quyền hạn (chỉ admin)
@user_passes_test(lambda u: u.is_superuser)
def baomatvaquyenhan(request):
    context = get_user_groups_context(request.user)
    return render(request, 'baomatvaquyenhan/baomatvaquyenhan.html', context)

# Trang hồ sơ cá nhân (yêu cầu đăng nhập)
@login_required
def myprofile(request):
    context = get_user_groups_context(request.user)
    return render(request, 'home/myprofile/myprofile.html', context)

# Trang báo cáo (yêu cầu đăng nhập)
@login_required
def reports(request):
    context = get_user_groups_context(request.user)
    return render(request, 'home/reports/reports.html', context)

# Trang hỗ trợ
def helpvasupport(request):
    context = get_user_groups_context(request.user)
    return render(request, 'home/HelpvaSupport/helpvasupport.html', context)

# Đăng xuất
def logout_view(request):
    logout(request)
    response = redirect('login')
    response.delete_cookie('sessionid')
    return response

# Đăng nhập
def login_view(request):
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        remember_me = request.POST.get('rememberMe')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                if remember_me:
                    request.session.set_expiry(30 * 24 * 60 * 60)
                else:
                    request.session.set_expiry(0)
                return redirect('home')
            else:
                messages.error(request, 'Tài khoản của bạn chưa được kích hoạt. Vui lòng kiểm tra email để kích hoạt.')
                return redirect('login')
        else:
            messages.error(request, 'Tên đăng nhập hoặc mật khẩu không đúng. Vui lòng thử lại.')
            return redirect('login')

    return render(request, 'home/login.html')

# Đăng ký
def register_view(request):
    if request.method == 'POST':
        full_name = request.POST.get('fullName')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirmPassword')

        if password != confirm_password:
            messages.error(request, 'Mật khẩu không khớp. Vui lòng thử lại.')
            return redirect('register')

        try:
            validate_email(email)
        except ValidationError:
            messages.error(request, 'Email không hợp lệ. Vui lòng nhập email đúng định dạng.')
            return redirect('register')

        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email đã tồn tại. Vui lòng sử dụng email khác.')
            return redirect('register')

        try:
            user = User.objects.create_user(username=email, email=email, password=password)
            user.first_name = full_name
            user.is_active = False
            user.save()
            send_activation_email(user, request)
            messages.success(request, 'Tài khoản đã được tạo thành công. Vui lòng kiểm tra email để kích hoạt.')
            return redirect('login')
        except Exception as e:
            messages.error(request, f'Lỗi khi tạo tài khoản: {str(e)}')
            return redirect('register')

    return render(request, 'home/register.html')

# Xác thực tài khoản
def activate_account(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
        signer = TimestampSigner()
        email = signer.unsign(token, max_age=86400)
        
        if user.email == email:
            user.is_active = True
            user.save()
            messages.success(request, 'Tài khoản của bạn đã được kích hoạt. Vui lòng đăng nhập.')
            return redirect('login')
        else:
            messages.error(request, 'Liên kết kích hoạt không hợp lệ.')
            return redirect('home')
    except (TypeError, ValueError, OverflowError, User.DoesNotExist, BadSignature, ValidationError):
        messages.error(request, 'Liên kết kích hoạt không hợp lệ hoặc đã hết hạn.')
        return redirect('home')

# Quên mật khẩu
def forgot_password_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            validate_email(email)
        except ValidationError:
            messages.error(request, 'Email không hợp lệ.')
            return redirect('forgot_password')

        try:
            user = User.objects.get(email=email)
            send_password_reset_email(user, request)
            messages.success(request, 'Hướng dẫn đặt lại mật khẩu đã được gửi đến email của bạn.')
            return redirect('login')
        except User.DoesNotExist:
            messages.error(request, 'Không tìm thấy người dùng với email này.')
    
    return render(request, 'home/forgot_password.html')

# Đặt lại mật khẩu
def reset_password(request, uidb64, token):
    try:
        # Giải mã uidb64 để lấy user ID
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
        
        # Kiểm tra token hợp lệ
        if default_token_generator.check_token(user, token):
            if request.method == 'POST':
                password = request.POST.get('password')
                confirm_password = request.POST.get('confirmPassword')
                
                # Kiểm tra mật khẩu khớp nhau
                if password == confirm_password:
                    try:
                        # Kiểm tra tính hợp lệ của mật khẩu
                        validate_password(password, user)
                        # Đặt lại mật khẩu
                        user.set_password(password)
                        user.save()
                        messages.success(request, 'Mật khẩu của bạn đã được đặt lại. Vui lòng đăng nhập.')
                        return redirect('login')
                    except ValidationError as e:
                        # Hiển thị lỗi nếu mật khẩu không hợp lệ
                        messages.error(request, f'Mật khẩu không hợp lệ: {", ".join(e.messages)}')
                else:
                    messages.error(request, 'Mật khẩu không khớp.')
            # Hiển thị trang đặt lại mật khẩu
            return render(request, 'home/reset_password.html')
        else:
            messages.error(request, 'Liên kết đặt lại mật khẩu không hợp lệ.')
            return redirect('home')
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        messages.error(request, 'Liên kết đặt lại mật khẩu không hợp lệ.')
        return redirect('home')
    
@login_required
def change_password(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            form = PasswordChangeForm(request.user, data)
            if form.is_valid():
                user = form.save()
                update_session_auth_hash(request, user)  # Cập nhật session để người dùng không bị đăng xuất
                return JsonResponse({'status': 'success', 'message': 'Mật khẩu đã được thay đổi thành công!'})
            else:
                # In ra lỗi để kiểm tra
                print(form.errors)  # In ra lỗi để xem lý do
                return JsonResponse({'status': 'error', 'message': form.errors}, status=400)
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    return JsonResponse({'status': 'error', 'message': 'Yêu cầu không hợp lệ.'}, status=400)

# Quản lý thông báo
@login_required
def notification_list(request):
    # Lấy danh sách thông báo của người dùng hiện tại
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')
    
    # Chuẩn bị dữ liệu để trả về dưới dạng JSON
    notifications_data = [
        {
            'id': notification.id,
            'message': notification.message,
            'is_read': notification.is_read,
            'notification_type': notification.notification_type,
            'link': notification.link,
            'created_at': notification.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for notification in notifications
    ]
    
    # Trả về dữ liệu dưới dạng JSON
    return JsonResponse({'notifications': notifications_data})

@login_required
def mark_notification_as_read(request, pk):
    notification = get_object_or_404(Notification, pk=pk, user=request.user)
    notification.is_read = True
    notification.save()
    return redirect('notification_list')

@login_required
def delete_notification(request, pk):
    notification = get_object_or_404(Notification, pk=pk, user=request.user)
    notification.delete()
    return redirect('notification_list')

# Quản lý công việc
@login_required
def task_list(request):
    tasks = Task.objects.filter(assigned_to=request.user).order_by('-created_at')
    context = get_user_groups_context(request.user)
    context['tasks'] = tasks
    return render(request, 'home/task_list.html', context)

@login_required
def task_detail(request, pk):
    task = get_object_or_404(Task, pk=pk, assigned_to=request.user)
    context = get_user_groups_context(request.user)
    context['task'] = task
    return render(request, 'home/task_detail.html', context)

@login_required
def task_create(request):
    class TaskForm(forms.Form):  # Tạo form trực tiếp trong view
        title = forms.CharField(max_length=255)
        description = forms.CharField(widget=forms.Textarea)
        status = forms.ChoiceField(choices=[('pending', 'Pending'), ('in_progress', 'In Progress'), ('completed', 'Completed')])
        priority = forms.ChoiceField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')])

    if request.method == 'POST':
        form = TaskForm(request.POST)
        if form.is_valid():
            title = form.cleaned_data['title']
            description = form.cleaned_data['description']
            status = form.cleaned_data['status']
            priority = form.cleaned_data['priority']
            Task.objects.create(
                title=title,
                description=description,
                status=status,
                priority=priority,
                assigned_to=request.user
            )
            messages.success(request, 'Công việc đã được tạo thành công.')
            return redirect('task_list')
    else:
        form = TaskForm()
    context = get_user_groups_context(request.user)
    context['form'] = form
    return render(request, 'home/task_form.html', context)

@login_required
def task_update(request, pk):
    task = get_object_or_404(Task, pk=pk, assigned_to=request.user)
    class TaskForm(forms.Form):  # Tạo form trực tiếp trong view
        title = forms.CharField(max_length=255, initial=task.title)
        description = forms.CharField(widget=forms.Textarea, initial=task.description)
        status = forms.ChoiceField(choices=[('pending', 'Pending'), ('in_progress', 'In Progress'), ('completed', 'Completed')], initial=task.status)
        priority = forms.ChoiceField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')], initial=task.priority)

    if request.method == 'POST':
        form = TaskForm(request.POST)
        if form.is_valid():
            task.title = form.cleaned_data['title']
            task.description = form.cleaned_data['description']
            task.status = form.cleaned_data['status']
            task.priority = form.cleaned_data['priority']
            task.save()
            messages.success(request, 'Công việc đã được cập nhật thành công.')
            return redirect('task_list')
    else:
        form = TaskForm()
    context = get_user_groups_context(request.user)
    context['form'] = form
    return render(request, 'home/task_form.html', context)

@login_required
def task_delete(request, pk):
    task = get_object_or_404(Task, pk=pk, assigned_to=request.user)
    task.delete()
    messages.success(request, 'Công việc đã được xóa thành công.')
    return redirect('task_list')

# Quản lý phản hồi
@login_required
def feedback_list(request):
    feedbacks = Feedback.objects.filter(intern__user=request.user).order_by('-feedback_date')
    context = get_user_groups_context(request.user)
    context['feedbacks'] = feedbacks
    return render(request, 'home/feedback_list.html', context)

@login_required
def feedback_detail(request, pk):
    feedback = get_object_or_404(Feedback, pk=pk, intern__user=request.user)
    context = get_user_groups_context(request.user)
    context['feedback'] = feedback
    return render(request, 'home/feedback_detail.html', context)

@login_required
def feedback_create(request):
    class FeedbackForm(forms.Form):  # Tạo form trực tiếp trong view
        content = forms.CharField(widget=forms.Textarea)

    if request.method == 'POST':
        form = FeedbackForm(request.POST)
        if form.is_valid():
            content = form.cleaned_data['content']
            Feedback.objects.create(
                content=content,
                intern=Intern.objects.get(user=request.user)
            )
            messages.success(request, 'Phản hồi của bạn đã được gửi thành công.')
            return redirect('feedback_list')
    else:
        form = FeedbackForm()
    context = get_user_groups_context(request.user)
    context['form'] = form
    return render(request, 'home/feedback_form.html', context)

# Quản lý hồ sơ cá nhân
@login_required
def update_profile(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user = request.user  # Lấy thông tin người dùng hiện tại

            # Cập nhật thông tin
            user.first_name = data.get('firstName', user.first_name)
            user.last_name = data.get('lastName', user.last_name)
            user.email = data.get('email', user.email)
            user.save()

            return JsonResponse({'status': 'success', 'message': 'Thông tin đã được cập nhật thành công!'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    return JsonResponse({'status': 'error', 'message': 'Yêu cầu không hợp lệ.'}, status=400)

@login_required
def view_badges(request):
    context = get_user_groups_context(request.user)
    return render(request, 'home/view_badges.html', context)

@login_required
def start_remaining_tasks(request):
    remaining_tasks = Task.objects.exclude(status='completed')
    context = get_user_groups_context(request.user)
    context['remaining_tasks'] = remaining_tasks
    return render(request, 'home/start_remaining_tasks.html', context)

# Quản lý điểm danh
@login_required
def attendance_list(request):
    attendances = Attendance.objects.all()
    context = get_user_groups_context(request.user)
    context['attendances'] = attendances
    return render(request, 'home/attendance_list.html', context)

@login_required
def attendance_detail(request, pk):
    attendance = get_object_or_404(Attendance, pk=pk)
    context = get_user_groups_context(request.user)
    context['attendance'] = attendance
    return render(request, 'home/attendance_detail.html', context)

# Quản lý điểm danh
@login_required
def attendance_create(request):
    context = get_user_groups_context(request.user)  # Khởi tạo context

    if request.method == 'POST':
        # Xử lý form tạo mới điểm danh
        pass
    else:
        # Hiển thị form tạo mới
        pass
    return render(request, 'home/attendance_form.html', context)

@login_required
def attendance_update(request, pk):
    attendance = get_object_or_404(Attendance, pk=pk)
    context = get_user_groups_context(request.user)  # Khởi tạo context
    context['attendance'] = attendance  # Thêm thông tin điểm danh vào context

    if request.method == 'POST':
        # Xử lý form cập nhật điểm danh
        pass
    else:
        # Hiển thị form cập nhật
        pass
    return render(request, 'home/attendance_form.html', context)

@login_required
def attendance_delete(request, pk):
    attendance = get_object_or_404(Attendance, pk=pk)
    attendance.delete()
    messages.success(request, 'Điểm danh đã được xóa thành công.')
    return redirect('attendance_list')

# Quản lý sự kiện
@login_required
def event_list(request):
    events = Event.objects.all()
    context = get_user_groups_context(request.user)
    context['events'] = events
    return render(request, 'home/event_list.html', context)

@login_required
def event_detail(request, pk):
    event = get_object_or_404(Event, pk=pk)
    context = get_user_groups_context(request.user)
    context['event'] = event
    return render(request, 'home/event_detail.html', context)

# Quản lý sự kiện
@login_required
def event_create(request):
    context = get_user_groups_context(request.user)  # Khởi tạo context

    if request.method == 'POST':
        # Xử lý form tạo mới sự kiện
        pass
    else:
        # Hiển thị form tạo mới
        pass
    return render(request, 'home/event_form.html', context)

@login_required
def event_update(request, pk):
    event = get_object_or_404(Event, pk=pk)
    context = get_user_groups_context(request.user)  # Khởi tạo context
    context['event'] = event  # Thêm thông tin sự kiện vào context

    if request.method == 'POST':
        # Xử lý form cập nhật sự kiện
        pass
    else:
        # Hiển thị form cập nhật
        pass
    return render(request, 'home/event_form.html', context)

@login_required
def event_delete(request, pk):
    event = get_object_or_404(Event, pk=pk)
    event.delete()
    messages.success(request, 'Sự kiện đã được xóa thành công.')
    return redirect('event_list')

@login_required
def report_detail(request, pk):
    report = get_object_or_404(Report, pk=pk, user=request.user)
    context = get_user_groups_context(request.user)
    context['report'] = report
    return render(request, 'home/report_detail.html', context)

# Quản lý hiệu suất
@login_required
def performance_list(request):
    performances = Performance.objects.filter(intern__user=request.user).order_by('-evaluation_date')
    context = get_user_groups_context(request.user)
    context['performances'] = performances
    return render(request, 'home/performance_list.html', context)

@login_required
def performance_detail(request, pk):
    performance = get_object_or_404(Performance, pk=pk, intern__user=request.user)
    context = get_user_groups_context(request.user)
    context['performance'] = performance
    return render(request, 'home/performance_detail.html', context)

@login_required
def enroll_training_program(request, pk):
    program = get_object_or_404(TrainingProgram, pk=pk)

@user_passes_test(lambda u: is_hr(u) or u.is_superuser)
def edit_recruitment(request, pk):
    recruitment = get_object_or_404(Recruitment, pk=pk)
    if request.method == 'POST':
        form = RecruitmentForm(request.POST, instance=recruitment)
        if form.is_valid():
            form.save()
            messages.success(request, 'Chiến dịch tuyển dụng đã được cập nhật.')
            return redirect('quanlituyendung')
    else:
        form = RecruitmentForm(instance=recruitment)
    
    context = get_user_groups_context(request.user)
    context['form'] = form
    return render(request, 'Quanlituyendung/edit_recruitment.html', context)

@user_passes_test(lambda u: is_hr(u) or u.is_superuser)
def delete_recruitment(request, pk):
    recruitment = get_object_or_404(Recruitment, pk=pk)
    recruitment.delete()
    messages.success(request, 'Chiến dịch tuyển dụng đã được xóa.')
    return redirect('quanlituyendung')

@login_required
def create_job_post(request):
    if request.method == 'POST':
        title = request.POST.get('jobPostTitle')
        description = request.POST.get('jobPostDescription')
        platform = request.POST.get('jobPostPlatform')

        # Kiểm tra xem các trường bắt buộc có được điền hay không
        if not title:
            messages.error(request, 'Tiêu đề không được để trống.')
            return redirect('quanlituyendung')
        if not platform:
            messages.error(request, 'Nền tảng không được để trống.')
            return redirect('quanlituyendung')

        # Tạo JobPost và lưu vào cơ sở dữ liệu
        try:
            JobPost.objects.create(
                title=title,
                description=description,
                platform=platform,
                posted_by=request.user
            )
            messages.success(request, 'Bài đăng tuyển dụng đã được tạo thành công.')
        except Exception as e:
            messages.error(request, f'Lỗi khi tạo bài đăng: {str(e)}')

        return redirect('quanlituyendung')
    

@require_POST
def generate_report(request):
    title = request.POST.get('title')
    content = request.POST.get('content')
    review_notes = request.POST.get('review_notes', '')

    if not title or not content:
        return JsonResponse({'status': 'error', 'message': 'Vui lòng điền đầy đủ thông tin.'})

    # Tạo báo cáo
    report = Report(
        title=title,
        content=content,
        review_notes=review_notes,
        user=request.user,  # Người tạo báo cáo
        reviewed_by=request.user,  # Người đánh giá là tài khoản hiện tại
        review_date=timezone.now(),  # Ngày đánh giá là thời gian hiện tại
    )
    report.save()

    return JsonResponse({'status': 'success', 'message': 'Báo cáo đã được tạo thành công!'})

@login_required
def report_list(request):
    reports = Report.objects.filter(user=request.user)
    print(reports)  # In ra danh sách báo cáo để kiểm tra
    context = {'reports': reports}
    return render(request, 'home/report_list.html', context)

@login_required
def integrate_system(request):
    if request.method == 'POST':
        system = request.POST.get('integrationSystem')
        Integration.objects.create(
            system=system,
            integrated_by=request.user
        )
        messages.success(request, 'Hệ thống đã được tích hợp thành công.')
        return redirect('quanlituyendung')
    
@login_required
def manage_permissions(request):
    if request.method == 'POST':
        user_id = request.POST.get('userRole')
        role = request.POST.get('userRole')
        permission = request.POST.get('userPermissions')
        try:
            user = User.objects.get(id=user_id)
            group, created = Group.objects.get_or_create(name=role)
            user.groups.add(group)
            messages.success(request, f'Quyền truy cập của {user.username} đã được cập nhật thành công.')
        except User.DoesNotExist:
            messages.error(request, 'Người dùng không tồn tại.')
        return redirect('quanlituyendung')  # Chuyển hướng về trang quản lý tuyển dụng
    return render(request, 'manage_permissions.html')  # Hiển thị form quản lý quyền truy cập

def create_recruitment(request):
    if request.method == 'POST':
        position = request.POST.get('position')
        description = request.POST.get('description')
        requirements = request.POST.get('requirements')
        deadline = request.POST.get('deadline')
        location = request.POST.get('location')
        salary_range = request.POST.get('salaryRange')
        
        # Debug: In ra console để kiểm tra dữ liệu
        print(f"Position: {position}")
        print(f"Description: {description}")
        print(f"Requirements: {requirements}")
        print(f"Deadline: {deadline}")
        print(f"Location: {location}")
        print(f"Salary Range: {salary_range}")
        
        try:
            Recruitment.objects.create(
                position=position,
                description=description,
                requirements=requirements,
                deadline=deadline,
                posted_by=request.user,
                location=location,
                salary_range=salary_range
            )
            messages.success(request, 'Chiến dịch tuyển dụng đã được tạo thành công.')
        except Exception as e:
            messages.error(request, f'Lỗi khi tạo chiến dịch: {str(e)}')
        
        return redirect('quanlituyendung')
    
@login_required
def manage_candidates(request):
    # Sắp xếp các ứng viên theo ngày ứng tuyển giảm dần
    candidates = Candidate.objects.all().order_by('-applied_date')

    # Tìm kiếm
    candidate_search = request.GET.get('candidateSearch', '')
    if candidate_search:
        candidates = candidates.filter(name__icontains=candidate_search)

    # Lọc
    candidate_filter = request.GET.get('candidateFilter', 'all')
    if candidate_filter == 'new':
        candidates = candidates.filter(status='new')
    elif candidate_filter == 'interviewed':
        candidates = candidates.filter(status='interviewed')

    # Phân trang
    paginator = Paginator(candidates, 10)  # 10 ứng viên mỗi trang
    page_number = request.GET.get('page')
    candidates = paginator.get_page(page_number)

    context = {
        'candidates': candidates,
        'candidate_search': candidate_search,
        'candidate_filter': candidate_filter,
    }
    return render(request, 'Quanlituyendung/quanlituyendung.html', context)

@csrf_exempt
def schedule_interview(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        candidate_id = data.get('candidate_id')
        interview_date = data.get('interview_date')
        interview_time = data.get('interview_time')
        location = data.get('location')
        notes = data.get('notes')
        interviewer_id = request.user.id  # Lấy ID của người dùng hiện tại

        try:
            candidate = Candidate.objects.get(id=candidate_id)
            interviewer = User.objects.get(id=interviewer_id)
            interview = Interview.objects.create(
                candidate=candidate,
                interview_date=interview_date,
                interview_time=interview_time,
                interviewer=interviewer,
                location=location,
                notes=notes,
            )
            return JsonResponse({"message": "Lịch phỏng vấn đã được tạo thành công!", "id": interview.id}, status=201)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    return JsonResponse({"error": "Phương thức không được hỗ trợ"}, status=405)

@login_required
def evaluate_candidate(request, candidate_id):
    if request.method == 'POST':
        candidate = get_object_or_404(Candidate, id=candidate_id)
        evaluation_text = request.POST.get('candidateEvaluation')
        evaluation_score = request.POST.get('evaluationScore')

        # Kiểm tra dữ liệu đầu vào
        if not evaluation_text or not evaluation_score:
            messages.error(request, 'Vui lòng điền đầy đủ thông tin.')
            return JsonResponse({'status': 'error', 'message': 'Vui lòng điền đầy đủ thông tin.'}, status=400)

        try:
            # Chuyển đổi điểm số sang kiểu số nguyên
            evaluation_score = int(evaluation_score)

            # Kiểm tra xem điểm số có hợp lệ không
            if evaluation_score < 0 or evaluation_score > 100:
                messages.error(request, 'Điểm số phải nằm trong khoảng từ 0 đến 100.')
                return JsonResponse({'status': 'error', 'message': 'Điểm số phải nằm trong khoảng từ 0 đến 100.'}, status=400)

            # Tạo hoặc cập nhật đánh giá
            evaluation, created = CandidateEvaluation.objects.update_or_create(
                candidate=candidate,
                evaluator=request.user,
                defaults={
                    'comments': evaluation_text,
                    'score': evaluation_score,
                }
            )
            messages.success(request, '✅ Đánh giá đã được lưu thành công.')
            return JsonResponse({'status': 'success', 'message': 'Đánh giá đã được lưu thành công.'})
        except Exception as e:
            messages.error(request, f'Có lỗi xảy ra: {str(e)}')
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    return JsonResponse({'status': 'error', 'message': 'Yêu cầu không hợp lệ.'}, status=400)

@login_required
def interview_list(request):
    interviews = Interview.objects.all().order_by('-interview_date')
    context = {
        'interviews': interviews,
    }
    return render(request, 'Lichphongvan/lichphongvan.html', context)

@login_required
def edit_interview(request, pk):
    interview = get_object_or_404(Interview, pk=pk)
    if request.method == 'POST':
        form = InterviewForm(request.POST, instance=interview)
        if form.is_valid():
            form.save()
            messages.success(request, 'Lịch phỏng vấn đã được cập nhật thành công!')
            return redirect('schedule_interview')
    else:
        form = InterviewForm(instance=interview)

    context = {
        'form': form,
    }
    return render(request, 'Lichphongvan/edit_interview.html', context)


@login_required
@require_http_methods(["GET", "POST"])
def performance_api(request):
    if request.method == 'GET':
        performances = Performance.objects.filter(evaluator=request.user).select_related('intern')
        data = [{
            "id": p.id,
            "intern_id": p.intern.id,
            "intern_name": p.intern.full_name,
            "metric": p.evaluation_period,
            "score": float(p.score),
            "feedback": p.comments,
            "rating": p.rating,
            "rating_text": get_rating_text(p.rating)
        } for p in performances]
        return JsonResponse(data, safe=False)
    
    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            intern_id = data.get('intern_id')
            score = data.get('score')
            comments = data.get('comments')
            
            intern = Intern.objects.get(id=intern_id)
            performance = Performance.objects.create(
                intern=intern,
                evaluator=request.user,
                score=score,
                comments=comments,
                evaluation_period="Hàng tuần"  # Có thể điều chỉnh theo logic
            )
            return JsonResponse({"status": "success", "id": performance.id}, status=201)
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=400)

def get_rating_text(rating):
    rating_dict = {
        1: 'Rất kém',
        2: 'Kém',
        3: 'Trung bình',
        4: 'Tốt',
        5: 'Xuất sắc'
    }
    return rating_dict.get(rating, 'Chưa đánh giá')

@login_required
@require_http_methods(["PUT", "DELETE"])
def performance_detail_api(request, pk):
    try:
        performance = Performance.objects.get(pk=pk, evaluator=request.user)
    except Performance.DoesNotExist:
        return JsonResponse({"status": "error", "message": "Not found"}, status=404)
    
    if request.method == "PUT":
        try:
            data = json.loads(request.body)
            new_intern_id = data.get('intern_id')
            new_period = data.get('evaluation_period')
            rating = data.get('rating')  # Lấy giá trị đánh giá
            
            # Kiểm tra trùng lặp với intern và period mới
            if Performance.objects.filter(
                intern_id=new_intern_id,
                evaluator=request.user,
                evaluation_period=new_period
            ).exclude(pk=pk).exists():
                return JsonResponse(
                    {"status": "error", "message": "Đánh giá này đã tồn tại"},
                    status=400
                )
            
            # Cập nhật dữ liệu
            performance.intern_id = new_intern_id
            performance.score = data.get('score')
            performance.comments = data.get('comments')
            performance.evaluation_period = new_period
            performance.rating = rating  # Cập nhật đánh giá
            performance.save()
            
            return JsonResponse({"status": "success"})
        
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=400)
    
    elif request.method == "DELETE":
        performance.delete()
        return JsonResponse({"status": "success"})

@login_required
def get_active_interns(request):
    interns = Intern.objects.filter(is_active=True)
    data = [{"id": i.id, "name": i.full_name} for i in interns]
    return JsonResponse(data, safe=False)

@login_required
def communication_feedback(request):
    # Xử lý form tạo mới
    if request.method == 'POST':
        form = CommunicationForm(request.POST)
        if form.is_valid():
            communication = form.save(commit=False)
            communication.sender = request.user
            communication.save()
            return JsonResponse({
                'status': 'success',
                'data': {
                    'id': communication.id,
                    'sender': communication.sender.get_full_name(),
                    'receiver': communication.receiver.get_full_name(),
                    'message': communication.message,
                    'feedback_type': communication.get_feedback_type_display(),
                    'created_at': communication.created_at.strftime("%Y-%m-%d %H:%M")
                }
            })
        else:
            return JsonResponse({'status': 'error', 'errors': form.errors}, status=400)

    # Hiển thị danh sách
    communications = Communication.objects.filter(
        models.Q(sender=request.user) | 
        models.Q(receiver=request.user)
    ).select_related('sender', 'receiver').order_by('-created_at')
    
    return render(request, 'content.html', {
        'communications': communications,
        **get_user_groups_context(request.user)
    })

@login_required
@require_http_methods(["DELETE"])
def delete_communication(request, pk):
    try:
        communication = Communication.objects.get(
            pk=pk, 
            sender=request.user  # Chỉ người gửi mới được xóa
        )
        communication.delete()
        return JsonResponse({'status': 'success'})
    except Communication.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Không tìm thấy thông tin'}, status=404)

@login_required
@require_http_methods(["PUT"])
def update_communication(request, pk):
    try:
        communication = Communication.objects.get(pk=pk, sender=request.user)
        data = json.loads(request.body)
        form = CommunicationForm(data, instance=communication)
        
        if form.is_valid():
            form.save()
            return JsonResponse({
                'status': 'success',
                'data': {
                    'id': communication.id,
                    'receiver': communication.receiver.get_full_name(),
                    'message': communication.message,
                    'feedback_type': communication.get_feedback_type_display()
                }
            })
        return JsonResponse({'status': 'error', 'errors': form.errors}, status=400)
    except Communication.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Không tìm thấy thông tin'}, status=404)
    
@login_required
def get_profile(request):
    try:
        user = request.user  # Lấy thông tin người dùng hiện tại
        profile_data = {
            'username': user.username,
            'firstName': user.first_name,
            'lastName': user.last_name,
            'email': user.email,
        }
        return JsonResponse({'status': 'success', 'data': profile_data})
    except User.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Không tìm thấy thông tin người dùng.'}, status=404)

@csrf_exempt
@require_http_methods(["POST"])
def schedule_interview_api(request):
    try:
        data = json.loads(request.body)
        candidate_id = data.get('candidate_id')
        interview_date = data.get('interview_date')
        interview_time = data.get('interview_time')
        location = data.get('location')
        notes = data.get('notes')

        # Lấy người phỏng vấn từ request.user
        interviewer = request.user  # Người phỏng vấn là người dùng hiện tại

        # Kiểm tra xem candidate có tồn tại không
        candidate = Candidate.objects.get(id=candidate_id)

        # Tạo lịch phỏng vấn
        interview = Interview.objects.create(
            candidate=candidate,
            interview_date=interview_date,
            interview_time=interview_time,
            interviewer=interviewer,
            location=location,
            notes=notes
        )

        return JsonResponse({
            'status': 'success',
            'data': {
                'id': interview.id,
                'candidate_name': candidate.name,
                'interview_date': interview.interview_date,
                'interview_time': interview.interview_time,
                'interviewer_name': interviewer.username,
                'location': interview.location,
                'notes': interview.notes
            }
        }, status=201)  # Trả về status 201 (Created)
    except Candidate.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Ứng viên không tồn tại'}, status=404)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

def get_interviews(request):
    interviews = Interview.objects.all()
    data = [
        {
            "id": interview.id,
            "candidate_id": interview.candidate.id,
            "candidate_name": interview.candidate.name,
            "interview_date": interview.interview_date,
            "interview_time": interview.interview_time,
            "interviewer_name": interview.interviewer.username,
            "location": interview.location,
            "notes": interview.notes,
        }
        for interview in interviews
    ]
    return JsonResponse(data, safe=False)

@csrf_exempt
def update_interview(request, pk):
    if request.method == 'PUT':
        data = json.loads(request.body)
        interview_date = data.get('interview_date')
        interview_time = data.get('interview_time')
        location = data.get('location')
        notes = data.get('notes')

        try:
            interview = Interview.objects.get(id=pk)
            interview.interview_date = interview_date
            interview.interview_time = interview_time
            interview.location = location
            interview.notes = notes
            interview.save()
            return JsonResponse({"message": "Lịch phỏng vấn đã được cập nhật thành công!"}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    return JsonResponse({"error": "Phương thức không được hỗ trợ"}, status=405)

@csrf_exempt
def delete_interview(request, pk):
    if request.method == 'DELETE':
        try:
            interview = Interview.objects.get(id=pk)
            interview.delete()
            return JsonResponse({"message": "Lịch phỏng vấn đã được xóa thành công!"}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    return JsonResponse({"error": "Phương thức không được hỗ trợ"}, status=405)

def get_interview_detail(request, pk):
    try:
        interview = Interview.objects.get(id=pk)
        data = {
            "id": interview.id,
            "candidate_id": interview.candidate.id,
            "candidate_name": interview.candidate.name,
            "interview_date": interview.interview_date,
            "interview_time": interview.interview_time,
            "interviewer_name": interview.interviewer.username,
            "location": interview.location,
            "notes": interview.notes,
        }
        return JsonResponse(data)
    except Interview.DoesNotExist:
        return JsonResponse({"error": "Interview not found"}, status=404)
    
def get_candidates(request):
    candidates = Candidate.objects.all()
    data = [{"id": candidate.id, "name": candidate.name} for candidate in candidates]
    return JsonResponse(data, safe=False)

def get_interview_api(request, pk):
    interview = get_object_or_404(Interview, pk=pk)
    data = {
        "id": interview.id,
        "candidate_id": interview.candidate.id,
        "interview_date": interview.interview_date.isoformat() if interview.interview_date else None,
        "interview_time": interview.interview_time.isoformat() if interview.interview_time else None,
        "location": interview.location,
        "notes": interview.notes
    }
    return JsonResponse(data)

@login_required
@require_http_methods(["GET", "POST"])
def training_program_api(request):
    if request.method == 'GET':
        programs = TrainingProgram.objects.all().prefetch_related('interns')
        data = [{
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "start_date": p.start_date.strftime('%Y-%m-%d'),
            "end_date": p.end_date.strftime('%Y-%m-%d'),
            "trainer": p.trainer,
            "max_participants": p.max_participants,
            "interns": [intern.full_name for intern in p.interns.all()]
        } for p in programs]
        return JsonResponse(data, safe=False)
    
    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            name = data.get('name')
            description = data.get('description')
            start_date = data.get('start_date')
            end_date = data.get('end_date')
            trainer = data.get('trainer')
            max_participants = data.get('max_participants')
            intern_id = data.get('intern_id')
            
            intern = Intern.objects.get(id=intern_id)
            program = TrainingProgram.objects.create(
                name=name,
                description=description,
                start_date=start_date,
                end_date=end_date,
                trainer=trainer,
                max_participants=max_participants
            )
            program.interns.add(intern)
            return JsonResponse({"status": "success", "id": program.id}, status=201)
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=400)
        
@login_required
@require_http_methods(["PUT", "DELETE"])
def training_program_detail_api(request, pk):
    try:
        program = TrainingProgram.objects.get(pk=pk)
    except TrainingProgram.DoesNotExist:
        return JsonResponse({"status": "error", "message": "Not found"}, status=404)
    
    if request.method == "PUT":
        try:
            data = json.loads(request.body)
            program.name = data.get('name', program.name)
            program.description = data.get('description', program.description)
            program.start_date = data.get('start_date', program.start_date)
            program.end_date = data.get('end_date', program.end_date)
            program.trainer = data.get('trainer', program.trainer)
            program.max_participants = data.get('max_participants', program.max_participants)
            intern_id = data.get('intern_id')
            if intern_id:
                intern = Intern.objects.get(id=intern_id)
                program.interns.clear()
                program.interns.add(intern)
            program.save()
            return JsonResponse({"status": "success"})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=400)
    
    elif request.method == "DELETE":
        program.delete()
        return JsonResponse({"status": "success"})

@login_required
def get_notifications(request):
    try:
        if not request.user.is_authenticated:
            return JsonResponse({'error': 'Unauthorized'}, status=401)
        
        notifications = Notification.objects.filter(user=request.user, is_read=False).order_by('-created_at')
        notifications_data = [
            {
                'id': notification.id,
                'message': notification.message,
                'created_at': notification.created_at.strftime("%H:%M %d/%m/%Y"),
                'link': notification.link if notification.link else '#',
            }
            for notification in notifications
        ]
        logger.info(f"Notifications data: {notifications_data}")
        return JsonResponse({'notifications': notifications_data})
    except Exception as e:
        logger.error(f"Error in get_notifications: {e}")
        return JsonResponse({'error': str(e)}, status=500)

@require_POST
def mark_notification_as_read(request, notification_id):
    try:
        notification = Notification.objects.get(id=notification_id, user=request.user)
        notification.is_read = True
        notification.save()
        return JsonResponse({'status': 'success'})
    except Notification.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Notification not found'}, status=404)

    
@require_http_methods(["GET"])
def get_report(request, report_id):
    report = Report.objects.get(id=report_id)
    data = {
        'title': report.title,
        'content': report.content,
        'review_notes': report.review_notes,
    }
    return JsonResponse(data)

@require_POST
def update_report(request, report_id):
    report = Report.objects.get(id=report_id)
    report.title = request.POST.get('title')
    report.content = request.POST.get('content')
    report.review_notes = request.POST.get('review_notes')
    report.save()
    return JsonResponse({'status': 'success', 'message': 'Báo cáo đã được cập nhật!'})
    
@require_POST
def delete_report(request, report_id):
    try:
        report = Report.objects.get(id=report_id)
        
        # Kiểm tra quyền xóa
        if report.user != request.user and not request.user.is_superuser:
            return JsonResponse({'status': 'error', 'message': 'Bạn không có quyền xóa báo cáo này.'}, status=403)
        
        report.delete()
        return JsonResponse({'status': 'success', 'message': 'Báo cáo đã được xóa!'})
    except ObjectDoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Báo cáo không tồn tại.'}, status=404)
    

#
@login_required
def add_profile(request):
    if request.method == 'POST':
        form = ProfileForm(request.POST, request.FILES)  # Xử lý dữ liệu và file
        if form.is_valid():
            form.save()  # Lưu dữ liệu vào database
            return JsonResponse({'success': True, 'message': 'Hồ sơ đã được lưu thành công!'})
        else:
            return JsonResponse({'success': False, 'errors': form.errors})
    return JsonResponse({'success': False, 'message': 'Yêu cầu không hợp lệ!'})

@login_required
def get_profiles(request):
    profiles = Profile.objects.all()  # Lấy tất cả hồ sơ từ database
    data = []  # Tạo một list để chứa dữ liệu

    # Duyệt qua từng hồ sơ và thêm vào list
    for profile in profiles:
        data.append({
            'id': profile.id,
            'full_name': profile.full_name,
            'dob': profile.dob.strftime('%Y-%m-%d'),  # Định dạng ngày tháng
            'gender': profile.gender,
            'email': profile.email,
            'phone': profile.phone,
            'address': profile.address,
            'education': profile.education,
            'workExperience': profile.workExperience,
            'documents': profile.documents.url if profile.documents else None,  # Lấy URL file nếu có
        })

    return JsonResponse(data, safe=False)  # Trả về dữ liệu dưới dạng JSON

def intern_list(request):
    # Lấy các tham số từ query string
    search = request.GET.get('search', '')
    status = request.GET.get('status', '')
    department_id = request.GET.get('department', '')
    page = request.GET.get('page', 1)
    per_page = request.GET.get('per_page', 10)

    # Lấy tất cả thực tập sinh
    interns = Intern.objects.all()

    # Áp dụng bộ lọc tìm kiếm
    if search:
        interns = interns.filter(
            Q(full_name__icontains=search) | 
            Q(email__icontains=search) |
            Q(phone__icontains=search)
        )

    # Áp dụng bộ lọc trạng thái
    if status:
        interns = interns.filter(status=status)

    # Áp dụng bộ lọc phòng ban
    if department_id:
        interns = interns.filter(department_id=department_id)

    # Phân trang
    paginator = Paginator(interns, per_page)
    page_obj = paginator.get_page(page)

    # Chuẩn bị dữ liệu trả về
    data = {
        'interns': [
            {
                'id': intern.id,
                'full_name': intern.full_name,
                'email': intern.email,
                'phone': intern.phone,
                'department': intern.department.name if intern.department else 'N/A',
                'status': intern.get_status_display(),
            }
            for intern in page_obj
        ],
        'total': paginator.count,
        'page': page_obj.number,
        'per_page': per_page,
    }
    return JsonResponse(data)

def intern_detail(request, intern_id):
    intern = get_object_or_404(Intern, id=intern_id)
    data = {
        'id': intern.id,
        'full_name': intern.full_name,
        'email': intern.email,
        'phone': intern.phone,
        'department': intern.department.name if intern.department else 'N/A',
        'status': intern.get_status_display(),
    }
    return JsonResponse(data)

# View để chỉnh sửa thực tập sinh
def intern_edit(request, intern_id):
    intern = get_object_or_404(Intern, id=intern_id)
    if request.method == 'POST':
        intern.first_name = request.POST.get('first_name')
        intern.last_name = request.POST.get('last_name')
        intern.email = request.POST.get('email')
        intern.phone = request.POST.get('phone')
        intern.save()
        return JsonResponse({'success': True, 'message': 'Intern updated successfully!'})
    return JsonResponse({'success': False, 'message': 'Invalid request method.'})

# View để xóa thực tập sinh
def intern_delete(request, intern_id):
    intern = get_object_or_404(Intern, id=intern_id)
    if request.method == 'POST':
        intern.delete()
        return JsonResponse({'success': True, 'message': 'Intern deleted successfully!'})
    return JsonResponse({'success': False, 'message': 'Invalid request method.'})



