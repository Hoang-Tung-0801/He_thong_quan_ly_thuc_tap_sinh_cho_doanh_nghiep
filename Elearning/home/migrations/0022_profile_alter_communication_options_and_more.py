# Generated by Django 5.1.4 on 2025-02-14 17:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0021_alter_recruitment_location_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Profile',
            fields=[
                ('trainee_id', models.CharField(max_length=50, primary_key=True, serialize=False, verbose_name='Mã thực tập sinh')),
                ('full_name', models.CharField(max_length=100, verbose_name='Họ và tên')),
                ('dob', models.DateField(verbose_name='Ngày sinh')),
                ('gender', models.CharField(max_length=20, verbose_name='Giới tính')),
                ('email', models.EmailField(max_length=254, verbose_name='Email')),
                ('phone', models.CharField(max_length=20, verbose_name='Số điện thoại')),
                ('address', models.CharField(max_length=200, verbose_name='Địa chỉ')),
                ('education', models.CharField(max_length=100, verbose_name='Trình độ học vấn')),
                ('work_experience', models.TextField(blank=True, verbose_name='Kinh nghiệm làm việc')),
            ],
        ),
        migrations.AlterModelOptions(
            name='communication',
            options={'ordering': ['-created_at']},
        ),
        migrations.RemoveField(
            model_name='communication',
            name='updated_at',
        ),
        migrations.AlterField(
            model_name='recruitment',
            name='location',
            field=models.CharField(blank=True, max_length=200, null=True, verbose_name='Địa điểm'),
        ),
        migrations.AlterField(
            model_name='recruitment',
            name='salary_range',
            field=models.CharField(blank=True, max_length=100, null=True, verbose_name='Mức lương'),
        ),
    ]
