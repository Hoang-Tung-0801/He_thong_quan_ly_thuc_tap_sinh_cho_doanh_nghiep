# Generated by Django 5.1.4 on 2025-02-06 07:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0009_candidate_candidateevaluation_integration_interview_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='jobpost',
            name='is_active',
            field=models.BooleanField(default=True, verbose_name='Đang hoạt động'),
        ),
    ]
