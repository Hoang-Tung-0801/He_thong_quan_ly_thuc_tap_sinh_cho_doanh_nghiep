# Generated by Django 5.1.4 on 2025-02-12 09:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0017_delete_userprofile'),
    ]

    operations = [
        migrations.AddField(
            model_name='jobpost',
            name='is_active',
            field=models.BooleanField(default=True, verbose_name='Đang hoạt động'),
        ),
    ]
