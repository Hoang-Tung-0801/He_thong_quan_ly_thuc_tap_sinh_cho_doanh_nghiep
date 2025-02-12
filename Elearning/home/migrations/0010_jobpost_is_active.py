from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('home', '0009_candidate_candidateevaluation_integration_interview_and_more'),
    ]

    operations = [
        migrations.RunSQL(
            sql="ALTER TABLE JobPost ADD COLUMN is_active BOOLEAN DEFAULT TRUE;",
            reverse_sql="ALTER TABLE JobPost DROP COLUMN is_active;",
            state_operations=[
                migrations.AddField(
                    model_name='jobpost',
                    name='is_active',
                    field=models.BooleanField(default=True, verbose_name='Đang hoạt động'),
                ),
            ],
        ),
    ]