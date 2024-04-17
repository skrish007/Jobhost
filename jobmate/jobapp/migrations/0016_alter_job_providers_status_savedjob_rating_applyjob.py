# Generated by Django 4.2.7 on 2023-12-03 02:51

from django.conf import settings
import django.core.validators
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('jobapp', '0015_alter_job_providers_status'),
    ]

    operations = [
        migrations.AlterField(
            model_name='job_providers',
            name='status',
            field=models.BooleanField(default=False, verbose_name='Status'),
        ),
        migrations.CreateModel(
            name='SavedJob',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('stime', models.DateTimeField(default=django.utils.timezone.now)),
                ('job_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='jobapp.postjobs')),
                ('pro_id', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='jobapp.job_providers')),
                ('seeker_id', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='jobapp.job_seekers')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Rating',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(blank=True, max_length=255, null=True)),
                ('stars', models.DecimalField(decimal_places=2, max_digits=3, validators=[django.core.validators.MinValueValidator(0), django.core.validators.MaxValueValidator(5)])),
                ('comment', models.TextField(blank=True, null=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('pro_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='jobapp.job_providers')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='ApplyJob',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('application_date', models.DateTimeField(default=django.utils.timezone.now)),
                ('status', models.CharField(default='Pending', max_length=20)),
                ('job_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='jobapp.postjobs')),
                ('pro_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='jobapp.job_providers')),
                ('seeker_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='jobapp.job_seekers')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]