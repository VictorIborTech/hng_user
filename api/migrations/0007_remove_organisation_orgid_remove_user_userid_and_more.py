# Generated by Django 5.0.6 on 2024-07-07 07:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0006_alter_organisation_orgid_alter_user_userid'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='organisation',
            name='orgId',
        ),
        migrations.RemoveField(
            model_name='user',
            name='userId',
        ),
        migrations.AlterField(
            model_name='organisation',
            name='id',
            field=models.AutoField(primary_key=True, serialize=False, unique=True),
        ),
        migrations.AlterField(
            model_name='user',
            name='id',
            field=models.AutoField(primary_key=True, serialize=False, unique=True),
        ),
    ]
