# Generated by Django 5.0 on 2023-12-29 18:08

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='chat',
            old_name='date',
            new_name='created_at',
        ),
    ]
