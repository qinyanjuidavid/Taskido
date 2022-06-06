from accounts.models import User, Owner
from django.db.models.signals import post_save
from django.dispatch import receiver

from tasks.models import Category


@receiver(post_save, sender=Owner)
def post_save_create_Category(sender, instance, created, *args, **kwargs):
    if created:
        Category.objects.create(category="Tasks", owner=instance)
