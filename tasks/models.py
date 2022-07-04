from django.db import models
from django.utils.translation import gettext as _
from accounts.models import Owner, TrackingModel
# Create your models here.

# In_progress, Complete,Pending


class Category(TrackingModel):
    category = models.CharField(_("Category"),
                                max_length=108)
    owner = models.ForeignKey(Owner, on_delete=models.CASCADE)
    completed = models.BooleanField(default=False)

    def __str__(self):
        return str(self.category)

    class Meta:
        ordering = ("id",)
        verbose_name_plural = "Categories"


class Task(TrackingModel):
    task = models.CharField(_("task"), max_length=89)
    owner = models.ForeignKey(Owner,
                              on_delete=models.CASCADE)
    category = models.ForeignKey(
        Category, on_delete=models.CASCADE,
        related_name="categories", default=1
    )
    completed = models.BooleanField(_("completed"), default=False)
    note = models.TextField(_("Note"), blank=True, null=True)
    due_date = models.DateTimeField(_("Date due"), blank=True, null=True)
    important = models.BooleanField(_("important"), default=False)

    def __str__(self):
        return str(self.task)

    class Meta:
        verbose_name_plural = "Tasks"
        ordering = ("-important", "due_date",)
