from django.db import models

# Create your models here.
class Report(models.Model):
    title = models.CharField(max_length=255)
    creation_date = models.DateTimeField(auto_now_add=True)
    content = models.TextField()
    report_type = models.CharField(max_length=50)