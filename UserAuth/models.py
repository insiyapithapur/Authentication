from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class otp(models.Model):
    username = models.ForeignKey(User,on_delete=models.CASCADE)
    code = models.IntegerField()

    # def __str__(self):
    #     return self.username