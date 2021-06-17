from django.db import models
from django.contrib.auth.models import User


# class UserManager(BaseUserManager):
#     """Define a model manager for User model with no username field."""
#
#     use_in_migrations = True
#
#     def _create_user(self, email, password, **extra_fields):
#         """Create and save a User with the given email and password."""
#         if not email:
#             raise ValueError('The given email must be set')
#         email = self.normalize_email(email)
#         user = self.model(email=email, **extra_fields)
#         user.set_password(password)
#         user.save(using=self._db)
#         return user
#
#     def create_user(self, email, password=None, **extra_fields):
#         """Create and save a regular User with the given email and password."""
#         extra_fields.setdefault('is_staff', False)
#         extra_fields.setdefault('is_superuser', False)
#         return self._create_user(email, password, **extra_fields)
#
#     def create_superuser(self, email, password, **extra_fields):
#         """Create and save a SuperUser with the given email and password."""
#         extra_fields.setdefault('is_staff', True)
#         extra_fields.setdefault('is_superuser', True)
#
#         if extra_fields.get('is_staff') is not True:
#             raise ValueError('Superuser must have is_staff=True.')
#         if extra_fields.get('is_superuser') is not True:
#             raise ValueError('Superuser must have is_superuser=True.')
#
#         return self._create_user(email, password, **extra_fields)
#
#
# class User(AbstractUser):
#     """User model."""
#
#     username = None
#     email = models.EmailField(_('email address'), unique=True)
#
#     USERNAME_FIELD = 'email'
#     REQUIRED_FIELDS = []
#
#     objects = UserManager()


# Create your models here.
class Logger(models.Model):
    #owner = models.ForeignKey(User, default=None, blank=True, on_delete=models.SET_NULL,
    #                          null=True)
    email = models.CharField(max_length=255)
    date = models.DateTimeField()
    threshold = models.IntegerField(blank=True, null=True)
    type_attack = models.CharField(max_length=255)
    command = models.CharField(max_length=1024)
    if_warn = models.BooleanField()

   # def __str__(self):
   #     return self.email


class UsersDemo(models.Model):
    username = models.CharField(max_length=255)
    password = models.CharField(max_length=255)


class FlagWaf:
    flag_waf = models.BooleanField()
    @property
    def lag_waf(self):
        print(self.flag_waf, "Waf flag is: ")
        return self.flag_waf


class User_value:
    user = None
    @property
    def user_val(self):
        print("user is:", self.user)
        return self.user


class WafTreshold:
    threshold_xss = models.FloatField()
    threshold_sql = models.FloatField()

    @property
    def threshold_xss(self):
        return self.threshold_xss
    @property
    def threshold_sql(self):
        return self.threshold_sql