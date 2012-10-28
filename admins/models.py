from django.db import models

# Create your models here.

class Device(models.Model):
    Ip = models.IPAddressField()
    Cpu = models.CharField(max_length=40)
    Mem = models.CharField(max_length=16)
    Disk = models.CharField(max_length=20)
    Virtued = models.CharField(max_length=10)
    Nic= models.CharField(max_length=40)
    Vga = models.CharField(max_length=40)
    Os = models.CharField(max_length=40)
    Arch = models.CharField(max_length=40)
    Kernel = models.CharField(max_length=40)
    Position = models.CharField(max_length=40)
    State = models.CharField(max_length=40)
    Server = models.CharField(max_length=40)
    Owner = models.CharField(max_length=20)

    def __unicode__(self):
        return self.Ip

class SSH(models.Model):
    Ip = models.IPAddressField()
    Username = models.CharField(max_length=40)
    Password = models.CharField(max_length=40)

class User_Random(models.Model):
    Username = models.CharField(max_length=40)
    Random_Password = models.CharField(max_length=40)
    Random_Port = models.CharField(max_length=8)

class Install_Package(models.Model):
    package_name = models.CharField(max_length=40)
    package_content = models.CharField(max_length=1024)
    package_path = models.CharField(max_length=1024)
    