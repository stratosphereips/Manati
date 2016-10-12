from django.contrib import admin


class UserAdmin(admin.ModelAdmin):
    list_filter = ('is_staff', 'company')
