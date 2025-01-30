from .models import PasswordResetToken, User
from utils.password_utils import validate_password, hash_password
from django.urls import reverse
import hashlib
import os
from .models import PasswordHistory
from django.contrib.auth import login
from users.models import User
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib import messages
from django.db import connection
from django.contrib.auth.password_validation import validate_password


def home(request):
    return render(request, 'home.html')  # דף הבית הכללי

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST['email']
        try:
            user = User.objects.get(email=email)
            # יצירת טוקן
            token = hashlib.sha1(os.urandom(64)).hexdigest()
            PasswordResetToken.objects.create(user=user, token=token)

            # שליחת מייל
            reset_url = request.build_absolute_uri(reverse('reset_password', args=[token]))
            user.email_user(
                subject="Password Reset",
                message=f"Click the link to reset your password: {reset_url}",
            )
            messages.success(request, "A password reset email has been sent.")
            return redirect('reset_password', token=token)  # מעבר לדף Reset Password
        except User.DoesNotExist:
            messages.error(request, "No user found with that email address.")
            return redirect('forgot_password')

    return render(request, 'forgot_password.html')


def reset_password(request, token):
    try:
        reset_token = PasswordResetToken.objects.get(token=token)
        if not reset_token.is_valid():
            messages.error(request, "The reset token has expired.")
            return redirect('forgot_password')
    except PasswordResetToken.DoesNotExist:
        messages.error(request, "Invalid reset token.")
        return redirect('forgot_password')

    if request.method == 'POST':
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect('reset_password', token=token)

        # בדיקות סיסמה
        password_errors = validate_password(password, reset_token.user)
        if password_errors:
            for error in password_errors:
                messages.error(request, error)
            return redirect('reset_password', token=token)

        # שמירת הסיסמה החדשה
        reset_token.user.set_password(password)
        reset_token.user.save()

        # שמירת הסיסמה בהיסטוריה
        PasswordHistory.objects.create(user=reset_token.user, password=reset_token.user.password)

        # מחיקת הטוקן
        reset_token.delete()

        messages.success(request, "Your password has been reset successfully.")
        return redirect('login')

    return render(request, 'reset_password.html')

@login_required
def change_password(request):
    if request.method == 'POST':
        current_password = request.POST['current_password']
        new_password = request.POST['new_password']
        confirm_password = request.POST['confirm_password']

        # בדיקת סיסמה נוכחית
        if not request.user.check_password(current_password):
            messages.error(request, "The current password is incorrect.")
            return redirect('change_password')

        # בדיקת התאמת סיסמאות
        if new_password != confirm_password:
            messages.error(request, "New passwords do not match.")
            return redirect('change_password')

        # בדיקת הסיסמה החדשה לפי כל הדרישות (כולל היסטוריה)
        password_errors = validate_password(new_password, user=request.user)
        if password_errors:
            for error in password_errors:
                messages.error(request, error)
            return redirect('change_password')

        # שמירת הסיסמה החדשה
        request.user.set_password(new_password)
        request.user.save()

        # עדכון היסטוריית סיסמאות
        from users.models import PasswordHistory
        PasswordHistory.objects.create(user=request.user, password=hash_password(new_password))

        messages.success(request, "Password changed successfully.")
        return redirect('user_home')

    return render(request, 'change_password.html')

@login_required
def user_home(request):
    print("Entered user_home view")  # הודעת דיבוג
    return render(request, 'user_home.html')


def login_user(request):

    #Payload: ' OR '1'='1' --

    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        # שאילתת SQL פגיעה
        query = f"SELECT * FROM users_user WHERE username = '{username}' AND password = '{password}'"
        with connection.cursor() as cursor:
            cursor.execute(query)
            user_data = cursor.fetchone()

        if user_data:
            # יצירת אובייקט משתמש חוקי והתחברות למערכת
            user = User.objects.get(id=user_data[0])  # איתור המשתמש לפי ID
            user.backend = 'django.contrib.auth.backends.ModelBackend'  # הגדרת backend
            login(request, user)  # התחברות המשתמש

            messages.success(request, "Logged in successfully.")
            return redirect('user_home')
        else:
            messages.error(request, "Invalid credentials.")

    return render(request, 'login.html')


def register(request):

    # SQLi Payload: ' UNION SELECT sqlite_version(), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL--

    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        # Check if passwords match
        if password != confirm_password:
            messages.error(request, "Passwords do not match")
            return redirect('register')

        # Check password validity
        password_errors = validate_password(password)
        if password_errors:
            for error in password_errors:
                 messages.error(request, error)
            return redirect('register')

        # Vulnerable SQL query to check if the username or email exists
        user_exists_query = f"SELECT * FROM users_user WHERE username = '{username}' OR email = '{email}'"
        with connection.cursor() as cursor:
            try:
                cursor.execute(user_exists_query)
                existing_users = cursor.fetchall()
            except Exception as e:
                messages.error(request, "Error checking existing users.")
                return redirect('register')

        # Check if any records were fetched
        if existing_users:
            messages.error(request, f"Username {existing_users[0][0]} is already taken.")
            return redirect('register')

        # Vulnerable SQL query to insert a new user
        insert_query = f"INSERT INTO users_user (username, email, password, is_active, is_staff, is_superuser, login_attempts) VALUES ('{username}', '{email}', '{password}', 1, 0, 0, 0)"
        with connection.cursor() as cursor:
            try:
                cursor.execute(insert_query)
                messages.success(request, f"User {username} registered successfully!")
                return redirect('login')
            except Exception as e:
                messages.error(request, "Error creating user.")
                return redirect('register')

    return render(request, 'register.html')

@login_required
def create_customer(request):

    #SQLi payload:
    #  sqli version: test' || (SELECT sqlite_version()) || '--
    #  all table names: test' || (SELECT group_concat(sql) FROM sqlite_master WHERE name='users_customer') || '--

    #Stored XSS payload: <script>alert("XSS Attack!");</script>

    if request.method == 'POST':
        # Get user inputs (potentially malicious)
        first_name = request.POST.get('first_name', '')
        last_name = request.POST.get('last_name', '')
        customer_id = request.POST.get('customer_id', '')  # Vulnerable to SQL Injection
        phone_number = request.POST.get('phone_number', '')
        email = request.POST.get('email', '')

        # **Vulnerable SQL query with direct user input**
        insert_query = f"""
            INSERT INTO users_customer (first_name, last_name, customer_id, phone_number, email)
            VALUES ('{first_name}', '{last_name}', '{customer_id}', '{phone_number}', '{email}')
        """

        # Debugging: Prints the query for testing purposes
        print(f"Executing query: {insert_query}")

        with connection.cursor() as cursor:
            try:
                cursor.execute(insert_query)  # Executing raw SQL (Vulnerable)
                messages.success(request, "Customer added successfully!")
            except Exception as e:
                print(f"Error executing query: {e}")
                messages.error(request, f"Error creating customer: {e}")
                return redirect('create_customer')

        return redirect('customer_list')

    return render(request, 'create_customer.html')

def customer_list(request):
    query = "SELECT * FROM users_customer"
    print(f"Executing query: {query}")

    with connection.cursor() as cursor:
        try:
            cursor.execute(query)
            customers = cursor.fetchall()  # Keep the raw tuple format
            print(f"Fetched customers: {customers}")
        except Exception as e:
            print(f"Error executing query: {e}")
            customers = []

    return render(request, 'customer_list.html', {'customers': customers})













