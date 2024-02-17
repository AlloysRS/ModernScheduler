from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime, timedelta
from calendar import monthrange
import sqlite3
import re
import bcrypt

app = Flask(__name__)
app.secret_key = "random_secret_key_1"

# Database initialization
def initialize_database():
    conn = sqlite3.connect('tasks.db')
    cursor = conn.cursor()
    # Create tables if they don't already exist for users, tasks, events and history
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT,
                    display_name TEXT
                )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS tasks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user TEXT,
                        task TEXT,
                        status TEXT,
                        date_added TEXT,
                        date_due TEXT,
                        date_last_updated TEXT,
                        comments TEXT
                    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user TEXT,
                    event_name TEXT,
                    date_added TEXT,
                    event_date TEXT,
                    comments TEXT
                )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        action TEXT,
                        user TEXT,
                        task_id INTEGER,
                        task_name TEXT,
                        task_status TEXT
                    )''')
    conn.commit()
    conn.close()

# Initialise the database
initialize_database()

# Define valid status options so that a user cannot make their own up
VALID_STATUS_OPTIONS = ['ToDo', 'InProgress', 'Done', 'OnHold']

# Page - Index (Tasks) - This page is the default page which shows users their tasks in a table
@app.route('/')
def index():
    # Checks if user is logged in already, this check is done on every page except login, logout and register
    if 'username' in session:
        conn = sqlite3.connect('tasks.db')
        cursor = conn.cursor()
        # Retrieve all tasks data from tasks and store in tasks variable
        cursor.execute("SELECT * FROM tasks WHERE user=? AND status != 'Deleted'", (session['username'],))
        tasks = cursor.fetchall()
        # Retrieve display_name from users and store in display_name variable
        cursor.execute("SELECT display_name FROM users WHERE username=?", (session['username'],))
        display_name = cursor.fetchone()[0]
        conn.close()
        # Group tasks by status into lists
        tasks_by_status = {'ToDo': [], 'InProgress': [], 'Done': [], 'OnHold': []}
        for task in tasks:
            tasks_by_status[task[3]].append(task)
        greeting = get_greeting()
        # Pass tasks_by_status, valid_status_options, current_datetime, display_name to the template context
        return render_template('index.html', tasks_by_status=tasks_by_status, valid_status_options=VALID_STATUS_OPTIONS, current_datetime=datetime.now(), display_name=display_name, greeting=greeting, today_date=datetime.now().strftime('%Y-%m-%d'))
    # If user not logged in then show them login page
    return redirect(url_for('login'))

# Page - About - Returns a static page telling users about the application
@app.route('/about')
def about():
    return render_template('about.html')

# Page - Register - This page allows a user to register with a username and password, POST filter passes through registration data, if already logged in then user is redirected to index
@app.route('/register', methods=['GET', 'POST'])
def register():
    # If already logged in then redirected to Index
    if 'username' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        # Set username and password, as well as formatted default display_name, if username taken or invalid then error returned
        username = request.form['username'].lower()
        display_name = request.form['username'].capitalize()
        password = request.form['password']
        # Validate username
        if not is_valid_username(username):
            flash("Username must be max 20 characters with no spaces or special characters", "error")
            return render_template('register.html')
        # Check if username already exists
        if not is_username_available(username):
            flash("Username already exists", "error")
            return render_template('register.html')
        # Hashes the password using hash_password function
        hashed_password = hash_password(password)
        # Connect to database and update users table with username, password, display_name
        conn = sqlite3.connect('tasks.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password, display_name) VALUES (?, ?, ?)", (username, hashed_password, display_name))
        conn.commit()
        conn.close()
        # Redirect to login page after successful registration
        return redirect(url_for('login'))
    # If user not visited via POST then sees register page
    return render_template('register.html')

# Page - Login - Allows a user to log in with their registered details
@app.route('/login', methods=['POST', 'GET'])
def login():
    # If already logged in then redirected to Index
    if 'username' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        # Username is formatted to lower by default
        username = request.form['username'].lower()
        password = request.form['password']
        # Connect to the database and checks that username exists and then goes to verify password
        conn = sqlite3.connect('tasks.db')
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        stored_hashed_password = cursor.fetchone()
        if stored_hashed_password:
            stored_hashed_password = stored_hashed_password[0]
            # Verify the password when hashed matches the stored_hashed_password
            if verify_password(password, stored_hashed_password):
                # Store the username in the session, this is used in other routes to verify user is logged in
                session['username'] = username
                # Record login history
                cursor.execute("INSERT INTO history (action, user) VALUES (?, ?)", ('Login', session['username']))
                conn.commit()
                conn.close()
                return redirect(url_for('index'))
            # If the password does not exist then return error and redirect to login
            else:
                flash("Invalid username or password", "error")
                return render_template('login.html')
        # If there is no stored_hashed_password, likely user does not exist, so return error and redirect to login
        else:
            flash("Invalid username or password", "error")
            return render_template('login.html')
    return render_template('login.html')

# Update - Logout - Allows a user to log out and redirects to login page, if not logged in also goes to login page
@app.route('/logout', methods=['POST', 'GET'])
def logout():
    if 'username' in session:
        conn = sqlite3.connect('tasks.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO history (action, user) VALUES (?, ?)", ('Logout', session['username']))
        conn.commit()
        conn.close()
        session.pop('username', None)
    return redirect(url_for('login'))

# Page - Profile - This page allows a user to change their display_name, change their password, and toggle darkmode on or off
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' in session:
        username = session['username']
        # Connect to database and fetch username and display_name then render page
        conn = sqlite3.connect('tasks.db')
        cursor = conn.cursor()
        cursor.execute("SELECT username, display_name FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        conn.close()
        return render_template('profile.html', user=user)
    return redirect(url_for('login'))

# Page - Events - This shows users their events in a table
@app.route('/events')
def events():
    if 'username' in session:
        conn = sqlite3.connect('tasks.db')
        cursor = conn.cursor()
        # Retrieve events data from events and display_name from users
        cursor.execute("SELECT * FROM events WHERE user=?", (session['username'],))
        events = cursor.fetchall()
        cursor.execute("SELECT display_name FROM users WHERE username=?", (session['username'],))
        display_name = cursor.fetchone()[0]
        conn.close()
        return render_template('events.html', events=events, display_name=display_name, today_date=datetime.now().strftime('%Y-%m-%d'))
    return redirect(url_for('login'))

# Page - Calendar - This page allows a user to see all of their tasks and events in a calendar view with ability to change the month
@app.route('/calendar')
def calendar():
    if 'username' in session:  # Check if user is logged in
        # Fetch tasks for the logged-in user
        conn = sqlite3.connect('tasks.db')
        cursor = conn.cursor()
        # Set selected year and selected month by default to current year and month and start/end to month start/end
        selected_year = request.args.get('year', datetime.now().year)
        selected_month = request.args.get('month', datetime.now().month)
        selected_date = datetime(int(selected_year), int(selected_month), 1)
        start_date = selected_date.replace(day=1)
        end_date = selected_date.replace(day=monthrange(int(selected_year), int(selected_month))[1])
        # Retrieve tasks and events information from the tasks and events tables
        cursor.execute("SELECT * FROM tasks WHERE user=? AND date_due >= ? AND date_due <= ? AND status NOT IN ('Deleted', 'Done')", (session['username'], start_date.strftime('%Y-%m-%d'), end_date.strftime('%Y-%m-%d')))
        tasks = cursor.fetchall()
        cursor.execute("SELECT * FROM events WHERE user=? AND event_date >= ? AND event_date <= ?", (session['username'], start_date.strftime('%Y-%m-%d'), end_date.strftime('%Y-%m-%d')))
        events = cursor.fetchall()
        conn.close()
        # Prepare calendar data
        calendar_data = []
        date_month = start_date
        # While loop to adjust start_date to the first Monday before the start of the month
        while start_date.weekday() != 0:  # 0 is Monday
            start_date -= timedelta(days=1)
        current_date = start_date
        end_date = end_date
        # While loop to create week data in intervals of 7 days for start date less or equal to end date
        while start_date <= end_date:
            week = []
            # For loop to fetch day tasks and day events for each day in week
            for i in range(7):
                # Data only fetched if day is in the selected month
                if start_date.month == selected_date.month:
                    day_tasks = [task for task in tasks if task[5] == start_date.strftime('%Y-%m-%d')]
                    day_events = [event for event in events if event[4] == start_date.strftime('%Y-%m-%d')]
                    day = {
                        'date': start_date.strftime('%Y-%m-%d'),
                        'tasks': day_tasks,
                        'events': day_events,
                        # Total number of tasks and events calculated
                        'total_tasks': len(day_tasks),
                        'total_events': len(day_events)
                    }
                else:
                    day = None
                week.append(day)
                start_date += timedelta(days=1)
            calendar_data.append(week)
        return render_template('calendar.html', calendar_data=calendar_data, current_date=current_date, date_month=date_month)
    return redirect(url_for('login'))

# Page - Task - Allows a user to see a given task, admins can see any task but users can only view their own tasks
@app.route('/task/<int:task_id>')
def task(task_id):
    if 'username' in session:
        if session['username'] == 'admin':
            with sqlite3.connect('tasks.db') as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM tasks WHERE id=?", (task_id,))
                task = cursor.fetchone()
            if task:
                return render_template('task.html', task=task)
        else:
            with sqlite3.connect('tasks.db') as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM tasks WHERE id=? AND user=?", (task_id, session['username']))
                task = cursor.fetchone()
            if task:
                return render_template('task.html', task=task)
    return redirect(url_for('index'))

# Page - Event - Allows a user to see a given event, admins can see any task but users can only view their own tasks
@app.route('/event/<int:event_id>')
def event(event_id):
    if 'username' in session:
        if session['username'] == 'admin':
            with sqlite3.connect('tasks.db') as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM events WHERE id=?", (event_id,))
                event = cursor.fetchone()
            if event:
                return render_template('event.html', event=event)
        else:
            with sqlite3.connect('tasks.db') as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM events WHERE id=? AND user=?", (event_id, session['username']))
                event = cursor.fetchone()
            if event:
                return render_template('event.html', event=event)
    return redirect(url_for('index'))

# Page - History (Admin only) - For seeing a transactional history of changes to tasks, events are not shown here
@app.route('/history')
def history():
    # Fetch history from history table if username is admin
    if 'username' in session and session['username'] == 'admin':
        conn = sqlite3.connect('tasks.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM history ORDER BY timestamp DESC")
        history_entries = cursor.fetchall()
        conn.close()
        return render_template('history.html', history_entries=history_entries)
    return redirect(url_for('index'))

# Update - For updating user display_name
@app.route('/update_display_name', methods=['POST'])
def update_display_name():
    if 'username' in session:
        username = session['username']
        display_name = request.form['display_name']
        # Check if the display_name exceeds 20 characters
        if len(display_name) > 20:
            flash("Display name must be 20 characters or less!", "error")
            return redirect(url_for('profile'))
        # Connect to database and update display_name with form input
        conn = sqlite3.connect('tasks.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET display_name=? WHERE username=?", (display_name, username))
        conn.commit()
        conn.close()
        # Flash success message
        flash("Display name updated successfully!", "success")
        return redirect(url_for('profile'))
    return redirect(url_for('login'))

# Update - For changing password, retrieves user details, and input for current and new password, then connects to the database to fetch hashed stored_password
@app.route('/change_password', methods=['POST'])
def change_password():
    if 'username' in session:
        username = session['username']
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        conn = sqlite3.connect('tasks.db')
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username=?", (username,))
        stored_password = cursor.fetchone()[0]
    # Checks if hashed current_password matches hashed stored_password and returns error if not
    if not verify_password(current_password, stored_password):
        flash("Incorrect current password. Please try again.", "error")
        return redirect(url_for('profile'))
    # Checks if new_password input matches confirm_password input and returns error if not
    elif new_password != confirm_password:
        flash("New password and confirm password do not match. Please try again.", "error")
        return redirect(url_for('profile'))
    # If both checks pass then password is hashed and updated in the users table
    else:
        hashed_password = hash_password(new_password)
        cursor.execute("UPDATE users SET password=? WHERE username=?", (hashed_password, username))
        conn.commit()
        flash("Password updated successfully!", "success")
    conn.close()
    return redirect(url_for('profile'))

# Update - For adding tasks, allows a user to add new tasks to their tasks list
@app.route('/add_task', methods=['POST'])
def add_task():
    if 'username' in session:
        # User and task details are fetched from the add task form
        user = session['username']
        task = request.form['task']
        status = request.form['status']
        # Check if the status provided is valid
        if status not in VALID_STATUS_OPTIONS:
            return "Invalid status option"
        # Obtains current date and time into date variables
        date_added = datetime.now().strftime("%Y-%m-%d")
        date_due = request.form['due']
        date_last_updated = datetime.now().strftime("%Y-%m-%d")
        # Comments left blank by default
        comments = ""
        # Connects to database and inserts new task with task fields
        conn = sqlite3.connect('tasks.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO tasks (user, task, status, date_added, date_due, date_last_updated, comments) VALUES (?, ?, ?, ?, ?, ?, ?)",
               (user, task, status, date_added, date_due, date_last_updated, comments))
        # Retrieve the TaskId, TaskName, and TaskStatus after adding the task
        task_id = cursor.lastrowid
        cursor.execute("SELECT task, status FROM tasks WHERE id=?", (task_id,))
        task_info = cursor.fetchone()
        task_name, task_status = task_info
        # Insert the history entry with additional information
        cursor.execute("INSERT INTO history (timestamp, action, user, task_id, task_name, task_status) VALUES (?, ?, ?, ?, ?, ?)",
                       (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'Add Task', user, task_id, task_name, task_status))
        conn.commit()
        conn.close()
    return redirect(url_for('index'))

# Update - For updating task status, allows a user to update task status
@app.route('/update_status/<int:task_id>', methods=['POST'])
def update_status(task_id):
    if 'username' in session:
        status = request.form['status']
        date_last_updated = datetime.now().strftime("%Y-%m-%d")
        # Check if the status provided is valid
        if status not in VALID_STATUS_OPTIONS:
            return "Invalid status option"
        conn = sqlite3.connect('tasks.db')
        cursor = conn.cursor()
        # Retrieve current task information
        cursor.execute("SELECT task, status, user FROM tasks WHERE id=?", (task_id,))
        task_info = cursor.fetchone()
        # Ensure task exists and belongs to the current user
        if task_info and task_info[2] == session['username']:
            task_name, old_status, task_user = task_info
            # Update the status of the task
            cursor.execute("UPDATE tasks SET status=?, date_last_updated=? WHERE id=?", (status, date_last_updated, task_id))
            # Insert the history entry with additional information
            cursor.execute("INSERT INTO history (timestamp, action, user, task_id, task_name, task_status) VALUES (?, ?, ?, ?, ?, ?)",
                           (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'Update Status', session['username'], task_id, task_name, status))
            conn.commit()
            conn.close()
    return redirect(url_for('index'))

# Update - For deleting tasks, allows a user to delete a task
@app.route('/delete_task/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    if 'username' in session:
        date_last_updated = datetime.now().strftime("%Y-%m-%d")
        conn = sqlite3.connect('tasks.db')
        cursor = conn.cursor()
        # Retrieve current task information
        cursor.execute("SELECT task, status, user FROM tasks WHERE id=?", (task_id,))
        task_info = cursor.fetchone()
        # Ensure task exists and belongs to the current user
        if task_info and task_info[2] == session['username']:
            task_name, task_status, task_user = task_info
            # Update the status of the task to 'Deleted'
            cursor.execute("UPDATE tasks SET status=?, date_last_updated=? WHERE id=?", ('Deleted', date_last_updated, task_id))
            # Insert the history entry with additional information
            cursor.execute("INSERT INTO history (timestamp, action, user, task_id, task_name, task_status) VALUES (?, ?, ?, ?, ?, ?)",
                           (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'Delete Task', session['username'], task_id, task_name, 'Deleted'))
            conn.commit()
            conn.close()
    return redirect(url_for('index'))

# Update - For task comments, allows a user to add or update comments on a task
@app.route('/update_comments/<int:task_id>', methods=['POST'])
def update_comments(task_id):
    if 'username' in session:
        if request.method == 'POST':
            new_comments = request.form.get('comments')
            with sqlite3.connect('tasks.db') as conn:
                cursor = conn.cursor()
                # Retrieve task information including the task owner
                cursor.execute("SELECT task, status, user FROM tasks WHERE id=?", (task_id,))
                task_info = cursor.fetchone()
                # Ensure task exists
                if task_info:
                    task_name, status, task_owner = task_info
                    # Check if the user is admin or the owner of the task
                    if session['username'] == 'admin' or session['username'] == task_owner:
                        cursor.execute("UPDATE tasks SET comments=? WHERE id=?", (new_comments, task_id))
                        cursor.execute("INSERT INTO history (timestamp, action, user, task_id, task_name, task_status) VALUES (?, ?, ?, ?, ?, ?)",
                                       (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 'Comments', session['username'], task_id, task_name, status))
                        conn.commit()
                        return "Comments updated successfully"
    return redirect(url_for('login'))

# Update - For adding events, allows a user to add an event
@app.route('/add_event', methods=['POST'])
def add_event():
    if 'username' in session:
        user = session['username']
        event_name = request.form['event_name']
        event_date = request.form['event_date']
        date_added = datetime.now().strftime("%Y-%m-%d")
        conn = sqlite3.connect('tasks.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO events (user, event_name, date_added, event_date) VALUES (?, ?, ?, ?)",
               (user, event_name, date_added, event_date))
        conn.commit()
        conn.close()
    return redirect(url_for('events'))

# Update - For deleting events, allows a user to delete an event
@app.route('/delete_event/<int:event_id>', methods=['POST'])
def delete_event(event_id):
    if 'username' in session:
        conn = sqlite3.connect('tasks.db')
        cursor = conn.cursor()
        # Add WHERE clause to ensure only events belonging to the logged-in user are deleted
        cursor.execute("DELETE FROM events WHERE id=? AND user=?", (event_id, session['username']))
        conn.commit()
        conn.close()
    return redirect(url_for('events'))

# Update - For event comments, allows a user to update comments for an event
@app.route('/update_event_comments/<int:event_id>', methods=['POST'])
def update_event_comments(event_id):
    if 'username' in session:
        if request.method == 'POST':
            new_comments = request.form.get('comments')
            with sqlite3.connect('tasks.db') as conn:
                cursor = conn.cursor()
                # Update the comments for the event only if it belongs to the logged-in user
                cursor.execute("UPDATE events SET comments=? WHERE id=? AND user=?", (new_comments, event_id, session['username']))
                conn.commit()
            flash("Event comments updated!", "success")
            # Render the event.html template with the updated event
            return render_template('event.html', event=event)
    return redirect(url_for('index'))

# Update - For event date, allows a user to update date for an event
@app.route('/update_event_date/<int:event_id>', methods=['POST'])
def update_event_date(event_id):
    if 'username' in session:
        if request.method == 'POST':
            new_date = request.form.get('new_date')
            with sqlite3.connect('tasks.db') as conn:
                cursor = conn.cursor()
                # Update the date for the event only if it belongs to the logged-in user
                cursor.execute("UPDATE events SET event_date=? WHERE id=? AND user=?", (new_date, event_id, session['username']))
                conn.commit()
            flash("Event date updated!", "success")
            # As date can be changed on events or event page, checks which one referred from and then returns to appropriate page
            if request.referrer.endswith('/events'):
                return redirect(url_for('events'))
            else:
                return redirect(url_for('event', event_id=event_id))
    return redirect(url_for('index'))

# Update - For darkmode, allows a user to toggle darkmode
@app.route('/toggle_dark_mode', methods=['POST'])
def toggle_dark_mode():
    if 'dark_mode' in session:
        session['dark_mode'] = not session['dark_mode']  # Toggle dark mode status
    else:
        session['dark_mode'] = True  # Initialize dark mode status if not set
    return redirect(request.referrer)  # Redirect back to the previous page

# Function - To hash passwords using bcrypt
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password.decode()

# Function - To verify a password input against a stored_hash password
def verify_password(password, stored_hash):
    return bcrypt.checkpw(password.encode(), stored_hash.encode())

# Function - To check for duplicate usernames
def is_username_available(username):
    conn = sqlite3.connect('tasks.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user is None

# Function - To validate the username
def is_valid_username(username):
    # Check if username length is within limits
    if len(username) > 20:
        return False
    # Check if username contains only alphanumeric characters
    if not re.match("^[a-zA-Z0-9]+$", username):
        return False
    return True

# Function to determine the appropriate greeting based on the time of day
def get_greeting():
    current_hour = datetime.now().hour
    if 5 <= current_hour < 12:
        return "Good Morning"
    elif 12 <= current_hour < 18:
        return "Good Afternoon"
    else:
        return "Good Evening"

# Function - Converts a string to datetime
def string_to_datetime(date_str):
    return datetime.strptime(date_str, '%Y-%m-%d')

# Function - Formats a string to date format
def format_date(value, format='%d'):
    return value.strftime(format)

app.jinja_env.filters['string_to_datetime'] = string_to_datetime
app.jinja_env.filters['format_date'] = format_date

if __name__ == '__main__':
    app.run(debug=True)
