# Modern Scheduler

Modern Scheduler is a task and event management web application developed as my final project for Harvard's CS50 Introduction to Computer Science Course.

## Table of Contents

- [Introduction](#introduction)
- [Functionality](#functionality)
- [Implementation Details](#implementation-details)
- [Usage Examples](#usage-examples)
- [Getting Started](#getting-started)
- [Dependencies](#dependencies)
- [Setup](#setup)
- [Contributing](#contributing)
- [License](#license)

## Introduction

Welcome to Modern Scheduler, your ultimate tool for managing tasks and events. This project was created as part of Harvard's CS50 Introduction to Computer Science Course, showcasing skills in web development, database management, and security.

## Functionality

- **Task Management:**
  - Add, update, and delete tasks.
  - Organize tasks by status (To Do, In Progress, Done, On Hold).

- **Event Management:**
  - Add, update, and delete events.
  - Associate events with specific dates.

- **Calendar View:**
  - View tasks and events in a monthly calendar.

- **User Authentication:**
  - Register, log in, and log out securely.
  - Passwords are hashed using bcrypt.

- **Profile Management:**
  - Update display name and password.

- **Dark Mode:**
  - Toggle dark mode for a different visual theme.

- **Admin Features:**
  - View login/logout history.

## Implementation Details

Modern Scheduler is implemented using Python's Flask framework for the backend and SQLite for the database. Key features include:

- **Tasks:** Managed with status options (To Do, In Progress, Done, On Hold).
- **Events:** Associated with specific dates.
- **Calendar:** Displays tasks and events for a selected month.
- **User Authentication:** Secure registration, login, and logout.
- **Profile Management:** Allows users to update display name and password.
- **Dark Mode:** Enhances user experience with a different visual theme.
- **Admin Features:** Includes a history view for login/logout details.

## Usage Examples

- **Adding a Task:** Navigate to the "Tasks" page, click "Add Task," enter details, and click "Submit."
- **Updating Task Status:** On the "Tasks" page, use the dropdown next to a task to select a new status.
- **Viewing Calendar:** Visit the "Calendar" page to see tasks and events in a monthly view.
- **Changing Profile Information:** Go to the "Profile" page to update your display name or password.
- **Logging Out:** Click "Logout" in the navigation bar to log out.

## Getting Started

To run Modern Scheduler locally, follow these steps:

## Dependencies

- Flask
- Flask-Bcrypt
- Flask-Login
- Flask-WTF
- SQLite

## Setup

1. Clone the repository:

   ```
   git clone https://github.com/AlloysRS/TBC
   ```

2. Install dependencies:

    ```
    pip install -r requirements.txt
    ```

3. Set up the database:

    ```
    flask db init
    flask db migrate
    flask db upgrade
    ```

4. Run the application:

    ```
    flask run
    ```

5. Open your web browser and visit http://localhost:5000/

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License.
