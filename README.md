# Server Inspector
This repository contains a Flask web application that provides a server management system. The application allows users to manage servers. It also provides an API for server-related operations.

## Features
+ Manage server information
+ Responsive and user-friendly interface using BULMA CSS framework [BULMA CSS framework](https://bulma.io/)
+ User authentication and authorization using Flask-Login
+ Database models using Flask-SQLAlchemy
+ Form handling and validation using Flask-WTF
+ API key generation and validation for API access
+ API endpoints for server operations
+ Role-based access control for various actions

## Prerequisites
+ Python 3.x
+ Flask
+ Flask-Login
+ Flask-SQLAlchemy
+ Flask-Migrate
+ Flask-WTF
+ Flask-Bcrypt
+ SQLAlchemy
+ WTForms

## Getting Started
1. Clone this repository to your local machine.
2. Create a virtual environment (recommended).
3. Install the required dependencies using the following command:
```bash
    pip install -r requirements.txt
```
4. Run the Flask application:
```bash
    python app.py
```
The application will be accessible at [http://localhost:5000](http://localhost:5000) in your web browser.

## Usage
+ Visit [http://localhost:5000](http://localhost:5000) to access the main application interface.
+ Users can log in or register to access the dashboard and manage servers.
+ Administrators can access the admin panel to manage users and application settings.
+ API documentation is available at [http://localhost:5000/api/docs](http://localhost:5000/api/docs)

## API Endpoints
+ **GET /api/servers**: List all servers (requires API key).
+ **POST /api/servers**: Add a new server (requires API key with 'Moderator' or 'Administrator' role).
+ **PUT /api/servers/int:id**: Update a server (requires API key with 'Moderator' or 'Administrator' role).
+ **DELETE /api/servers/int:id**: Delete a server (requires API key with 'Moderator' or 'Administrator' role).
+ **POST /admin/users/int:id/generate_password**: Generate a new password for a user (requires API key with 'Administrator' role).

## Contributing
Contributions to this project are welcome. If you encounter any bugs or have suggestions for improvements, please create an issue or submit a pull request.

## License
This project is licensed under the [MIT License](LICENSE).