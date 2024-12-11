# User Management Feature

This document provides details about the user management feature in the project.

## Overview

The user management feature enables the creation, updating, and deletion of user accounts. It includes functionalities for user authentication and role management.

## Endpoints

### 1. Create User
- **URL**: `/api/users`
- **Method**: POST
- **Payload**:
  ```json
  {
    "name": "John Doe",
    "email": "john@example.com",
    "password": "securePassword123"
  }
### 2. Update User
- **URL**: `/api/users/{id}`
- **Method**: PUT
- **Payload**:
  ```json
  {
  "name": "Updated Name",
  "email": "updated@example.com"
  }
### 3. Delete User
- **URL**: `/api/users`
- **Method**: DELETE
- **Payload**:
  ```json
  {
  "message": "User deleted successfully."
  }
### 4. Get All Users
- **URL**: `/api/users`
- **Method**: GET
- **Payload**:
  ```json
  [
  {
    "id": 1,
    "name": "John Doe",
    "email": "john@example.com"
  }
  ]
