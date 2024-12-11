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
