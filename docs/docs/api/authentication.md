# Authentication API

This document provides details about the authentication endpoints used in the project.

## Endpoints

### 1. Login
- **URL**: `/api/auth/login`
- **Method**: POST
- **Payload**:
  ```json
  {
    "email": "user@example.com",
    "password": "securePassword123"
  }
