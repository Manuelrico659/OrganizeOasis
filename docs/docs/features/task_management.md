# Task Management API

This document outlines the API for managing tasks in the application.

## Endpoints

### 1. Create Task
- **URL**: `/api/tasks`
- **Method**: POST
- **Payload**:
  ```json
  {
    "title": "New Task",
    "description": "Task details",
    "priority": 1
  }
### 2. Update Task
- **URL**: `/api/tasks/{id}`
- **Method**: PUT
- **Payload**:
  ```json
  {
  "title": "Updated Task Title",
  "description": "Updated task details",
  "priority": 2
  }
### 3. Delete Task
- **URL**: `/api/tasks`
- **Method**: DELETE
- **Payload**:
  ```json
  {
  "message": "Task deleted successfully."
  }
### 4. Get All Tasks
- **URL**: `/api/tasks/{id}`
- **Method**: GET
- **Payload**:
  ```json
  [
  {
    "id": 1,
    "title": "Task Title",
    "priority": 1
  }
  ]
