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
### 2. Get All Tasks
- **URL**: `/api/tasks`
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
