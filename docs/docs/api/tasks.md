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
