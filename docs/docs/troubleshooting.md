# Troubleshooting

## Common Issues

### 1. Application fails to start
- **Cause**: Missing environment variables.
- **Solution**: Ensure `.env` file is correctly configured.

### 2. Database connection errors
- **Cause**: MongoDB or MySQL not running.
- **Solution**: Start the database services:
  ```bash
  sudo service mongod start
  sudo service mysql start
