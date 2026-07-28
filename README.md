# Vulnscope-Pro

Vulnscope-Pro is a lightweight, efficient PHP-based web application tailored for internal operations and security deployments. Built with a focus on simplicity and rapid deployment, it provides an robust foundation for scalable web services.

### 🏢 Built By
**ZeroDay Security Services**

### 👨‍💻 Founder & Lead Developer
**Vijay Ishan Chowdhury**

---

## 🚀 Local Deployment Guide

You can run Vulnscope-Pro locally using either Docker (Recommended) or a local PHP server.

### Method 1: Using Docker (Recommended)
This method ensures the application runs in the exact same environment as production (e.g., Render).

**Prerequisites:**
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed on your machine.

**Steps:**
1. Clone this repository to your local machine:
   ```bash
   git clone https://github.com/ZeroDay-Security-Services/Vulnscope-Pro.git
   cd Vulnscope-Pro
   ```

2. Build the Docker image:
   ```bash
   docker build -t vulnscope-pro .
   ```

3. Run the container:
   ```bash
   docker run -d -p 8080:80 --name vulnscope-app vulnscope-pro
   ```

4. Access the application in your browser at:
   [http://localhost:8080](http://localhost:8080)

### Method 2: Using Local PHP Built-in Server
If you have PHP installed directly on your machine, you can use its built-in development server.

**Prerequisites:**
- PHP 8.x installed (`php -v` to verify).

**Steps:**
1. Navigate to the project directory in your terminal:
   ```bash
   cd Vulnscope-Pro
   ```

2. Start the local PHP server:
   ```bash
   php -S localhost:8000
   ```

3. Access the application in your browser at:
   [http://localhost:8000](http://localhost:8000)

---

## ☁️ Production Deployment

### Render
This project includes a `Dockerfile` pre-configured for deployment on Render's Web Services.
1. Connect this repository to your Render account.
2. Create a new **Web Service**.
3. Render will automatically detect the Dockerfile and deploy the application.

---
*© ZeroDay Security Services. All rights reserved.*
