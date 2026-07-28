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

## 🔑 Required API Keys & Environment Variables

Vulnscope-Pro relies on external Intelligence APIs to function properly. You must provide the following environment variables:

1. `NVD_API_KEY`: Your API key for the National Vulnerability Database (NVD v2).
2. `SHODAN_API_KEY`: Your Shodan API key for threat intelligence and open port analysis.
3. `CENSYS_API_TOKEN`: Your Censys v2 Bearer Token for advanced internet-wide scanning data.

### Setting Variables in Linux / Ubuntu

If you are running the application natively on a Linux machine (e.g., Ubuntu), you can set these variables permanently by adding them to your system's profile.

1. Open your bash profile or environment file:
   ```bash
   nano ~/.bashrc
   ```
2. Add the following lines at the bottom of the file (replace with your actual keys):
   ```bash
   export NVD_API_KEY="your_nvd_api_key_here"
   export SHODAN_API_KEY="your_shodan_api_key_here"
   export CENSYS_API_TOKEN="your_censys_api_token_here"
   ```
3. Save the file (`Ctrl+O`, `Enter`, `Ctrl+X`) and reload your profile:
   ```bash
   source ~/.bashrc
   ```

*(If you are using Docker, you can pass these variables in your run command using `-e KEY="value"` or by creating a `.env` file and using `--env-file .env`)*.

---

## ☁️ Production Deployment

### Render
This project includes a `Dockerfile` pre-configured for deployment on Render's Web Services.
1. Connect this repository to your Render account.
2. Create a new **Web Service**.
3. Under **Environment Variables**, add `NVD_API_KEY`, `SHODAN_API_KEY`, and `CENSYS_API_TOKEN` with their respective values.
4. Render will automatically detect the Dockerfile and deploy the application.

---
*© ZeroDay Security Services. All rights reserved.*
