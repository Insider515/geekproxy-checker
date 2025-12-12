# 🚀 GeekProxy Checker 

🇬🇧 English

A high-performance web service written in Go for checking proxies. It supports multi-threading, detailed analysis, and a clean web interface.

## ✨ Features

*   **UDP Check:** Verifies UDP protocol support (essential for SOCKS5).
*   **IP Intelligence:** Detects Country, City, ISP, and IP Type (Residential vs. Hosting).
*   **Bulk Check:** fast parallel checking of proxy lists.
*   **Shadowsocks Support:** Full support for `ss://` links (AES-256-GCM, Chacha20-IETF-Poly1305, etc.).
*   **Auto-Detection:** Automatically attempts SOCKS5 → HTTP if the protocol is not specified.

## 🛠 Installation & Setup

### Prerequisites
*   Go 1.19+ installed.
*   Linux / macOS / Windows.

### 1. Initialize Project
Navigate to the project folder and run:

```go
go mod init proxy-checker
go mod tidy
```

2. Run (Development)
```go
go run main.go
```
3. Build (Production)

```go
go build -o proxy-checker main.go
``` 
The server will start locally at: http://127.0.0.1:8081  
Note: The application listens on 127.0.0.1 (localhost) only. To access it from the internet, you must set up Nginx as a reverse proxy.  
📝 Proxy Formats  
Paste these formats into the Bulk Check text area:
1. Standard Proxies (SOCKS5 / HTTP)
```bash
IP:PORT:USER:PASS
Example: 185.231.244.90:40033:user:pass
```
2. Shadowsocks (Plain text)
```bash
ss://METHOD:PASSWORD@HOST:PORT
```
Example: ss://aes-256-gcm:mypassword@1.2.3.4:8388
3. Shadowsocks (SIP002 / Base64)
```bash
ss://BASE64_STRING@HOST:PORT
ss://BASE64_STRING
```
Example: ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388  
⚙️ Nginx Configuration (Reverse Proxy)  
Since the app runs on port 8081 internally, use this Nginx config to expose it safely via SSL (e.g., on port 8443 for Cloudflare compatibility):
```nginx
server {
    # Port 8443 is supported by Cloudflare for HTTPS
    listen 8443 ssl http2;
    server_name your-domain.com;

    # SSL Certificates
    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
Don't forget to allow the port in your firewall: ufw allow 8443/tcp  
🐧 Run as Service (Ubuntu Systemd)  
To keep the application running in the background:  
Create a service file: /etc/systemd/system/proxy-checker.service  
Add the following content:
```Ini
[Unit]
Description=Go Proxy Checker Service
After=network.target

[Service]
User=root
# Directory containing index.html and the binary
WorkingDirectory=/opt/proxy-checker
ExecStart=/opt/proxy-checker/proxy-checker
Restart=always

[Install]
WantedBy=multi-user.target
```
Enable and start:
```bash
systemctl daemon-reload
systemctl enable proxy-checker
systemctl start proxy-checker
```

---

🇺🇦 Українська

Потужний та швидкий веб-сервіс для перевірки проксі-серверів. Написаний на Go, підтримує багатопотоковість, детальний аналіз IP та роботу через зручний веб-інтерфейс.

## ✨ Можливості

*   **UDP Check:** Перевірка підтримки протоколу UDP (важливо для SOCKS5).
*   **IP Intelligence:** Визначення країни, міста, провайдера (ISP) та типу IP (Резидентський / Хостинг).
*   **Bulk Check (Масова перевірка):** Паралельна перевірка списків проксі.
*   **Shadowsocks Support:** Повна підтримка посилань `ss://` (шифрування AES-256-GCM, Chacha20 та ін.).
*   **Auto-Detection:** Автоматичне визначення протоколу (спочатку SOCKS5, потім HTTP).

## 🛠 Встановлення та запуск

### Вимоги
*   Go 1.19+
*   Linux / macOS / Windows

1. Ініціалізація проєкту
У папці з файлами виконайте команди:

```bash
go mod init proxy-checker
go mod tidy
```
2. Запуск (Режим розробки)
```Bash
go run main.go
```
3. Компіляція (Продакшн)
```Bash
go build -o proxy-checker main.go
```
Після запуску сервер буде доступний локально: http://127.0.0.1:8081  
Важливо: Сервер слухає лише локальний інтерфейс (127.0.0.1). Щоб відкрити його з інтернету, необхідно використовувати Nginx (див. розділ Nginx).  
📝 Формати проксі  
Вставте ці формати у текстове поле на вкладці Bulk Check:
1. Звичайні проксі (SOCKS5 / HTTP)
```Text
IP:PORT:USER:PASS
```
Приклад: 185.231.244.90:40033:user:pass
2. Shadowsocks (Звичайний текст)
```Text
ss://METHOD:PASSWORD@HOST:PORT
```
Приклад: ss://aes-256-gcm:mypassword@1.2.3.4:8388
3. Shadowsocks (SIP002 / Base64)
```Text
ss://BASE64_STRING@HOST:PORT
ss://BASE64_STRING
```
Приклад: ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388  
⚙️ Налаштування Nginx (Reverse Proxy)  
Оскільки програма працює на порту 8081 локально, для доступу ззовні (наприклад, через https://your-domain.com:8443) використовуйте цей конфіг Nginx. Порт 8443 обрано для сумісності з Cloudflare.
```Nginx
server {
    listen 8443 ssl http2;
    server_name your-domain.com;

    # Шляхи до сертифікатів
    ssl_certificate /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
Не забудьте відкрити порт у фаєрволі: ufw allow 8443/tcp.  
🐧 Запуск як сервіс (Ubuntu Systemd)  
Щоб програма працювала у фоновому режимі та перезапускалася автоматично:  
Створіть файл: /etc/systemd/system/proxy-checker.service  
Вставте наступний вміст:
```Ini
[Unit]
Description=Go Proxy Checker Service
After=network.target

[Service]
User=root
# Папка, де лежить index.html та бінарний файл
WorkingDirectory=/opt/proxy-checker
ExecStart=/opt/proxy-checker/proxy-checker
Restart=always

[Install]
WantedBy=multi-user.target
```
Активуйте сервіс:
```Bash
systemctl daemon-reload
systemctl enable proxy-checker
systemctl start proxy-checker
```
