/*************************************************************
                      creadits: Akash-iot
open port will shut down due to attack  
Fake web interface with root, user login, admin login, and IoT config pages
Fake dashboard UI showing device statuses
Admin login with generated 6-digit OTP and Blynk redirect on success
SQL injection detector (substrings like ' or, 1=1, union, select, drop, --, #)
Detection for credential-style patterns like username='username',password='password' and username=...&password=...
Immediate permanent blocking of IPs on detected SQLi (persisted to SPIFFS)
Failed-login counting with automatic block after 5 attempts
OTP retry limits (default max 3) and blocking on excessive OTP failures
Fake service banners on extra ports: FTP (21), SSH (22), MQTT (1883)
Serial and Blynk alerts (Blynk.logEvent) for detections and blocks
SPIFFS persistence for blocked IP list (/blocked.txt) so bans survive reboots
Temporary port 80 closure for 5 minutes when triggered (optional behavior)
/attackers page showing IPs, failed login counts, and OTP attempts (not linked from root)
Wi-Fi AP created (fake SSID) alongside station mode
OTP printed to Serial for testing/demonstration
Simple HTML/CSS dark-themed UI styling
In-memory maps for login attempts and OTP state management
No network-level firewalling—blocks are enforced in-app only
Potential false positives due to conservative substring-based SQLi detection
Hard-coded Blynk token and Wi-Fi credentials present in the sketch (not secure)
*************************************************************/

#define BLYNK_TEMPLATE_ID "TMPL3z1pr2dja"
#define BLYNK_TEMPLATE_NAME "HONEYPOT"
#define BLYNK_AUTH_TOKEN "xqEGnZSSBj_8bZvi--XpGJ5mEHMiDRwA"
#define BLYNK_FIRMWARE_VERSION "0.6.0"

#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <WiFiClient.h>
#include <BlynkSimpleEsp32.h>
#include <map>
#include <set>
#include <string>
#include <SPIFFS.h>

// ---------------- WiFi ----------------
char ssid[] = "wifi";
char pass[] = "12345678";

const char* fakeSSID = "HOME";
const char* fakePASS = "12345678";

// ---------------- Redirect target ----------------
const char* BLYNK_REDIRECT_URL = "https://blynk.cloud/dashboard/login";

// ---------------- Credentials ----------------
String userName = "user";
String adminName = "smvc";
String generalPass = "2210";

// ---------------- Servers ----------------
WebServer server(80);
WebServer serverAlt(8080);
WiFiServer ftpServer(21);
WiFiServer sshServer(22);
WiFiServer mqttServer(1883);

// ---------------- Login Attempts & Blocking ----------------
std::map<String, int> loginAttempts;
std::set<String> blockedIPs;
bool port80Closed = false;
unsigned long reopenTime = 0;
const unsigned long PORT_BLOCK_TIME = 300000UL; // 5 minutes

// ---------------- OTP Handling ----------------
std::map<String, String> otpByIP;
std::map<String, int> otpAttemptsByIP;
const int OTP_MAX_ATTEMPTS = 3;

// ---------------- Helpers ----------------
void sendAlert(String msg) {
  Serial.println("[ALERT] " + msg);
  Blynk.logEvent("honeypot_alert", msg);
}

// ---------------- SPIFFS persistence for blocked IPs ----------------
const char* BLOCKED_FILE = "/blocked.txt";

void saveBlockedIPs() {
  if (!SPIFFS.begin(true)) {
    Serial.println("SPIFFS mount failed during save.");
    return;
  }
  File f = SPIFFS.open(BLOCKED_FILE, FILE_WRITE);
  if (!f) {
    Serial.println("Failed to open blocked file for writing");
    return;
  }
  for (auto &ip : blockedIPs) {
    f.println(ip);
  }
  f.close();
  Serial.println("Blocked IPs saved.");
}

void loadBlockedIPs() {
  blockedIPs.clear();
  if (!SPIFFS.begin(true)) {
    Serial.println("SPIFFS mount failed during load.");
    return;
  }
  if (!SPIFFS.exists(BLOCKED_FILE)) {
    Serial.println("No blocked file found (first run).");
    return;
  }
  File f = SPIFFS.open(BLOCKED_FILE, FILE_READ);
  if (!f) {
    Serial.println("Failed to open blocked file for reading");
    return;
  }
  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line.length() > 0) blockedIPs.insert(line);
  }
  f.close();
  Serial.println("Blocked IPs loaded.");
}

// ---------------- Port control ----------------
void blockPort80() {
  if (!port80Closed) {
    port80Closed = true;
    server.stop();
    reopenTime = millis() + PORT_BLOCK_TIME;
    sendAlert("🚫 Port 80 closed for 5 minutes due to attack");
  }
}

void reopenPort80() {
  if (port80Closed && millis() > reopenTime) {
    server.begin();
    port80Closed = false;
    sendAlert("✅ Port 80 reopened");
  }
}

bool isBlocked(const String &ip) {
  return blockedIPs.find(ip) != blockedIPs.end();
}

// ---------------- Permanent blocking helper ----------------
void blockIPPermanently(const String &ip, const String &reason = "Permanent block due to SQLi") {
  if (!isBlocked(ip)) {
    blockedIPs.insert(ip);
    sendAlert("⛔ " + ip + " permanently blocked | Reason: " + reason);
    saveBlockedIPs(); // persist immediately
    // Optional: close port 80 temporarily to reduce noise/visibility.
    // If you don't want this behavior, comment out the next line.
    blockPort80();
  }
}

// ---------------- SQLi Detector (improved) ----------------
bool detectSQLi(String input) {
  // Normalize common unicode apostrophe to ASCII
  input.replace("’", "'");
  // Convert to lowercase for case-insensitive checks
  input.toLowerCase();

  // Quick substring checks (existing ones)
  if (input.indexOf("' or") >= 0 ||
      input.indexOf("1=1") >= 0 ||
      input.indexOf("union") >= 0 ||
      input.indexOf("select") >= 0 ||
      input.indexOf("drop") >= 0 ||
      input.indexOf("--") >= 0 ||
      input.indexOf("#") >= 0) {
    return true;
  }

  // Check for credential-style query: username='username',password='password'
  // We'll also handle double-quotes and optional spaces by removing whitespace for the check.
  String compact = input;
  // remove spaces, tabs, newlines for compact comparison
  compact.replace(" ", "");
  compact.replace("\t", "");
  compact.replace("\r", "");
  compact.replace("\n", "");

  // Common variants to detect:
  // username='username',password='password'
  // username="username",password="password"
  // username=username,password=password
  if (compact.indexOf("username='username',password='password'") >= 0 ||
      compact.indexOf("username=\"username\",password=\"password\"") >= 0 ||
      compact.indexOf("username=username,password=password") >= 0) {
    return true;
  }

  // Also detect cases where someone passes username='anything',password='anything'
  // (generic pattern to detect credential injection attempts)
  // Look for "username=" and "password=" together with quotes or equals
  if (compact.indexOf("username=") >= 0 && compact.indexOf("password=") >= 0) {
    // If there are single or double quotes around values, treat as suspicious
    if (compact.indexOf("username='") >= 0 || compact.indexOf("username=\"") >= 0 ||
        compact.indexOf("password='") >= 0 || compact.indexOf("password=\"") >= 0) {
      return true;
    }
    // Also treat username=...&password=... style or comma separated as suspicious in many contexts
    // (this is intentionally conservative for a honeypot)
    return true;
  }

  return false;
}

// ---------------- HTML UI ----------------
String colorfulPage(String title, String body) {
  return "<html><head><meta name='viewport' content='width=device-width,initial-scale=1'/>"
         "<style>"
         "body { background:#121212; color:#eee; font-family:Arial; text-align:center; padding:20px; }"
         "h1 { color:#00ff88; }"
         "input,button { padding:12px; margin:5px; border-radius:8px; border:none; font-size:14px; }"
         "button { background:#00ff88; color:black; font-weight:bold; }"
         "table { border-collapse: collapse; margin:auto; background:#1e1e1e; color:#00ff88; }"
         "td,th { border:1px solid #333; padding:8px; }"
         "a{ color:#00ff88; text-decoration:none; }"
         "</style></head><body><h1>" + title + "</h1>" + body + "</body></html>";
}

// ---------------- Fake Dashboard ----------------
String fakeDashboard() {
  return "<div style='display:grid;grid-template-columns:repeat(3,1fr);gap:15px;'>"
         "<div style='background:#1e1e1e;padding:20px;border-radius:10px;'>"
         "<h2>Temperature</h2><p style='font-size:24px;color:#00ff88;'>25°C</p></div>"
         "<div style='background:#1e1e1e;padding:20px;border-radius:10px;'>"
         "<h2>Light</h2><p style='font-size:24px;color:#00ff88;'>ON</p></div>"
         "<div style='background:#1e1e1e;padding:20px;border-radius:10px;'>"
         "<h2>Door</h2><p style='font-size:24px;color:#00ff88;'>Locked</p></div>"
         "</div>";
}

// ---------------- OTP Generator ----------------
String generateOTP() {
  int n = random(100000, 999999);
  char buf[8];
  snprintf(buf, sizeof(buf), "%06d", n);
  return String(buf);
}

// ---------------- Root (ATTENTION: "View Attackers" link removed) ----------------
void handleRoot() {
  server.send(200, "text/html",
              colorfulPage("IoT Configuration",
                           "<a href='/login'>User Login</a><br>"
                           "<a href='/admin'>Admin Login</a><br>"
                           "<a href='/config'>IoT Config</a><br>"
                           "<!-- View Attackers link hidden from root -->"));
}

// ---------------- User Login ----------------
void handleUserLogin() {
  String ip = server.client().remoteIP().toString();
  if (isBlocked(ip)) {
    server.send(403, "text/html", colorfulPage("Access Denied", "🚫 Your IP is permanently blocked"));
    return;
  }

  String u = server.arg("user"), p = server.arg("pass");

  if (u != "" || p != "") {
    if (detectSQLi(u) || detectSQLi(p)) {
      sendAlert("💉 SQLi attempt in USER login @ " + ip + " | Input: " + u + " / " + p);
      // Permanently block the IP on SQLi detection
      blockIPPermanently(ip, "SQLi in USER login");
      server.send(403, "text/html", colorfulPage("SQLi Blocked", "Suspicious input detected 🚫"));
    } else if (u == userName && p == generalPass) {
      loginAttempts[ip] = 0;
      sendAlert("👤 User logged in @ " + ip);
      server.sendHeader("Location", "/config", true);
      server.send(302, "text/plain", "");
    } else {
      loginAttempts[ip]++;
      sendAlert("❌ Wrong USER login @ " + ip + " | Attempt " + String(loginAttempts[ip]) +
                " | User=" + u + " Pass=" + p);
      if (loginAttempts[ip] >= 5) {
        blockedIPs.insert(ip);
        saveBlockedIPs();
        blockPort80();
      }
      server.send(403, "text/html", colorfulPage("User Login Blocked",
                                                 "Too many wrong attempts! 🚫"));
    }
    return;
  }

  server.send(200, "text/html",
              colorfulPage("User Login",
                           "<form method='POST'><input name='user' placeholder='Username'>"
                           "<input name='pass' type='password' placeholder='Password'>"
                           "<button>Login</button></form>"));
}

// ---------------- Admin Login (with SQLi trap + OTP) ----------------
void handleAdminLogin() {
  String ip = server.client().remoteIP().toString();
  if (isBlocked(ip)) {
    server.send(403, "text/html", colorfulPage("Access Denied", "🚫 Your IP is permanently blocked"));
    return;
  }

  String u = server.arg("user"), p = server.arg("pass");

  if (u != "" || p != "") {
    if (detectSQLi(u) || detectSQLi(p)) {
      sendAlert("💉 SQLi attempt in ADMIN login @ " + ip + " | Input: " + u + " / " + p);
      // Permanently block the IP on SQLi detection
      blockIPPermanently(ip, "SQLi in ADMIN login");
      server.send(403, "text/html", colorfulPage("SQLi Blocked", "Suspicious input detected 🚫"));
    } else if (u == adminName && p == generalPass) {
      loginAttempts[ip] = 0;
      String otp = generateOTP();
      otpByIP[ip] = otp;
      otpAttemptsByIP[ip] = 0;
      sendAlert("🔐 Admin credentials entered from " + ip + " | OTP generated: " + otp);
      Serial.println("OTP for " + ip + " = " + otp);

      server.send(200, "text/html",
                  colorfulPage("Two-Step Verification",
                               "<p>Enter the 6-digit OTP sent to the administrator.</p>"
                               "<form action='/admin/verify' method='POST'>"
                               "<input name='otp' placeholder='6-digit OTP'>"
                               "<button>Verify</button></form>"));
    } else {
      loginAttempts[ip]++;
      sendAlert("❌ Wrong ADMIN login @ " + ip + " | Attempt " + String(loginAttempts[ip]) +
                " | User=" + u + " Pass=" + p);
      if (loginAttempts[ip] >= 5) {
        blockedIPs.insert(ip);
        saveBlockedIPs();
        blockPort80();
      }
      server.send(403, "text/html", colorfulPage("Admin Login Blocked",
                                                 "Too many wrong attempts! 🚫"));
    }
    return;
  }

  server.send(200, "text/html",
              colorfulPage("Admin Login",
                           "<form method='POST'><input name='user' placeholder='Admin'>"
                           "<input name='pass' type='pass word' placeholder='Password'>"
                           "<button>Login</button></form>"));
}

// ---------------- Admin OTP Verification ----------------
void handleAdminVerify() {
  String ip = server.client().remoteIP().toString();

  if (isBlocked(ip)) {
    server.send(403, "text/html", colorfulPage("Access Denied", "🚫 Your IP is permanently blocked"));
    return;
  }

  String entered = server.arg("otp");
  if (entered == "") {
    server.send(200, "text/html", colorfulPage("OTP Required", "Please enter the OTP."));
    return;
  }

  if (otpByIP.find(ip) == otpByIP.end()) {
    server.send(403, "text/html", colorfulPage("No OTP Found", "No OTP was generated for this session."));
    return;
  }

  String real = otpByIP[ip];
  if (entered == real) {
    otpByIP.erase(ip);
    otpAttemptsByIP.erase(ip);
    loginAttempts[ip] = 0;
    sendAlert("✅ Admin 2FA success from " + ip);

    server.sendHeader("Location", String(BLYNK_REDIRECT_URL), true);
    String body = "<meta http-equiv='refresh' content='1;url=" + String(BLYNK_REDIRECT_URL) + "' />"
                  "<p>OTP accepted. Redirecting to the dashboard...</p>"
                  "<script>setTimeout(function(){ window.location.href = '" + String(BLYNK_REDIRECT_URL) + "'; }, 1000);</script>"
                  "<p>If you are not redirected, <a href='" + String(BLYNK_REDIRECT_URL) + "'>click here</a>.</p>";
    server.send(302, "text/html", colorfulPage("Redirecting", body));
    return;
  } else {
    otpAttemptsByIP[ip]++;
    sendAlert("❌ Wrong OTP from " + ip + " | Attempt " + String(otpAttemptsByIP[ip]));
    if (otpAttemptsByIP[ip] >= OTP_MAX_ATTEMPTS) {
      blockedIPs.insert(ip);
      saveBlockedIPs();
      server.send(403, "text/html", colorfulPage("Blocked", "Too many wrong OTP attempts 🚫"));
      sendAlert("🚫 " + ip + " blocked due to OTP failures");
    } else {
      server.send(403, "text/html", colorfulPage("Invalid OTP",
                                                 "Wrong OTP. Attempts: " + String(otpAttemptsByIP[ip]) + "/" + String(OTP_MAX_ATTEMPTS)));
    }
    return;
  }
}

// ---------------- Fake IoT Config ----------------
void handleConfig() {
  String table = "<table>";
  table += "<tr><th>Device</th><th>Status</th></tr>";
  for (int i = 1; i <= 15; i++) {
    table += "<tr><td>Device " + String(i) + "</td><td>Active</td></tr>";
  }
  table += "</table>";
  server.send(200, "text/html", colorfulPage("IoT Configuration", table));
}

// ---------------- Attackers page (still accessible directly) ----------------
void handleAttackers() {
  String table = "<table>";
  table += "<tr><th>IP</th><th>Failed Attempts</th><th>OTP Attempts</th></tr>";
  for (auto &p : loginAttempts) {
    String ip = p.first;
    int la = p.second;
    int oa = 0;
    if (otpAttemptsByIP.find(ip) != otpAttemptsByIP.end()) oa = otpAttemptsByIP[ip];
    table += "<tr><td>" + ip + "</td><td>" + String(la) + "</td><td>" + String(oa) + "</td></tr>";
  }
  table += "</table>";
  server.send(200, "text/html", colorfulPage("Known Attackers", table));
}

// ---------------- Fake Extra Ports ----------------
void checkFTP() {
  WiFiClient client = ftpServer.available();
  if (client) {
    String ip = client.remoteIP().toString();
    client.print("220 Fake FTP Service Ready\r\n");
    sendAlert("📂 FTP connection from " + ip);
    client.stop();
  }
}

void checkSSH() {
  WiFiClient client = sshServer.available();
  if (client) {
    String ip = client.remoteIP().toString();
    client.print("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\r\n");
    sendAlert("🔑 SSH connection from " + ip);
    client.stop();
  }
}

void checkMQTT() {
  WiFiClient client = mqttServer.available();
  if (client) {
    String ip = client.remoteIP().toString();
    client.print("MQTT CONNACK FakeBroker\r\n");
    sendAlert("📡 MQTT connection from " + ip);
    client.stop();
  }
}

// ---------------- Setup ----------------
void setup() {
  Serial.begin(115200);
  delay(100);
  randomSeed(esp_random());

  // Load persisted blocked IPs (SPIFFS)
  loadBlockedIPs();

  WiFi.mode(WIFI_AP_STA);
  WiFi.begin(ssid, pass);
  Serial.print("Connecting WiFi");
  while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
  Serial.println("\nConnected: " + WiFi.localIP().toString());

  WiFi.softAP(fakeSSID, fakePASS);
  Serial.println("Fake AP started: " + String(fakeSSID));

  Blynk.begin(BLYNK_AUTH_TOKEN, ssid, pass);

  server.on("/", HTTP_GET, handleRoot);
  server.on("/login", HTTP_GET, handleUserLogin);
  server.on("/login", HTTP_POST, handleUserLogin);
  server.on("/admin", HTTP_GET, handleAdminLogin);
  server.on("/admin", HTTP_POST, handleAdminLogin);
  server.on("/admin/verify", HTTP_POST, handleAdminVerify);
  server.on("/config", HTTP_GET, handleConfig);
  server.on("/attackers", HTTP_GET, handleAttackers);

  server.begin();
  serverAlt.begin();
  ftpServer.begin();
  sshServer.begin();
  mqttServer.begin();

  sendAlert("✅ Honeypot started with SQLi trap + OTP redirect (root hides attackers)");
}

// ---------------- Loop ----------------
void loop() {
  Blynk.run();
  reopenPort80();

  if (!port80Closed) {
    server.handleClient();
  }
  serverAlt.handleClient();
  checkFTP();
  checkSSH();
  checkMQTT();
}
