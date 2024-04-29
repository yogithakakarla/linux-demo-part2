# Security

Security in Linux refers to the measures taken to protect a Linux-based system from unauthorized access, data breaches, malware, and other security threats. It includes various aspects as below

## Linux Accounts

We can classify accounts as below for our understanding
1) user account
2) super user acount
3) system account
4) service account 

### user account
Every user in linux has its account called User account uid . they have dedicated home directory like /home/users/user1/

Information about user is stored in /etc/passwd file

```
cat /etc/passwd
```

Groups -> Linux group is collection of users. it is used to organize users based on common attributes such as role or function .
Information about groups is stored in /etc/group

```
cat /etc/group
```
### super user account 
super user account which has uid=0 generally refers to be root user

### system account

Apart from user account , we have system account to be used by software and services that will not run as super user. UID for system accounts are usually <100  or between 500-1000. they usually do not have dedicated home directory . examples are root,daemon, bin,sys etc .
System accounts are used internally by the operating system or system services to perform system maintenance tasks.

### service accounts

service accounts are used to run specific services or applications and manage the resources required by those services.
The UID range for service accounts often starts from 1000 and ends at around 59999 or higher. This range ensures that service accounts are assigned UIDs that do not conflict with system accounts (which typically have UIDs below 1000) and regular user accounts.

Examples of service accounts include accounts associated with web servers (e.g., www-data for Apache), database servers (e.g., mysql for MySQL), email servers (e.g., mail for Sendmail), and other services or applications running on the system.

```
id   #gives information about the user 
``` 
```
who  # to see list of users currently logged into system
```
```
last   # shows user , date and time when system was rebooted
```
switching users

```
sudo su -  # switching to root from current session
```
```
su - user2 # switching to user2
```

```
cat /etc/sudoers # The /etc/sudoers file is a system configuration file that controls the sudo (superuser do) command's behavior. It specifies which users or groups are allowed to execute commands as the root user or another user with elevated privileges.
```

### Access Control Files -> passwd, group, shadow

Most of the access control files are stored under /etc directory. This directory can be read by any user by default , but only root user has access to write it

In Linux and Unix-like operating systems, some common access control files include:

**/etc/passwd:** While not strictly an access control file, the /etc/passwd file contains information about user accounts on the system, including their usernames, user IDs (UIDs), home directories, and login shells. It is used by the system to authenticate users during the login process.

**/etc/shadow:** The /etc/shadow file stores encrypted password hashes for user accounts. It is accessible only by the root user and contains more sensitive information than the /etc/passwd file.

**/etc/group:** The /etc/group file contains information about groups on the system, including group names, group IDs (GIDs), and a list of users who are members of each group. It is used to manage group memberships and permissions.

**/etc/sudoers:** The /etc/sudoers file is a system configuration file that controls the sudo (superuser do) command's behavior. It specifies which users or groups are allowed to execute commands as the root user or another user with elevated privileges.

These are just a few examples of access control files commonly used in Linux and Unix-like systems. Depending on the system configuration and installed software, there may be additional access control mechanisms and configuration files used to enforce security policies and manage user access.


### User Management


User management in Linux involves creating, modifying, and deleting user accounts, as well as managing user permissions and access rights. Here are some common tasks and tools used for user management in Linux:

1) Creating Users:

The useradd command is used to create new user accounts from the command line. For example:

```
sudo useradd username
```

You can specify additional options, such as the user's home directory and login shell, using command-line options.

2) Modifying Users:
The usermod command is used to modify existing user accounts. For example, to change a user's primary group:
```
sudo usermod -g newgroup username
```
You can also use usermod to change a user's home directory, login shell, or other attributes.

3) Deleting Users:
The userdel command is used to delete user accounts. For example
```
sudo userdel username

```
You can use the -r option to remove the user's home directory and mail spool.

4) Managing Passwords:
The passwd command is used to set or change a user's password. For example
```
sudo passwd username
```
Users can change their own passwords using the passwd command without sudo privileges.

5) Viewing User Information:
The id command displays information about a specific user, including their UID and GID.
The finger command can be used to view more detailed information about users, such as their full name and the last time they logged in.

6) Managing Groups:
The groupadd, groupmod, and groupdel commands are used to manage groups in a similar way to user accounts.

```
sudo groupadd groupname
sudo groupmod -n newname oldname
sudo groupdel groupname
sudo usermod -aG groupname username #This command adds the specified user to the specified group.
sudo usermod -g groupname username # This command sets the specified group as the user's primary group
getent group groupname  # listing group members 
groups username   # list groups user is part of
```
Lets talk something called restricted shell. A restricted shell is a type of shell program that limits the capabilities and functionalities available to a user when they log in. The purpose of a restricted shell is to provide a controlled environment that prevents users from executing certain commands or accessing parts of the system beyond their allowed scope. Here's what it typically means:

**Limited Command Execution:** Restricted shells often restrict the commands that users can execute. For example, they might only allow basic commands like cd (change directory) or echo, while disallowing potentially dangerous commands like rm (remove) or sudo.

so one way to give sudo permissions to run just few commands is as below

```
sudo visudo

username ALL=(ALL) NOPASSWD: /bin/ls, /bin/pwd, /bin/echo
```

Now the user can execute the allowed commands using sudo

```
sudo ls
sudo pwd
sudo echo "Hello, world!"
```
Restricted shells can be applied on a per-user basis, allowing administrators to tailor the level of restriction to individual users' needs. For example, certain administrative users might have more privileges than regular users.

**No Interactive Shell:** In some cases, a restricted shell might not even provide an interactive shell prompt. Instead, it might immediately exit upon login or display a message indicating that interactive logins are not allowed.

Below commands are to create or modify users with no interactive shell.creating users with non-interactive shells is a security best practice in many environments, particularly for system accounts and service accounts associated with background services or automated processes. It helps to minimize security risks and ensure system integrity.

```
sudo useradd -s /sbin/nologin username
```

```
sudo usermod -s /sbin/nologin username
```

 Restricted shells are often used in environments where security and compliance are paramount. By limiting the capabilities of users, restricted shells help reduce the risk of unauthorized access or malicious actions.


Examples: Common examples of restricted shells include /bin/false and /sbin/nologin. Users assigned these shells typically cannot interact with the shell prompt at all.

 Lets discuss about something called **PAM authentication**. Setting up PAM (Pluggable Authentication Modules) configuration involves configuring authentication mechanisms and policies for various services on a Linux system. PAM provides a flexible framework for authenticating users and managing authorization policies.

 PAM configuration files are located in the /etc/pam.d/ directory. Each file corresponds to a specific service or application that uses PAM for authentication. Few files are common-auth, common-account, common-password, and common-session, which are used to define authentication, account management, password management, and session management policies respectively.

The syntax of a PAM configuration line is: module-type control-flag module-path module-arguments

Module Types: Module types include auth, account, password, and session, which correspond to different stages of the authentication process.


Control Flags: Control flags determine how the module's success or failure affects the overall authentication process. Common control flags include required, requisite, sufficient, and optional.

Module Path: The module path specifies the location of the PAM module library.

Module Arguments: Module arguments are optional and provide additional configuration options for the module.

Here's an example of a PAM configuration line for SSH authentication (/etc/pam.d/sshd):

```
auth    required    pam_unix.so
```
This line specifies that the pam_unix.so module is required for SSH authentication.

When a user attempts to authenticate (e.g., logging in via SSH or entering a password), the PAM-aware application (e.g., SSH server) invokes the PAM library to handle authentication.

### File permission and Ownership

AS we learnt earlier , that ls -l list out all details of files present over there . it also list permission for file/directory present .

For example if we consider -rwxrwxrwx , the first - represent file type . so lets look what all different types of files we have and how to identify them.

   File Type           |     Identifier
-----------------------|----------------
 Directory             |     d
-----------------------|---------------
 regular File          |     -
-----------------------|---------------
 Character device      |     c
-----------------------|----------------
 Link                  |     l
 ----------------------|-----------------
 Socket File           |     s
 ----------------------|------------------
 pipe                  |     p
 ----------------------|------------------                    
 Block device          |     b
 ----------------------|-------------------


 
In this Linux file permissions , lets look at next 
    

- rwx  rwx  rwx
       
 first octet(-) represents filetype
 
 next 3 octets represents permissions for owner(u)
 
 next 3 octets represents permissions for group(g)
 
 next 3 octets represents permissions for others(o)

But when we give permissions/modify permissions  we generally mention it as chmod 777 filename.txt  or chmod 466 filename.txt  , so lets check Octal value for each bit 

Bit         Purpose         Octal Value
r           Read                4
w           write               2
x           execute             1


SO , lets understand whats 777 -> rwx permissions for owner, group , others   
                           764 -> rwx for owner , read and write permission for group ,read for  others
 

```
chmod 777 filename.txt
```
we can also change permissions as below

```
chmod u+rwx test-file   # provide rwx permissions to owner(u)

chmod ugo+r-x test-file # provide read permission to user(u),group (g), others (o) and remove execute (x) permissions for u , g ,o

chmod o-rwx test-file  # remove r,w,x for others

chmod u+rwx,g+r-x,o-rwx test-file # read access for owner , add read for group and remove execute for group , remove r,w,x for others
```

### SSH and SCP

SSH (Secure Shell):

SSH is a network protocol used for secure remote access to systems over unsecured networks.

It provides a secure channel for communication between two computers, allowing users to log in securely, execute commands remotely, and transfer files securely.

SSH operates on TCP port 22 by default, but it can be configured to use different ports if needed.

SSH supports various authentication methods, including password authentication, public key authentication, and multi-factor authentication (e.g., using Google Authenticator).

```
ssh username@remote_host
```

```
ssh -p port_number username@remote_host

```
```
ssh -i path/to/private_key username@remote_host
```

SCP

SCP is a command-line tool used for securely transferring files between a local and a remote host or between two remote hosts over an SSH connection.

It uses the SSH protocol for authentication and encryption, providing secure file transfers.

SCP syntax is similar to the cp command in Unix/Linux systems, making it easy to use and integrate into shell scripts.

SCP supports both recursive copying of directories and copying of multiple files in a single command.

SCP preserves file permissions, timestamps, and ownership during file transfers, maintaining the integrity of the transferred files.

SCP can be used both interactively, where users specify source and destination paths manually, and non-interactively, where file transfers are scripted or automated.

Difference between SCP and cp in Linux:-

cp is a command-line utility used for copying files and directories within a filesystem.

It operates locally and does not provide encryption or secure transfer mechanisms.

It is commonly used for tasks such as duplicating files, creating backups, and moving files within the same machine.

cp is suitable for local file operations where encryption and secure transfer are not required.

scp encrypts data during transfer, providing secure file copying between hosts as well as locally.

It is commonly used for tasks such as transferring files between a local machine and a remote server or between two remote servers.

scp is suitable for scenarios where data privacy, integrity, and security are paramount, such as transferring sensitive files or backups over untrusted networks.


```
scp /path/to/local_file username@remote_host:/path/to/destination
```

```
scp username@remote_host:/path/to/remote_file /path/to/destination
```


```
scp -P port_number username@remote_host:/path/to/remote_file /path/to/destination
```

```
scp -i path/to/private_key /path/to/local_file username@remote_host:/path/to/destination
```

### IP Tables

IPtables is a firewall management tool in Linux that allows administrators to define rules for controlling the flow of network traffic. 

It operates within the Linux kernel's netfilter framework and provides capabilities for packet filtering, Network Address Translation (NAT), and packet mangling.

we can view existing iptables rules as below. This command lists all the currently configured rules, including the default policies for each chain (INPUT, OUTPUT, FORWARD), as well as any user-defined rules.

```
iptables -L -n

```
This command adds a rule to allow incoming TCP traffic on port 22 (SSH) from the IP range 192.168.1.0/24.

```

iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT
```

This command deletes the previously added rule that allows incoming SSH traffic from the specified IP range.

```
iptables -D INPUT -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT
```


Suppose you want to allow incoming SSH traffic (port 22) from a specific IP address range (192.168.1.0/24) while blocking all other incoming traffic. You can achieve this with iptables as follows:


```
# Flush existing rules (optional)
iptables -F

# Set default policy to drop incoming traffic
iptables -P INPUT DROP

# Allow incoming SSH traffic from specific IP range
iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT

# Allow incoming ICMP (ping) traffic (optional)
iptables -A INPUT -p icmp -j ACCEPT
```
