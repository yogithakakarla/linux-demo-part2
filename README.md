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

/etc/passwd: While not strictly an access control file, the /etc/passwd file contains information about user accounts on the system, including their usernames, user IDs (UIDs), home directories, and login shells. It is used by the system to authenticate users during the login process.

/etc/shadow: The /etc/shadow file stores encrypted password hashes for user accounts. It is accessible only by the root user and contains more sensitive information than the /etc/passwd file.

/etc/group: The /etc/group file contains information about groups on the system, including group names, group IDs (GIDs), and a list of users who are members of each group. It is used to manage group memberships and permissions.

/etc/sudoers: The /etc/sudoers file is a system configuration file that controls the sudo (superuser do) command's behavior. It specifies which users or groups are allowed to execute commands as the root user or another user with elevated privileges.

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



### File permission and Ownership



### SSH and SCP



### IP Tables
