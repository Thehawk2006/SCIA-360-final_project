# SCIA-360-final_project
Title: Secure System Observer (SSO) 

         Course: SCIA 360 

     Date: May 11th, 2026 

 

 

    Group Members: 

    - Tristen: Admin – Module C: Security & Authentication 

    -Robert: Auditor – Module A: Kernel & Processes 

    -Rowland: Auditor – Module B: File System & Logs 

 

    GitHub Repository Link: https://github.com/Thehawk2006/SCIA-360-final_project  

 

 

 

 

 

 

 

 

 

Table Of Contents: 

Project Overview ..................... Page 3 

System Requirements ................. Page 3-4 

Installation Guide .................. Page 4-6 

Module A: Kernel & Processes ........ Page 6-7 

Module B: File System & Logs ........ Page 7-9 

Module C: Security & Authentication ........... Page 9-12 

How to Use the Application .......... Page 12-14 

Security Analysis ................... Page 14-15 

 

 

 

 

 

 

 

 

 

Project Overview & System Requirements 

Project Overview: 

This project titled the Secure System Observer or SSO is a command line Linux graphical user interface that monitors operating system health through the terminal. This unlike manager tools in Linux like top or task manager, it requires user authentication before launching the application and enforces strict role-based access controls (RBAC) on what role can view sensitive system processes and who can delete system snapshot logs which restricted for auditors.  

This project was built to combine two different fields of computer science, which include System Monitoring and Security Engineering. Also, because it was the final project for this class. The goal of this project was to build a tool that directly interacts with the operating system kernel, that also implements real-world modern security principles like salting, hashing passwords, role-based access control (RBAC), and the principle of least privilege.  



System Requirements: 

	This section includes the system requirements needed to run this project. For the operating system, you need Ubuntu Linux version 22.04 or higher. For the Python version, you need Python 3.10 or higher. For the required packages you need to download, you need python3-psutil, python3-colorama. For the internet, you only need it for the installation to download everything only. For the storage requirement, you need a minimum of 50 megabytes of free storage space. For RAM requirements, you need at least 1 gigabyte for it to run efficiently.  

Installation Guide: 

This section will explain how to get the SSO running on your machine from scratch. You must follow these steps in order. 

Step 1: Install Ubuntu 22.04 Desktop from ubuntu.com and install it on an virtual machine using UTM, VMware, or VirtualBox.  

Step 2: Open your terminal in the Virtual Machine.  

Step 3: Install git on your terminal with this command: sudo apt install git –y.  

Step 4: Clone the repository using this command: git clone https://github.com/Thehawk2006/SCIA-360-final_project and then use this command to create a directory cd final_project. 

Step 5: Install these required packages with this command: sudo apt install python3-psutil python3-colorama –y. 

Step 6: Create user accounts for the SSO, this is code/command to use: 

python3 -c " 

from auth import register_user register_user 

('yourname', 'yourpassword', 'admin')  

register_user('member2', 'theirpassword', 'auditor') " 

Step 7: Get the application running with this command: python3 main.py 

 

 

 

 

Module A: Kernel & Processes: 

Module A is responsible for reading live data directly from the OS Linux kernel. It uses the library from the psutil which interfaces with the /proc virtual filesystem that retrieves the process and information from the memory in real-time. Every running program in Linux has a process control block that is stored in the kernel. It is accessed by reading the /proc/[pid]/stat for each of the processes. It then gives us the process ID, name, the current state its in, and which user owns it. There are 6 different process states in SSO which include: R-running meaning that it is currently using the CPU, S-sleeping meaning its waiting for an event like a user input, D-disk-sleep which it is waiting for disk input/output, Z-zombie which means the process is finished but not cleaned up yet, ST-stopped which means it is paused by a signal, and lastly I-idle which means it is still. Memory reading works through physical RAM and swap space data being directly read from /proc/meminfo. Each is displayed separately to demonstrate a understanding of virtual memory. Admin and auditors view is viewed differently for each role. Administrators can view all processes including root ones, while auditors can only view basic processes which enforces the principle of least privilege in module C.  

 

 

Module B: File Systems & Logs 

	Module B handles all the operations dealing with files in the Secure System Observer. It manages saving system snapshots, recording file metadata, deleting logs, and verifying file integrity. All the logs are stored in the file/logs directory. Feature 1 in this module includes saving a system snapshot: when a user selects 3 in the SSO, the save_snapshot() function in file_manager.py creates a unique named JSON file using the current timestamp in was created so no snapshots can overwrite each other. An example file name of this would be logs/snapshot_20260504_102345.json. Feature 2 includes metadata management which allows every snapshot to capture what time/date it was created at, which user created it, and the total amount of processes captured for it and it is written/shown in a JSON file. Feature 3 includes the SHA-256 integrity check: which immediately after the snapshot is saved, a .sha256 file is created containing the SHA-256 hash of the entire snapshot file. When the log is opened later with option 6, it will recompute the hash and compare it to the stored one: if the hashes match it will show its untampered but if they don’t it will show a violation alert showing the file was modified. This shows our design can detect tampering by external text editors, malware, or malicious insiders trying to their tracks in our system.  





Module C: Security & Authentication 

	Module C is our security layer that guards the entire applications. It handles password storage, user authentication, RBAC, and Security Alert Logging. Our GUI wouldn’t function without passing through Module C first. Here is the login process: The user enters a username and password, then salt is retrieved from the users.json file for that user, then the SHA-256 with salt plus password is computed, then the result is compared to the stored hash, and lastly if they match the user is granted access with their role assigned to them. Passwords are never stored in plain text and must go through this process before storage: first a random 32-character salt is generated using secrets.token_hex(16), then the salt is combined with the password, then the SHA-256 hash is computed on the combination, and then the password hash and salt are saved to users.json. Our SSO defines different roles with two different permissions: ADMIN & AUDITOR. ADMIN are allowed to view all processes, view memory usage, save system snapshots, list & verify logs, and delete log files. AUDITORs are allowed to view basic processes, view memory usage, save system snapshots, list & verify logs, but can’t view hidden root processes as well as cannot delete logs. Every security even is recorded automatically in the logs/security_audit.log with a timestamp, username, event type, and a full description of the event. Events record failed login attempts, successful login attempts, access denied actions, and user logouts with how long they were logged in for.  

]. 

How to Use The Application 

To start this application, you must do these two following commands: cd ~/final_project and python3 main.py. After that you will be shown a UI with options to choose from. Choosing option 1 will let administrators to view all processes and auditors to view basic processes but not root-owned ones. Choosing option 2 will let you view physical RAM and swap space stats/storage in the system. Choosing option 3 will save the current system snapshot state to the logs/ file. Choosing option 4 will show all snapshot files currently saved in the system. Choosing option 5 will show all security audit events/logs in the system. Choosing option 6 will let you check and view file integrity that allows you to see if there were tampering or not. Choosing 7 for an administrator will allow them to delete logs and for auditors it will deny the action and send a security audit log. Lastly choosing option 8 will let you exit the Secure System Observer (SSO) and then it will log automatically log the session in the security audit logs. 

 

 

 

Security Analysis 

	We chose SHA-256 as our password hashing algorithm for multiple reasons. For one, it is a one-way function that is irreversible. We also chose it because it is the industry standard hashing algorithm used for TLS, SSL, and Git. Lastly, we chose this hashing algorithm as it protects against collision attacks on it. We add salt to this because without it two users who by chance use the same password would produce identical hashes, making it easier for it to crack with rainbow table attacks. Each salt in our GUI is randomly generated using secrets.token_hex(16) and is random and unique for every user created in the system. With salt added to our system, it makes rainbow table attacks ineffective now and now produces two different hashes for identical passwords made with this added. Two attack vectors that our security design mitigates include password file theft and log file tampering. The first attack vector scenario is the attacker directly reads the user.json file directly from the disk. When they read it they will only see salted SHA-256 password hashes and usernames but no passwords in plain text. Our defense mitigates it as SHA-256 is irreversible and each brute force attempt requires the added salt with guessing the password, making it almost impossible for a brute force attack to happen. The second attack vector scenario is when an attacker edits the snapshot file in a text editor to remove the evidence of an unauthorized process. Our defense mitigates that through a SHA-256 integrity check detecting any changes made to the snapshot. Lastly, it will flag the file as violated, and the authorized user can delete the file from there.  
