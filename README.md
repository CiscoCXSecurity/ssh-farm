# ssh-farm
A simple tool to spawn multiple SSH services via docker.

**Use Case #1: Testing SSH clients**.  The configuration of some SSH servers can make them hard to connect to with modern clients.  ssh_farm helps you quickly verify that an SSH client/tool that you're using/developing can connect to SSH servers that use unusual/old configurations.  Example: If you're using an SSH password-guessing tool, it's useful to know that you're not getting false-negative results because your tools is failing to connect at the SSH protocol level.

**Use Case #2: Setting up hacker challenges** to hone credential-shuffling skills (for yourself or your team).  You could use ssh_farm to help set up a maze of SSH services that tools/pentesters need to navigate through.  Put weak passwords / exposed SSH keys on various systems that allow access to other systems.  Make sure you're able to execute your methodology correctly even when there's a need to pivot/privesc/connect using SSH setting that aren't supported by default in modern clients.

## Usage
Note: You need to run as root or a user that can run docker commands
```
usage: ssh-farm.py ( -f config.csv [ -d ] [ -C credentials.txt ] [ -t trusts.txt] [ -c sshd_config_base ] [ -w /path/to/a/writable/working/directory ] | -o sshd_config_base.txt )

Create lots of docker containers running sshd

options:
  -h, --help            show this help message and exit
  -f FARMCONFIG, --farmconfig FARMCONFIG
                        CSV file containing configuration
  -c SSHDBASECONFIG, --sshdbaseconfig SSHDBASECONFIG
                        sshd_config file to use as base
  -d, --delete          Delete all containers named ssh_farm_*
  -T TIMEZONE, --timezone TIMEZONE
                        Timezone for containers.  Default is Etc/UTC
  -P SSH_PORT, --ssh_port SSH_PORT
                        SSH port for containers.  Default is 22
  -t TRUSTS, --trusts TRUSTS
                        CSV file containing SSH key trusts.  Columns: src_host,src_user,dst_host,dst_user,known_hosts_clue.  Default is none
  -N, --no_clean_up     Do not cleanup tmp files.  Default is False
  -n PREFIX, --prefix PREFIX
                        Prefix for docker container name.  Default is ssh_farm_
  -C CREDS, --creds CREDS
                        CSV file containing OS usernames and passwords.  Columns: ID,username,password,sudo. Default is none
  -x PROBLEM, --problem PROBLEM
                        Create extra sshd's that are harder to connect to.  List one or more of ciphers,kex,hostkey.  Default is none
  -i DOCKER_IMAGE, --docker_image DOCKER_IMAGE
                        Docker image to use for containers.  Default is linuxserver/openssh-server:version-9.3_p2-r0
  -o OUTPUTSSHDCONFIG, --outputsshdconfig OUTPUTSSHDCONFIG
                        Output sshd_config from docker

Example 1: 

ssh-farm.py -o sshd_config_base.txt # output the base sshd_config file from the docker image

Example 2 (Generic Use Case): 

ssh-farm.py -d -f config-example1.csv -C creds-example1.csv -c sshd_config_base.txt # Start containers described in the CSV file.

config.csv is expected to have the following columns (also see config-example*.csv files):
* required: ID
* optional: ssh_port,docker_image,any sshd_config setting, e.g. PermitRootLogin

creds.csv is expected to have the following columns:
* required: ID,username,password
* optional: sudo,hash_type

hash_type must be one of: DES, MD5, SHA256, SHD512, "" (empty string - for default: MD5)

Example 3 (Use Case: Testing if SSH tools/clients can connect to servers that have been configured with problematic ciphers, key exchange, and hostkey settings):

ssh-farm.py -d -f config-example1.csv -x ciphers,kex,hostkey

Example 4 (Use Case: Creating a hacker challenge):

ssh-farm.py -N -d -f config-challenge1.csv -C creds-challenge1.csv -t trusts-challenge1.csv

trusts.csv is expected to have the following columns:
* required: src_host,src_user,dst_host,dst_user,known_hosts_clue
* optional: N/A

IMPORTANT: Before you run ssh_farm for the first time, pull down the openssh-server docker image:
# docker pull linuxserver/openssh-server:version-9.3_p2-r0
```

# Example of Use Case #1: Testing Medusa's ability to guess SSH passwords

If medusa gives us a negative result (i.e. tells us that a password isn't valid), is that because the password is actually wrong, or is it because medusa is failing to connect to the SSH server?  ssh_farm can help us answer that question.

First we define how our base openssh server should be configured using a CSV file:
```
# cat config.csv
ID,ssh_port
1,22
```
Then some valid credentials:
```
# cat creds.csv
ID,username,password,sudo,hash_type
1,test1,password1,0,
```
Note: The ID field specifies the container number (1 in this case).

This will set up a single openssh server with a single user account (test1) and password (password1).  We can then use ssh_farm to create a docker container running this openssh server (container ssh_farm_1) alongside lots of others with more problematic configurations:
```
# python3 ssh-farm.py -d -x ciphers,kex,hostkey -f config.csv -C creds.txt
 [I] Using /tmp/tmp_57bc6m8 as working directory
[I] sshd_config_base: None (3189 bytes)
[I] farm_config: config.csv
[-] Deleting container: ssh_farm_1
[+] Starting container: ssh_farm_1
[+] Starting container: ssh_farm_1_c_3des-cbc
[+] Starting container: ssh_farm_1_c_aes128-cbc
[+] Starting container: ssh_farm_1_c_aes192-cbc
[+] Starting container: ssh_farm_1_c_aes256-cbc
[+] Starting container: ssh_farm_1_k_diffie-hellman-group14-sha1
[+] Starting container: ssh_farm_1_k_diffie-hellman-group1-sha1
[+] Starting container: ssh_farm_1_k_diffie-hellman-group-exchange-sha1
[+] Starting container: ssh_farm_1_h_ssh-dss
[+] Starting container: ssh_farm_1_h_ssh-rsa
[I] 10 containers running
[I] ssh_farm_1_h_ssh-rsa is running at 172.17.0.12
[I] ssh_farm_1_h_ssh-dss is running at 172.17.0.11
[I] ssh_farm_1_k_diffie-hellman-group-exchange-sha1 is running at 172.17.0.10
[I] ssh_farm_1_k_diffie-hellman-group1-sha1 is running at 172.17.0.9
[I] ssh_farm_1_k_diffie-hellman-group14-sha1 is running at 172.17.0.8
[I] ssh_farm_1_c_aes256-cbc is running at 172.17.0.7
[I] ssh_farm_1_c_aes192-cbc is running at 172.17.0.6
[I] ssh_farm_1_c_aes128-cbc is running at 172.17.0.5
[I] ssh_farm_1_c_3des-cbc is running at 172.17.0.4
[I] ssh_farm_1 is running at 172.17.0.2
```

Here we use `-d` to delete any existing containers named `ssh_farm_*`.  `-x` tells ssh_farm to create extra containers with problematic configurations.  In this case, we're creating containers with problematic ciphers, key exchange, and hostkey settings that are not supported by default in modern SSH clients.  We're also using `-f` and `-C` to tell ssh_farm to use config.csv as the base configuration for all containers and to set up the accounts described in `creds.txt.  If we had a suitable sshd_config file, we could use `-c` to tell ssh_farm to use that instead.  By default the base sshd_config file is the one in the [docker image](https://hub.docker.com/r/linuxserver/openssh-server).

Create an `ips.txt` file containing all the docker IPs above (172.17.x.x):
```
# cat ips.txt
172.17.0.12
172.17.0.11
172.17.0.10
172.17.0.9
172.17.0.8
172.17.0.7
172.17.0.6
172.17.0.5
172.17.0.4
172.17.0.2
```

Now we can use medusa to test our SSH server:
```
# medusa -H ips.txt -u test1 -p password1 -M ssh
Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>

ACCOUNT CHECK: [ssh] Host: 172.17.0.12 (1 of 10, 0 complete) User: test1 (1 of 1, 0 complete) Password: password1 (1 of 1 complete)
ACCOUNT FOUND: [ssh] Host: 172.17.0.12 User: test1 Password: password1 [SUCCESS]
ACCOUNT CHECK: [ssh] Host: 172.17.0.11 (2 of 10, 1 complete) User: test1 (1 of 1, 0 complete) Password: password1 (1 of 1 complete)
ACCOUNT FOUND: [ssh] Host: 172.17.0.11 User: test1 Password: password1 [SUCCESS]
ACCOUNT CHECK: [ssh] Host: 172.17.0.10 (3 of 10, 2 complete) User: test1 (1 of 1, 0 complete) Password: password1 (1 of 1 complete)
ACCOUNT FOUND: [ssh] Host: 172.17.0.10 User: test1 Password: password1 [SUCCESS]
ACCOUNT CHECK: [ssh] Host: 172.17.0.9 (4 of 10, 3 complete) User: test1 (1 of 1, 0 complete) Password: password1 (1 of 1 complete)
ACCOUNT FOUND: [ssh] Host: 172.17.0.9 User: test1 Password: password1 [SUCCESS]
ACCOUNT CHECK: [ssh] Host: 172.17.0.8 (5 of 10, 4 complete) User: test1 (1 of 1, 0 complete) Password: password1 (1 of 1 complete)
ACCOUNT FOUND: [ssh] Host: 172.17.0.8 User: test1 Password: password1 [SUCCESS]
ACCOUNT CHECK: [ssh] Host: 172.17.0.7 (6 of 10, 5 complete) User: test1 (1 of 1, 0 complete) Password: password1 (1 of 1 complete)
ACCOUNT FOUND: [ssh] Host: 172.17.0.7 User: test1 Password: password1 [SUCCESS]
ACCOUNT CHECK: [ssh] Host: 172.17.0.6 (7 of 10, 6 complete) User: test1 (1 of 1, 0 complete) Password: password1 (1 of 1 complete)
ACCOUNT FOUND: [ssh] Host: 172.17.0.6 User: test1 Password: password1 [SUCCESS]
ACCOUNT CHECK: [ssh] Host: 172.17.0.5 (8 of 10, 7 complete) User: test1 (1 of 1, 0 complete) Password: password1 (1 of 1 complete)
ACCOUNT FOUND: [ssh] Host: 172.17.0.5 User: test1 Password: password1 [SUCCESS]
ACCOUNT CHECK: [ssh] Host: 172.17.0.4 (9 of 10, 8 complete) User: test1 (1 of 1, 0 complete) Password: password1 (1 of 1 complete)
ACCOUNT FOUND: [ssh] Host: 172.17.0.4 User: test1 Password: password1 [SUCCESS]
ACCOUNT CHECK: [ssh] Host: 172.17.0.2 (10 of 10, 9 complete) User: test1 (1 of 1, 0 complete) Password: password1 (1 of 1 complete)
ACCOUNT FOUND: [ssh] Host: 172.17.0.2 User: test1 Password: password1 [SUCCESS]
```

So on these particular test cases, medusa worked perfectly.  If there are other corner cases you want to test, look into creating a CSV file that describes the SSH services you want to test or tweak the source code to add more problematic configurations.

# Another example of Use Case #1: Testing Hydra's ability to guess SSH passwords

Use the same setup as for medusa above, but run hydra instead this time:
```
# hydra -M ips.txt -l test1 -p password1  ssh
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-27 11:39:54
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 1 task per 10 servers, overall 10 tasks, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking ssh://(10 targets):22/
[ERROR] could not connect to ssh://172.17.0.12:22 - kex error : no match for method server host key algo: server [ssh-rsa], client [rsa-sha2-512,rsa-sha2-256,ssh-ed25519,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256]
[ERROR] could not connect to ssh://172.17.0.11:22 - kex error : no match for method server host key algo: server [ssh-dss], client [ssh-ed25519,ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256]
[ERROR] could not connect to ssh://172.17.0.10:22 - kex error : no match for method encryption client->server: server [aes256-cbc], client [chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,]
[ERROR] could not connect to ssh://172.17.0.9:22 - kex error : no match for method encryption client->server: server [aes192-cbc], client [chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,]
[ERROR] could not connect to ssh://172.17.0.8:22 - kex error : no match for method encryption client->server: server [aes128-cbc], client [chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,]
[ERROR] could not connect to ssh://172.17.0.7:22 - kex error : no match for method encryption client->server: server [3des-cbc], client [chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr,]
[ERROR] could not connect to ssh://172.17.0.6:22 - kex error : no match for method kex algos: server [diffie-hellman-group-exchange-sha1], client [curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256]
[ERROR] could not connect to ssh://172.17.0.5:22 - kex error : no match for method kex algos: server [diffie-hellman-group1-sha1], client [curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256]
[ERROR] could not connect to ssh://172.17.0.4:22 - kex error : no match for method kex algos: server [diffie-hellman-group14-sha1], client [curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256]
[22][ssh] host: 172.17.0.2   login: test1   password: password1
1 of 10 targets successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-07-27 11:39:54
```
So here, hydra has let us know what's happening in 100% of cases, but only logged in 1 time out of 10.  So as long as we're reading the error messages our pentest won't necessarily suffer from false negatives.  However if we'd automated our testing and were only grepping for positive results, we'd have missed 9 out of 10 issues.  Good to know.

FWIW, I quickly ran strace and found that hydra reads `~/.ssh/config` and `/etc/ssh/ssh_config`, but adding `ssh-dss` to these files didn't seem to help.  So I'm not sure if/how hydra can be made to connect to old SSH servers.  Here's what I tried:
```
# cat ~/.ssh/config
Host *
 HostKeyAlgorithms=+ssh-dss
# cat /etc/ssh/ssh_config
Host *
 HostKeyAlgorithms=+ssh-dss
``` 

# Example of Use Case #2: Setting up hacker challenge

We'll set up 5 containers running sshd.  We specify the account that will exist on each using `creds.txt`and the trust relationships that should be set up on each using `trusts.csv`.  We'll also specify the base sshd_config file to use using `trusts.csv`.  Here, trusts refers to authorized_keys.  ssh_farm will optionally create a corresponding known_hosts file for the target system if desired.
```
# cat config-challenge1.csv # minimal config.  No port or other parameters need be specified. 
ID
1
2
3
4
5

# cat creds-challenge1.csv # Some users have sudo rights; some don't.  Some have different password hashes.
ID,username,password,sudo,hash_type
1,user0,password,yes,
1,user1,Password1,no,DES
2,user1,Password1,no,MD5
1,user2,Password,no,SHA256
5,user3,user3,no,SHA512

# cat trusts-challenge1.csv # Pairs of host/users can that id_rsa/authorized_keys pairs set up. 
src_host,src_user,dst_host,dst_user,known_hosts_clue
1,user2,3,user2,plain
3,user2,4,user3,no
```
Note that known_hosts_clue can be `plain`, `hashed` or `no`.

```
# ssh-farm.py -N -d -f config-challenge1.csv -C creds-challenge1.csv -t trusts-challenge1.csv
[*] Global settings:
  [i] timezone (-t): Etc/UTC
  [i] ssh_port (-P): 22
  [i] container_prefix (-n): ssh_farm_
  [i] docker_image (-i): linuxserver/openssh-server:version-9.3_p2-r0
  [i] no_clean_up (-N): True
  [i] working_directory: /tmp/ssh_farm_vhuf_sul

[*] Deleting old ssh_farm containers (-d)
  [-] Deleting container: ssh_farm_5
  [-] Deleting container: ssh_farm_4
  [-] Deleting container: ssh_farm_3
  [-] Deleting container: ssh_farm_2
  [-] Deleting container: ssh_farm_1

[+] No base sshd_config supplied (-c).  Getting sshd_config from docker container.  Use -o to save to file.
  [+] Starting container: ssh_farm_base
  [-] Deleting container: ssh_farm_base
  [+] Got sshd_config from docker container 117 lines

[+] Reading farm config: config-challenge1.csv
  [+] Created 5 container objects

[+] Reading trusts config: trusts-challenge1.csv
  [+] Creating user/credential objects on container ssh_farm_1: user2, None, None
  [+] Creating user/credential objects on container ssh_farm_3: user2, None, None
  [+] Creating user/credential objects on container ssh_farm_3: user2, None, None
  [+] Creating user/credential objects on container ssh_farm_4: user3, None, None

[+] Reading creds config: creds-challenge1.csv
  [+] Creating user/credential objects on container ssh_farm_1: user0, password, None
  [+] Creating user/credential objects on container ssh_farm_1: user1, Password1, None
  [+] Creating user/credential objects on container ssh_farm_2: user1, Password1, None
  [+] Creating user/credential objects on container ssh_farm_1: user2, Password, None
  [+] Creating user/credential objects on container ssh_farm_5: user3, user3, None

[+] Creating problem containers (-x)
  [+] No problems defined for ssh_farm_1
  [+] No problems defined for ssh_farm_2
  [+] No problems defined for ssh_farm_3
  [+] No problems defined for ssh_farm_4
  [+] No problems defined for ssh_farm_5

[+] Starting containers
  [+] Starting container: ssh_farm_1
  [+] Starting container: ssh_farm_2
  [+] Starting container: ssh_farm_3
  [+] Starting container: ssh_farm_4
  [+] Starting container: ssh_farm_5

[+] Configuring SSH Key Trusts
  [D] Created public key on ssh_farm_3: -rw------- 1 user2 user2 560 Aug  2 15:10 /home/user2/.ssh/authorized_keys
  [D] Created private key on ssh_farm_1: -rw------- 1 user2 user2 2590 Aug  2 15:10 /home/user2/.ssh/id_rsa
  [D] Added ssh_farm_3 (172.17.0.4) to ssh_farm_1 ~user2/.ssh/known_hosts
  [D] Created public key on ssh_farm_4: -rw------- 1 user3 user3 560 Aug  2 15:10 /home/user3/.ssh/authorized_keys
  [D] Created private key on ssh_farm_3: -rw------- 1 user2 user2 2590 Aug  2 15:10 /home/user2/.ssh/id_rsa

[+] Containers in /etc/hosts format (copy saved in: /tmp/ssh_farm_vhuf_sul/hosts)
172.17.0.2	ssh_farm_1
172.17.0.3	ssh_farm_2
172.17.0.4	ssh_farm_3
172.17.0.5	ssh_farm_4
172.17.0.6	ssh_farm_5

[+] Container IPs (copy saved in: /tmp/ssh_farm_vhuf_sul/ips.txt)
172.17.0.2
172.17.0.3
172.17.0.4
172.17.0.5
172.17.0.6

[+] Clear known_hosts
ssh-keygen -R 172.17.0.2
ssh-keygen -R 172.17.0.3
ssh-keygen -R 172.17.0.4
ssh-keygen -R 172.17.0.5
ssh-keygen -R 172.17.0.6

[*] Saving config to: /tmp/ssh_farm_vhuf_sul/ssh_farm.json (disable with -N)

[*] Skipping clean up of working directory (-N): /tmp/ssh_farm_vhuf_sul
```

Start the challenge:
```
ssh user0@172.17.0.2 # ssh_farm_1: password is user0
```

This simple challenge covers familiar concepts such as:
* Guessing passwords (e.g. with medusa)
* Predicting that usernames are likely to be
* Reuse of user:pass combos on other hosts
* Cracking passwords from /etc/shadow (different hash formats used)
* Use private SSH keys to access other hosts when guided by known_hosts
* Unguided use of private SSH keys (against other usernames)

There are a few other concepts that could easily be added to this challenge:
* scan for SSH servers on non-default ports
* connect to problem SSH services (e.g. those using old ciphers - see above)
* reuse of pass on different accounts

A few ideas that haven't been implemented by ssh_farm:
* Use of shosts.
* Exposing passwords in files other than /etc/shadow?  
* Allowing non-trivial abuse of sudo to get root / read the shadow file.
* Requiring users to pivot by restricting source IPs that can log in to some SSH servers

# Risks and Limitations

I only tested this on Linux (specifically on Kali).

The code seemed to work well when I tested it, but the configuration process is fairly complicated and prone to race conditions.  Expect some bugs / untested option combinations.

If you want to test a problematic setting that isn't supported by the [openssh-server docker image I'm using](https://hub.docker.com/r/linuxserver/openssh-server) (like something specific to DropBear or something OpenSSH no longer supports), ssh_farm will need to be modified.  Start by finding a docker image that supports the setting of interest.

The -d option deletes all docker images named ssh_farm_*.  Hopefully that doesn't go wrong or clash with the name of an important container already running on your system.

It would be pretty easy to start a huge number of docker containers using this script - and there's no limit or sanity check.  This could use up all the resources on your system and cause it to crash.  So be careful.

You'll probably find that it's possible to use older version of OpenSSH from https://hub.docker.com/r/linuxserver/openssh-server/tags.  However, as you try older and older versions, eventually the name of the daemon changes from `sshd.pam` to `sshd`s, which will break ssh_farm.  Pull request appreciated.  The oldest tag is from 2019 for OpenSSH 8.1.  The current version (as of July 2023) is OpenSSH 9.3.

Be cautious about blindly accepting hacker challenge CSV files from someone else.  This code has to run as root and there is plenty of scope for accidental command injection vulnerabilities as data from the CSV files is passed through to OS commands.  Also DoS risks.  At least eyeball CSV files sent to you by other people. 

# Credits and Dependencies

ssh_farm uses the openssh-server docker image from linuxserver.io: https://hub.docker.com/r/linuxserver/openssh-server

Docker will need to be installed and running on your system.
