# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2023 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# A note on security
# ==================
# This script crafts a lot of docker commands that are run as root.  User input is used to craft these commands (from CSV files).
# The risk of command injection is (hopefully) mitigated by input sanitisation.  However, mistakes do happen.
# So please be careful running config files from untrusted sources.

import sys
import re
import subprocess
import argparse
import csv
import tempfile as tmpfile
import time
from argparse import RawTextHelpFormatter
import json
import copy
import struct
import socket
import os
import textwrap
import random
import string

global_defaults = {}
global_defaults['timezone'] = "Etc/UTC"
global_defaults['ssh_port'] = "22"
global_defaults['working_directory'] = None
global_defaults['no_clean_up'] = False # Clean up tmp files by default
global_defaults['container_prefix'] = "ssh_farm_"
global_defaults['docker_image'] = "linuxserver/openssh-server:version-9.3_p2-r0"  # Use specific version known to work with ssh_farm settings
# global_defaults['docker_image'] = "linuxserver/openssh-server:latest" # "latest" might work if it's compatible with settings used by ssh_farm
# global_defaults['docker_image'] = "linuxserver/openssh-server:amd64-8.1_p1-r0-ls1" # older versions have use sshd instead of sshd.pam.  ssh_farm needs updating to work with old versions.

# ===========
# SSH Ciphers
# ===========
#
# List supported ciphers: ssh -Q cipher
#
ssh_ciphers_supported = []
ssh_ciphers_supported.append("3des-cbc")
ssh_ciphers_supported.append("aes128-cbc")
ssh_ciphers_supported.append("aes192-cbc")
ssh_ciphers_supported.append("aes256-cbc")
ssh_ciphers_supported.append("aes128-ctr")
ssh_ciphers_supported.append("aes192-ctr")
ssh_ciphers_supported.append("aes256-ctr")
ssh_ciphers_supported.append("aes128-gcm@openssh.com")
ssh_ciphers_supported.append("aes256-gcm@openssh.com")
ssh_ciphers_supported.append("chacha20-poly1305@openssh.com")
#
# Defaults for SSH client: man ssh_config
#
ssh_ciphers_default = []
ssh_ciphers_default.append("chacha20-poly1305@openssh.com")
ssh_ciphers_default.append("aes128-ctr")
ssh_ciphers_default.append("aes192-ctr")
ssh_ciphers_default.append("aes256-ctr")
ssh_ciphers_default.append("aes128-gcm@openssh.com")
ssh_ciphers_default.append("aes256-gcm@openssh.com")
#
# Ciphers that modern SSH clients may struggle to connect with:
#
problem_ciphers = []
problem_ciphers.append("3des-cbc")
problem_ciphers.append("aes128-cbc")
problem_ciphers.append("aes192-cbc")
problem_ciphers.append("aes256-cbc")
# arcfour < not supported
# blowfish-cbc < not supported
# cast128-cbc < not supported
# rijndael-cbc@lysator.liu.se < not supported

# =======================
# SSH Host Key Alogrithms
# =======================
#
# List supported host key algorithms: ssh -Q HostKeyAlgorithms
#
ssh_host_key_algorithms_supported = []
ssh_host_key_algorithms_supported.append("ssh-ed25519")
ssh_host_key_algorithms_supported.append("ssh-ed25519-cert-v01@openssh.com")
ssh_host_key_algorithms_supported.append("sk-ssh-ed25519@openssh.com")
ssh_host_key_algorithms_supported.append("sk-ssh-ed25519-cert-v01@openssh.com")
ssh_host_key_algorithms_supported.append("ecdsa-sha2-nistp256")
ssh_host_key_algorithms_supported.append("ecdsa-sha2-nistp256-cert-v01@openssh.com")
ssh_host_key_algorithms_supported.append("ecdsa-sha2-nistp384")
ssh_host_key_algorithms_supported.append("ecdsa-sha2-nistp384-cert-v01@openssh.com")
ssh_host_key_algorithms_supported.append("ecdsa-sha2-nistp521")
ssh_host_key_algorithms_supported.append("ecdsa-sha2-nistp521-cert-v01@openssh.com")
ssh_host_key_algorithms_supported.append("sk-ecdsa-sha2-nistp256@openssh.com")
ssh_host_key_algorithms_supported.append("sk-ecdsa-sha2-nistp256-cert-v01@openssh.com")
ssh_host_key_algorithms_supported.append("webauthn-sk-ecdsa-sha2-nistp256@openssh.com")
ssh_host_key_algorithms_supported.append("ssh-dss")
ssh_host_key_algorithms_supported.append("ssh-dss-cert-v01@openssh.com")
ssh_host_key_algorithms_supported.append("ssh-rsa")
ssh_host_key_algorithms_supported.append("ssh-rsa-cert-v01@openssh.com")
ssh_host_key_algorithms_supported.append("rsa-sha2-256")
ssh_host_key_algorithms_supported.append("rsa-sha2-256-cert-v01@openssh.com")
ssh_host_key_algorithms_supported.append("rsa-sha2-512")
ssh_host_key_algorithms_supported.append("rsa-sha2-512-cert-v01@openssh.com")
#
# List defaults: man ssh_config
#
ssh_host_key_algorithms_default = []
ssh_host_key_algorithms_default.append("ssh-ed25519-cert-v01@openssh.com")
ssh_host_key_algorithms_default.append("ecdsa-sha2-nistp256-cert-v01@openssh.com")
ssh_host_key_algorithms_default.append("ecdsa-sha2-nistp384-cert-v01@openssh.com")
ssh_host_key_algorithms_default.append("ecdsa-sha2-nistp521-cert-v01@openssh.com")
ssh_host_key_algorithms_default.append("sk-ssh-ed25519-cert-v01@openssh.com")
ssh_host_key_algorithms_default.append("sk-ecdsa-sha2-nistp256-cert-v01@openssh.com")
ssh_host_key_algorithms_default.append("rsa-sha2-512-cert-v01@openssh.com")
ssh_host_key_algorithms_default.append("rsa-sha2-256-cert-v01@openssh.com")
ssh_host_key_algorithms_default.append("ssh-ed25519")
#
# Host Key Algorithms that modern SSH clients may struggle to connect with.  Modify this list to test client compatibility:
#
problem_host_key_algorithms = []
problem_host_key_algorithms.append("ssh-dss") # Note: ssh_farm modifies containers to support ssh-dss (e.g. create DSA key).  This is not ssh-dss supported by default.
problem_host_key_algorithms.append("ssh-rsa")

# ==================
# SSH Kex Algorithms
# ==================
#
# List supported kex algorithms: ssh -Q KexAlgorithms
#
ssh_kex_algorithms_supported = []
ssh_kex_algorithms_supported.append("diffie-hellman-group1-sha1")
ssh_kex_algorithms_supported.append("diffie-hellman-group14-sha1")
ssh_kex_algorithms_supported.append("diffie-hellman-group14-sha256")
ssh_kex_algorithms_supported.append("diffie-hellman-group16-sha512")
ssh_kex_algorithms_supported.append("diffie-hellman-group18-sha512")
ssh_kex_algorithms_supported.append("diffie-hellman-group-exchange-sha1")
ssh_kex_algorithms_supported.append("diffie-hellman-group-exchange-sha256")
ssh_kex_algorithms_supported.append("ecdh-sha2-nistp256")
ssh_kex_algorithms_supported.append("ecdh-sha2-nistp384")
ssh_kex_algorithms_supported.append("ecdh-sha2-nistp521")
ssh_kex_algorithms_supported.append("curve25519-sha256")
ssh_kex_algorithms_supported.append("curve25519-sha256@libssh.org")
ssh_kex_algorithms_supported.append("sntrup761x25519-sha512@openssh.com")
#
# SSH Kex Algorithms that modern SSH clients may struggle to connect with.  Modify this list to test client compatibility:
#
problem_kex_algorithms = []
problem_kex_algorithms.append("diffie-hellman-group14-sha1")
problem_kex_algorithms.append("diffie-hellman-group1-sha1")
problem_kex_algorithms.append("diffie-hellman-group-exchange-sha1")
# gss-group1-sha1-* < not supported.  Also see RFC4462
# kexguess2@matt.ucc.asn.au < not supported.  Dropbear only?


class SshKey(object):
    def __init__(self, ssh_key_type="rsa"):
        if ssh_key_type not in ["dsa", "ecdsa", "ecdsa-sk", "ed25519", "ed25519-sk", "rsa"]:
            print(f"[E] Invalid ssh_key_type: {ssh_key_type}")
            sys.exit(1)
        self.key_type = ssh_key_type

        # create tmp directory for keys
        key_filename = tmpfile.mktemp(dir=global_defaults['working_directory'])

        # generate ssh_key
        cmd = f"ssh-keygen -t {self.key_type} -f {key_filename} -N ''"
        result = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()

        # check for errors
        if len(result) == 0:
            print(f"[E] Could not generate ssh_key")
            sys.exit(1)

        # read private key
        with open(key_filename, 'r') as key_file:
            self.private_key = key_file.read()

        # read public key
        with open(f"{key_filename}.pub", 'r') as key_file:
            self.public_key = key_file.read()

    def as_json(self):
        return json.dumps(self.as_dict(), indent=4)

    def as_dict(self):
        return {"ssh_key": {"key_type": self.key_type, "private_key": self.private_key, "public_key": self.public_key}}

class SshKeyTrust(object):
    def __init__(self, src_container, dst_container, src_user, dst_user, known_hosts_clue):
        self.src_container_obj = None
        self.dst_container_obj = None
        self.src_container = src_container
        self.dst_container = dst_container
        self.src_user = src_user
        self.dst_user = dst_user
        if known_hosts_clue not in ["plain", "hashed", "no"]:
            print(f"[E] Invalid known_hosts_clue: {known_hosts_clue}.  Must be: plain, hashed, or no")
            sys.exit(1)
        self.known_hosts_clue = known_hosts_clue
        self.ssh_key = SshKey()

    def as_json(self):
        return json.dumps(self.as_dict(), indent=4)

    def as_dict(self):
        return {"ssh_key_trust": {"src_container": self.src_container, "dst_container": self.dst_container, "src_user": self.src_user, "dst_user": self.dst_user, "known_hosts_clue": self.known_hosts_clue, "ssh_key": self.ssh_key.as_dict()}}

    def __eq__(self, other):
        return self.src_container == other.src_container and self.dst_container == other.dst_container and self.src_user == other.src_user and self.dst_user == other.dst_user

class Config(object):
    def __init__(self, indent=2):
        self.trusts = []
        self.containers = []
        self.credentials = []
        self.problems = ""
        self.problem_list = []
        self.sshd_base_config = None
        self.space = " " * indent

    def delete_old_ssh_farm_containers(self, quiet=False):
        container_ids = []
        # find all containers named ssh_farm_*
        cmd = f"docker ps -a --filter name={global_defaults['container_prefix']}* --format '{{{{.Names}}}}'" # TODO this is an independent prefix.  Should be coupled to prefix in container class
        result = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
        container_ids = result.split("\n")
        # remove empty strings
        container_ids = list(filter(None, container_ids))

        print()
        print("[*] Deleting old ssh_farm containers (-d)")
        for container_id in container_ids:
            # check that container_ids only contain letters, numbers, and underscores
            if not re.match("^[a-zA-Z0-9_-]+$", container_id):
                print(f"[E] Invalid container_id: {container_id}")
                sys.exit(1)

            if not quiet:
                print(f"{self.space}[-] Deleting container: {container_id}")

            # check container_id is valid
            if container_id is None or len(container_id) == 0:
                print(f"[E] Invalid container_id: {container_id}")
                sys.exit(1)
            cmd = f"docker rm -f {container_id}"
            result = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
            # check for errors
            if result != container_id:
                print(f"[E] Could not remove container: {container_id}")
                print(result)
                sys.exit(1)

        return container_ids

    # Set the base sshd_config that is usd for all containers
    def set_sshd_base_config(self, sshd_config):
        self.sshd_base_config = sshd_config

    # Get the configured base_sshd_config (which can be None)
    def get_sshd_base_config(self):
        return self.sshd_base_config

    # start a docker container and read the sshd_config from it
    def get_docker_sshd_base_config(self):
        print("")
        print("[+] No base sshd_config supplied (-c).  Getting sshd_config from docker container.  Use -o to save to file.")
        container = self.create_container(container_user_id="base", is_base_container=True)
        container.start()
        container.wait_for_sshd()
        sshd_config = container.get_docker_sshd_config()
        self.delete_container(container)
        print(f"{self.space}[+] Got sshd_config from docker container {len(sshd_config.splitlines())} lines")
        return sshd_config

    def get_container(self, container_user_id=None, container_id=None, container_name=None):
        # count how may ids passed are not none
        count = 0
        if container_user_id:
            count += 1
        if container_id:
            count += 1
        if container_name:
            count += 1

        # check exactly one id was passed
        if count != 1:
            print(f"[E] get_container should be passed exactly one type of ID: {container_user_id=} {container_id=} {container_name=}")
            sys.exit(1)

        if container_user_id:
            for container in self.containers:
                if container_user_id == container.container_user_id and container.is_base_container:
                    return container
        elif container_id:
            for container in self.containers:
                if container_id == container.container_id:
                    return container
        elif container_name:
            for container in self.containers:
                if container_name == container.container_name:
                    return container
        return None

    def create_container(self, **kwargs):
        # check if problems are set in kwargs and use defaults if not
        if "problems" not in kwargs:
            kwargs["problems"] = self.problems
            kwargs["problem_list"] = self.problem_list

        # check if sshd_config is set in kwargs and use defaults if not
        if "sshd_config" not in kwargs:
            kwargs["sshd_config"] = self.sshd_base_config

        # create container object (this doesn't start the container)
        new_container = Container(**kwargs)
        for container in self.containers:
            if new_container.container_user_id == container.container_user_id:
                print(f"[E] Container already exists: {container.container_user_id}.  Did you define the same container twice in the csv file?")
                raise ValueError
        self.containers.append(new_container)
        return new_container

    def delete_container(self, container):
        if container not in self.containers:
            print(f"[E] Container not found: {container}")
            sys.exit(1)

        # remove from list
        self.containers.remove(container)

        # delete
        container.delete()

    def add_trust(self, **kwargs):
        trust = SshKeyTrust(**kwargs)

        if trust not in self.trusts:
            trust.src_container_obj = self.get_container(container_user_id=trust.src_container)
            if not trust.src_container_obj:
                trust.src_container_obj = self.create_container(container_user_id=trust.src_container, is_base_container=True)

            trust.dst_container_obj = self.get_container(container_user_id=trust.dst_container)
            if not trust.dst_container_obj:
                trust.dst_container_obj = self.create_container(container_user_id=trust.dst_container, is_base_container=True)

            if not trust.src_container_obj.has_user(trust.src_user):
                trust.src_container_obj.add_user(trust.src_user)

            if not trust.dst_container_obj.has_user(trust.dst_user):
                trust.dst_container_obj.add_user(trust.dst_user)

            self.trusts.append(trust)

    def add_credential(self, *args):
        credential = Credential(*args)
        if credential not in self.credentials:
            self.credentials.append(credential)

    def set_problems(self, problems):
        if problems:
            self.problems = problems
            self.problem_list = problems.split(",")

            # check problems are valid
            for problem in self.problem_list:
                if problem not in ["ciphers", "hostkey", "kex"]:
                    print(f"[E] Invalid problem: {problem}")
                    sys.exit(1)

    def as_json(self):
        return json.dumps(self.as_dict(), indent=4)

    def as_dict(self):
        return {"config": {"trusts": [t.as_dict() for t in self.trusts], "containers": [c.as_dict() for c in self.containers], "credentials": [c.as_dict() for c in self.credentials], "problems": self.problems, "problem_list": self.problem_list}}

    def start_containers(self):
        print()
        print(f"[+] Starting containers")
        for container in self.containers:
            container.start()

        # Need the containers and user accounts to be set up before we configure SSH key trusts

        print()
        print(f"[+] Configuring SSH Key Trusts")
        for trust in self.trusts:
            #print(f"[D] processing trust: {trust.as_json()}")
            #print(f"[D] src_container_obj: {trust.src_container_obj}")
            #print(f"[D] dst_container_obj: {trust.dst_container_obj}")
            # Add id_rsa.pub to authorized_keys on dst container
            trust.dst_container_obj.add_ssh_authorized_key(trust.dst_user, trust.ssh_key)

            # Add id_rsa to src container # TODO this should be optional in the general case
            trust.src_container_obj.add_ssh_private_key(trust.src_user, trust.ssh_key)

            # Add known_hosts entry to src container
            if trust.known_hosts_clue:
                if trust.known_hosts_clue == "hashed":
                    trust.src_container_obj.add_ssh_known_host(dst_container=trust.dst_container_obj, src_user=trust.src_user, hashed=True)
                elif trust.known_hosts_clue == "plain":
                    trust.src_container_obj.add_ssh_known_host(dst_container=trust.dst_container_obj, src_user=trust.src_user, hashed=False)
                elif trust.known_hosts_clue == "no":
                    pass
                else:
                    print(f"[E] Invalid known_hosts clue: {trust.known_hosts_clue}")
                    sys.exit(1)

    def create_problem_container_objects(self):
        print()
        print(f"[+] Creating problem containers (-x)")
        for container in self.containers:
            if not container.is_base_container:
                continue
            # check if container has problems

            if not container.problem_list:
                print(f"  [+] No problems defined for {container.container_name}")
                continue

            print(f"  [+] Creating problem containers for {container.container_name}: {container.problem_list}")
            for problem in container.problem_list:

                if problem == "ciphers":
                    for cipher in problem_ciphers:
                        problem_container = container.clone()
                        problem_container.is_base_container = False
                        problem_container.container_name = f"{container.container_name}_c_{cipher}"
                        problem_container.modify_sshd_config(option_name="Ciphers", option_value=cipher)
                        self.containers.append(problem_container)
                        print(f"  [i] Created container object: {problem_container.container_name}")

                if problem == "kex":
                    for kex in problem_kex_algorithms:
                        problem_container = container.clone()
                        problem_container.is_base_container = False
                        problem_container.container_name = f"{container.container_name}_k_{kex}"
                        problem_container.modify_sshd_config(option_name="KexAlgorithms", option_value=kex)
                        self.containers.append(problem_container)
                        print(f"  [i] Created container object: {problem_container.container_name}")

                if problem == "hostkey":
                    for hostkey in problem_host_key_algorithms:
                        problem_container = container.clone()
                        problem_container.is_base_container = False
                        problem_container.container_name = f"{container.container_name}_h_{hostkey}"
                        problem_container.modify_sshd_config(option_name="HostKeyAlgorithms", option_value=hostkey)
                        if hostkey == "ssh-dss":
                            problem_container.modify_sshd_config(option_name="HostKey", option_value="/etc/ssh/ssh_host_dsa_key")
                        self.containers.append(problem_container)
                        print(f"  [i] Created container object: {problem_container.container_name}")

    def print_container_ips(self):
        path = os.path.join(global_defaults["working_directory"], "ips.txt")
        save_message = " (use -N to save a copy)"
        if global_defaults["no_clean_up"]:
            save_message = f" (copy saved in: {path})"
        print()
        print(f"[+] Container IPs{save_message}")
        # sort ip addresses then print
        with open(path, "w") as f:
            ips = [x.get_ip() for x in self.containers]
            ips.sort(key=lambda ip: struct.unpack("!L", socket.inet_aton(ip))[0])
            for ip in ips:
                line = f"{ip}\n"
                f.write(line)
                print(line, end="")

    def print_container_hosts_file(self):
        path = os.path.join(global_defaults["working_directory"], "hosts")
        save_message = " (use -N to save a copy)"
        if global_defaults["no_clean_up"]:
            save_message = f" (copy saved in: {path})"
        print()
        print(f"[+] Containers in /etc/hosts format{save_message}")
        with open(path, "w") as f:
            for container in self.containers:
                line = f"{container.get_ip()}\t{container.container_name}\n"
                f.write(line)
                print(line, end="")

    def print_clear_known_hosts(self):
        # output ssh-keygen -R commands
        print()
        print("[+] Clear known_hosts")
        for container in self.containers:
            print(f"ssh-keygen -R {container.get_ip()}")


class Credential(object):
    def __init__(self, password, hash_type=None):
        # check password only contains valid characters
        if not re.match(r"^[a-zA-Z0-9]+$", password):
            print(f"[E] Invalid password: {password} (only a-z, A-Z, 0-9 allowed)")
            sys.exit(1)
        self.password = password
        self.hash_type = None
        if hash_type:
            self.set_hash_type(hash_type)

    def as_json(self):
        return json.dumps(self.as_dict(), indent=4)

    def as_dict(self):
        return {"credential": {"password": self.password, "hash_type": self.hash_type}}

    def set_hash_type(self, hash_type):
        # set to MD5 if not set
        if hash_type is None or hash_type == "":
            hash_type = "MD5"

        # expect NONE DES MD5 SHA256 SHA512, but NONE is not supported by the linux host
        if hash_type not in ["DES", "MD5", "SHA256", "SHA512"]:
            print(f"[E] Invalid hash_type: {hash_type}")
            sys.exit(1)
        self.hash_type = hash_type


class User(object):
    def __init__(self, username, password=None, hash_type=None):
        # check username is valid
        if not re.match(r"^[a-z_][a-z0-9_-]*$", username):
            print(f"[E] Invalid username: {username}")
            sys.exit(1)
        self.username = username
        self.credential = None
        self.created = False # have we created it in the docker container?
        self.can_sudo = False # can this user sudo?  False / True / "NOPASSWD"
        if password:
            self.credential = Credential(password=password, hash_type=hash_type)

    def set_sudo_access(self, access):
        if access not in [False, True, "NOPASSWD"]:
            print(f"[E] Invalid sudo access: {access}")
            sys.exit(1)
        self.can_sudo = access

    def set_password(self, password):
        if not self.credential:
            self.credential = Credential(password=password)
        else:
            self.credential.password = password

    def set_hash_type(self, hash_type):
        if not self.credential:
            print(f"[E] Cannot set hash_type for user {self.username} without first setting a password")
            sys.exit(1)
        else:
            self.credential.hash_type = hash_type

    def as_json(self):
        return json.dumps(self.as_dict(), indent=4)

    def as_dict(self):
        return {"user": {"username": self.username, "credential": self.credential.as_dict() if self.credential else None}, "can_sudo": self.can_sudo, "created": self.created}

    def __str__(self):
        return self.as_json()

    def __eq__(self, other):
        if isinstance(other, User):
            return self.username == other.username
        return False

class Container(object):
    def __init__(self, container_user_id, container_prefix=None, container_suffix=None, ssh_port=None, sshd_config=None, is_base_container=None, docker_image=None, timezone=None, sudo_access=None, problems="", problem_list=[], indent=2):

        # set defaults
        self.ip = None
        self.problems = ""
        self.problem_list = []
        self.timezone = global_defaults['timezone']
        self.ssh_port = global_defaults['ssh_port']
        self.container_prefix = global_defaults['container_prefix']
        self.docker_image = global_defaults['docker_image'] # Use specific version known to work with ssh_farm settings
        self.is_base_container = False # True: relates to container specified in -c csv file; False: relates to a variation of a base container (-x)

        # set values
        if timezone:
            self.timezone = timezone

        if ssh_port:
            self.ssh_port = ssh_port

        if sudo_access:
            self.sudo_access = sudo_access

        if docker_image:
            self.docker_image = docker_image

        if container_prefix:
            self.container_prefix = container_prefix

        if is_base_container:
            self.is_base_container = is_base_container

        if problems:
            self.set_problems(problems)

        if problem_list:
            self.set_problem_list(problem_list)

        self.container_user_id = container_user_id # the ID the user used in the csv file
        self.container_id = None # assigned dy docker
        self.container_name = f"{self.container_prefix}{self.container_user_id}" # created by this script: either the user_id or the user_id with a suffix
        if container_suffix:
            self.container_name += f"_{container_suffix}"

        # check container_name only contains valid characters
        if not re.match(r'^[a-zA-Z0-9_\-]+$', self.container_name):
            print(f"[E] Invalid container name: {self.container_name}")
            sys.exit(1)
        self.sshd_config = sshd_config
        self.users = []
        self.space = " " * indent
        #print(f"{self.space}[D] Creating container object for {self.container_name}")

    def add_ssh_private_key(self, user: str, key: SshKey):
        # Write private key to a tmp file
        with tmpfile.NamedTemporaryFile(mode='w', delete=True) as f:
            f.write(key.private_key)
            f.flush()
            # Add the key to the container
            self.create_ssh_user_dir(user)
            cmd = f"docker cp {f.name} {self.container_name}:/home/{user}/.ssh/id_rsa"
            subprocess.check_output(cmd, shell=True)
            cmd = f"docker exec -i {self.container_name} bash -c 'chmod 600 ~{user}/.ssh/id_rsa'"
            subprocess.check_output(cmd, shell=True)
            self.fix_ssh_user_dir_owner(user)
            # ls the target file to check it exists
            cmd = f"docker exec -i {self.container_name} bash -c 'ls -l ~{user}/.ssh/id_rsa'"
            output = subprocess.check_output(cmd, shell=True)
            print(f"{self.space}[D] Created private key on {self.container_name}: {output.decode('utf-8').strip()}")

    def add_ssh_authorized_key(self, user: str, key: SshKey):
        # write public key to tmp file
        with tmpfile.NamedTemporaryFile(mode='w', delete=True) as f:
            f.write(key.public_key)
            f.flush()
            # Add the key to the container
            self.create_ssh_user_dir(user)
            cmd = f"docker cp {f.name} {self.container_name}:/home/{user}/.ssh/authorized_keys"
            subprocess.check_output(cmd, shell=True)
            cmd = f"docker exec -i {self.container_name} bash -c 'chmod 600 ~{user}/.ssh/authorized_keys'"
            subprocess.check_output(cmd, shell=True)
            self.fix_ssh_user_dir_owner(user)

            # ls the target file to check it exists
            cmd = f"docker exec -i {self.container_name} bash -c 'ls -l ~{user}/.ssh/authorized_keys'"
            output = subprocess.check_output(cmd, shell=True)
            print(f"{self.space}[D] Created public key on {self.container_name}: {output.decode('utf-8').strip()}")

    def create_ssh_user_dir(self, user: str):
        cmd = f"docker exec -i {self.container_name} bash -c 'mkdir -p ~{user}/.ssh && chmod 700 ~{user}/.ssh'"
        subprocess.check_output(cmd, shell=True)

    def fix_ssh_user_dir_owner(self, user: str):
        cmd = f"docker exec -i {self.container_name} bash -c 'chown -R {user}:{user} ~{user}/.ssh'"
        subprocess.check_output(cmd, shell=True)

    def add_ssh_known_host(self, dst_container, src_user: str, hashed: bool = True):
        self.create_ssh_user_dir(src_user)
        # use ssh-keyscan with or without -H to add known hosts to src docker container
        if hashed:
            cmd = f"docker exec -i {self.container_name} bash -c 'ssh-keyscan -H {dst_container.get_ip()} 2>&1 >> ~{src_user}/.ssh/known_hosts'"
        else:
            cmd = f"docker exec -i {self.container_name} bash -c 'ssh-keyscan {dst_container.get_ip()} 2>&1 >> ~{src_user}/.ssh/known_hosts'"

        subprocess.check_output(cmd, shell=True)
        self.fix_ssh_user_dir_owner(src_user)
        print(f"{self.space}[D] Added {dst_container.container_name} ({dst_container.get_ip()}) to {self.container_name} ~{src_user}/.ssh/known_hosts")

    def clone(self):
        # return a copy of this object
        return copy.deepcopy(self)

    def get_ip(self):
        if not self.ip:
            cmd = f"docker inspect -f '{{{{range.NetworkSettings.Networks}}}}{{{{.IPAddress}}}}{{{{end}}}}' {self.container_name}"
            result = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
            self.ip = result

        # check ip only contains valid characters
        if not re.match(r'^[0-9\.]+$', self.ip):
            print(f"[E] Invalid IP address: {self.ip}")
            sys.exit(1)
        return self.ip

    def set_problems(self, problem_str):
        self.problems = problem_str
        self.problem_list = problem_str.split(",")
        self.check_problem_list()

    def set_problem_list(self, problem_list):
        self.problem_list = problem_list
        self.check_problem_list()

    def check_problem_list(self):
        # check problems are valid
        for problem in self.problem_list:
            if problem not in ["ciphers", "hostkey", "kex"]:
                print(f"[E] Invalid problem: {problem}")
                sys.exit(1)

    def has_user(self, username):
        return username in self.users

    def add_user(self, user_str, password=None, hash_type=None):
        space = self.space
        print(f"{space}[+] Creating user/credential objects on container {self.container_name}: {user_str}, {password}, {hash_type}")
        user = None
        for u in self.users:
            if u.username == user_str:
                user = u
                break
        if not user:
            user = User(username=user_str)
            self.users.append(user)

        if password:
            user.set_password(password)
            if hash_type:
                user.set_hash_type(hash_type)

        return user

    def as_json(self):
        return json.dumps(self.as_dict(), indent=4)

    def as_dict(self):
        return {"container": {"container_user_id": self.container_user_id, "container_id": self.container_id, "container_name": self.container_name, "ssh_port": self.ssh_port, "sshd_config": self.sshd_config, "users": [u.as_dict() for u in self.users]}}

    def delete(self, quiet=False):
        if not quiet:
            print(f"{self.space}[-] Deleting container: {self.container_name}")

        # check container_id is valid
        if self.container_id is None or len(self.container_id) == 0:
            print(f"[E] Invalid container_id: {self.container_id}")
            sys.exit(1)

        # delete the container
        cmd = f"docker rm -f {self.container_name}"
        result = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()

        # check for errors
        if result != self.container_name:
            print(f"[E] Could not remove container: {self.container_name}.  Result: {result}")
            sys.exit(1)

    def get_docker_sshd_config(self):
        # use docker exec to cat the config and return it
        cmd = f"docker exec {self.container_name} cat /etc/ssh/sshd_config"
        result = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()

        # check for errors
        if len(result) == 0:
            print(f"[E] Could not get sshd_config for container {self.container_name}")
            sys.exit(1)
        return result

    def start(self, quiet=False, indent=2):
        space = " " * indent
        if not quiet:
            print(f"{space}[+] Starting container: {self.container_name}")

        # check if container is already running
        cmd = f"docker ps -a --filter name={self.container_name} --format '{{{{.Names}}}}'"
        result = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
        if result == self.container_name:
            print(f"{space}[E] Container with name {self.container_name} already running.  Rerun with -d to delete all containers.")
            sys.exit(1)

        # create docker env vars
        docker_env_vars = {}
        docker_env_vars["TZ"] = self.timezone
        docker_env_vars["PUID"] = 0

        # create docker command
        cmd_args = ["docker", "run", "-d", "--name", self.container_name]
        for key in docker_env_vars:
            cmd_args.append("-e")
            cmd_args.append(f"{key}={docker_env_vars[key]}")
        cmd_args.append(self.docker_image)

        # start container
        self.container_id = subprocess.check_output(cmd_args, shell=False).decode('utf-8').strip()

        # check for errors
        if len(self.container_id) == 0:
            print(f"[E] Could not start container: {self.container_name}")
            sys.exit(1)

        # copy sshd_config to container
        if self.sshd_config:
            # set port
            #print(f"{space}[D] Setting port for container: {self.container_name} to {self.ssh_port}")
            self.modify_sshd_config(option_name="Port", option_value=self.ssh_port)

            #print(f"  [D] Applying sshd_config to container: {self.container_name}")
            # write sshd_config to tmp file
            sshd_config_tmp_filename = tmpfile.mktemp(dir=global_defaults['working_directory'])
            with open(sshd_config_tmp_filename, 'w') as sshd_config_tmp_file:
                sshd_config_tmp_file.write(self.sshd_config)

            sshd_owner = self.wait_for_sshd()

            if sshd_owner is None:
                print(f"[E] Could not find owner of sshd.pam process in container {self.container_name}")
                sys.exit(1)

            # copy sshd_config to container
            cmd = f"docker cp {sshd_config_tmp_filename} {self.container_name}:/etc/ssh/sshd_config"
            #print(f"[D] {cmd}")
            result = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
            # check for errors
            if len(result) != 0:
                print(f"[E] Could not copy sshd_config to container: {self.container_name}")
                sys.exit(1)

            # Add ssh-dss support
            # ssh-dss will never work unless there's a dsa key in /etc/ssh/ and it has the correct permissions
            # Note: Additional steps are needed to enable ssh-dss support in the sshd_config file:
            #  HostKeyAlgorithms +ssh-dss
            #  PubkeyAcceptedKeyTypes +ssh-dss
            #  HostKey /etc/ssh/ssh_host_dsa_key

            # generate host key in dsa format (for ssh-dss): ssh-keygen -t dsa -f /etc/ssh/ssh_host_dsa_key
            cmd = f"docker exec {self.container_name} ssh-keygen -t dsa -f /etc/ssh/ssh_host_dsa_key -N ''"
            #print(f"[D] {cmd}")
            result = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
            # check for errors
            if len(result) == 0:
                print(f"[E] Could not generate ssh_host_dsa_key in container: {self.container_name}")
                sys.exit(1)

            cmd = f"docker exec {self.container_name} killall -HUP sshd.pam" # for image lscr.io/linuxserver/openssh-server:latest (OpenSSH_9.3)
            result = None
            retry = True
            retries = 0
            while retry:
                retry = False
                try:
                    result = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
                except subprocess.CalledProcessError as e:
                    if "status 1" in str(e):
                        retry = True
                        if retries > 5:
                            print(f"[E] Could not restart sshd.pam in container {self.container_name}: {e}")
                            sys.exit(1)
                        retries += 1
                        print(f" [-] Retrying killall -HUP...")
                        time.sleep(0.5)
                        continue
                    print("[E] Unknown error")
                    sys.exit(1)
            # check for errors
            if len(result) != 0:
                print(f"[E] Could not restart sshd.pam in container: {self.container_name}")
                sys.exit(1)

        # Configure users
        for user in self.users:

            # create user
            if not user.created:
                cmd = f"docker exec {self.container_name} useradd -m {user.username}"
                result = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()

                # check for errors
                if len(result) != 0:
                    print(f"[E] Could not create user {user.username} in container: {self.container_name}")
                    sys.exit(1)

                user.created = True

            # check if user needs a password set too
            password_hash = None
            password = None
            hash_type = None # MD5 by default
            if user.credential:
                password = user.credential.password
                hash_type = user.credential.hash_type
            else:
                # set a random password - it seems hard to not set a password on an unlocked account in linux...
                password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(20))

            if not hash_type: # NONE DES MD5 SHA256 SHA512
                hash_type = "MD5"
            cmd = f"docker exec {self.container_name} bash -c \"echo '{user.username}:{password}' | chpasswd -c {hash_type}\""
            result = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
            # check for errors
            if len(result) != 0:
                print(f"[E] Could not set password for user {user.username} in container: {self.container_name}")
                sys.exit(1)

            # check if user can sudo
            cmd = None
            if user.can_sudo == True:
                cmd = f"docker exec {self.container_name} bash -c \"echo {user.username} ALL=\(ALL\) ALL >> /etc/sudoers\""
            if user.can_sudo == "NOPASSWD":
                cmd = f"docker exec {self.container_name} bash -c \"echo {user.username} ALL=\(ALL\) ALL >> /etc/sudoers\""
            if cmd:
                result = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
                # check for errors
                if len(result) != 0:
                    print(f"[E] Could not add user {user.username} to sudo group in container: {self.container_name}")
                    sys.exit(1)

    def __eq__(self, other):
        if isinstance(other, Container):
            return self.container_name == other.container_name
        return False

    def wait_for_sshd(self):
        # Wait until sshd is running
        cmd = f"docker exec {self.container_name} ps auxn"
        result = None
        retry = True
        retries = 0
        while retry:
            retry = False
            try:
                result = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
                if not "/usr/sbin/sshd.pam" in result:  # TODO doesn't work for older daemon named "sshd"
                    raise Exception("sshd not running")
            except subprocess.CalledProcessError as e:
                if "status 1" in str(e):
                    retry = True
                    if retries > 5:
                        print(f"[E] Could not run ps auxn in container {self.container_name}: {e}")
                        return False
                    retries += 1
                    print(f" [-] Retrying ps auxn...")
                    time.sleep(0.5)
                    continue
                print("[E] Unknown error")
                sys.exit(1)
            except Exception as e:
                if "sshd not running" in str(e):
                    retry = True
                    if retries > 5:
                        print(f"[E] sshd not running after retrying in {self.container_name}: {e}")
                        return False
                    retries += 1
                    # print(f" [-] Waiting for sshd to start...")
                    time.sleep(0.5)
                    continue
                else:
                    print(f"[E] Unknown error: {e}")
                    sys.exit(1)

        # find owner of sshd.pam process from ps aux output
        sshd_owner = None
        for line in result.split("\n"):
            if "/usr/sbin/sshd.pam" in line:
                sshd_owner = line.split()[0]
                break

        return sshd_owner

    def modify_sshd_config(self, option_name, option_value):
        space = self.space + "  "
        # if key is present in sshd_config exactly once, replace it
        occurences = len(re.findall(f"^#?{option_name} ", self.sshd_config, re.MULTILINE))
        if occurences == 1:
            self.sshd_config = re.sub(f"^#?{option_name} .*", f"{option_name} {option_value}", self.sshd_config,
                                 flags=re.MULTILINE)
        elif occurences == 0 or occurences > 1:
            # append to file
            self.sshd_config += f"\n{option_name} {option_value}"
        else:
            print(f"[E] Unexpected number of occurences ({occurences}) of {option_name} in sshd_config: {self.sshd_config}.  Shouldn't happen.")
            sys.exit(1)

        return self.sshd_config


def print_global_defaults():
    print()
    print("[*] Global settings:")
    print(f"  [i] timezone (-t): {global_defaults['timezone']}")
    print(f"  [i] ssh_port (-P): {global_defaults['ssh_port']}")
    print(f"  [i] container_prefix (-n): {global_defaults['container_prefix']}")
    print(f"  [i] docker_image (-i): {global_defaults['docker_image']}")
    print(f"  [i] no_clean_up (-N): {global_defaults['no_clean_up']}")
    print(f"  [i] working_directory: {global_defaults['working_directory']}")

if __name__ == "__main__":
    config = Config()
    tmp_dir = None

    # parse command line arguments
    usage = "ssh-farm.py ( -f config.csv [ -d ] [ -C credentials.txt ] [ -t trusts.txt] [ -c sshd_config_base ] [ -w /path/to/a/writable/working/directory ] | -o sshd_config_base.txt )"
    epilog = """
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
    """
    epilog = textwrap.dedent(epilog)

    parser = argparse.ArgumentParser(description='Create lots of docker containers running sshd', usage=usage,
                                     epilog=epilog, formatter_class=RawTextHelpFormatter)

    # ssh-farm.py -f config.csv [ -c sshd_config_base ] [ -w /path/to/a/writable/working/directory ]
    parser.add_argument('-f', '--farmconfig', help='CSV file containing configuration', required=False)
    parser.add_argument('-c', '--sshdbaseconfig', help='sshd_config file to use as base', required=False)
    parser.add_argument('-d', '--delete', help='Delete all containers named ssh_farm_*', action='store_true',
                        required=False)
    parser.add_argument('-T', '--timezone', help=f'Timezone for containers.  Default is {global_defaults["timezone"]}',
                        required=False)
    parser.add_argument('-P', '--ssh_port', help=f'SSH port for containers.  Default is {global_defaults["ssh_port"]}',
                        required=False)
    parser.add_argument('-t', '--trusts',
                        help=f'CSV file containing SSH key trusts.  Columns: src_host,src_user,dst_host,dst_user,known_hosts_clue.  Default is none',
                        required=False)
    parser.add_argument('-N', '--no_clean_up', help=f'Do not cleanup tmp files.  Default is {global_defaults["no_clean_up"]}',
                        action='store_true',
                        required=False)
    parser.add_argument('-n', '--prefix', help=f'Prefix for docker container name.  Default is {global_defaults["container_prefix"]}',
                        required=False)
    parser.add_argument('-C', '--creds',
                        help=f'CSV file containing OS usernames and passwords.  Columns: ID,username,password,sudo. Default is none',
                        required=False)
    parser.add_argument('-x', '--problem',
                        help=f'Create extra sshd\'s that are harder to connect to.  List one or more of ciphers,kex,hostkey.  Default is none',
                        required=False)
    parser.add_argument('-i', '--docker_image',
                        help=f'Docker image to use for containers.  Default is {global_defaults["docker_image"]}',
                        required=False)

    # ssh-farm.py -o sshd_config_base.txt
    parser.add_argument('-o', '--outputsshdconfig', help='Output sshd_config from docker', required=False)
    args, extras = parser.parse_known_args()

    #
    # Check of illegal option combinations
    #

    # check for extra options
    if len(extras) > 0:
        print(f"[E] Unknown option(s): {extras}")
        print(usage)
        sys.exit(1)

    # expect -f or -o
    if not args.outputsshdconfig and not args.farmconfig:
        print("[E] Specify either -f or -o")
        print(usage)
        sys.exit(1)

    # check for illegal option combination -f and -o
    if args.farmconfig and args.outputsshdconfig:
        print("[E] Specify either -f or -o, but not both")
        print(usage)
        sys.exit(1)

    #
    # Process options
    #

    # process -o
    if args.outputsshdconfig:
        sshd_config = config.get_docker_sshd_base_config()
        # write config to file
        with open(args.outputsshdconfig, 'w') as sshd_config_file:
            sshd_config_file.write(sshd_config)
            print()
            print(f"[*] Base sshd_config file saved to {args.outputsshdconfig}")
            sys.exit(0)

    #
    # These options are in -f mode
    #

    tmp_dir_object = None
    if not args.outputsshdconfig:
        # check for -n
        if args.prefix:
            if len(args.prefix) > 20 or not re.match(r'^[a-zA-Z0-9_]+$', args.prefix):
                print(f"[E] Container prefix must be < 20 chars and only letters, numbers, and underscores.  You specified: {args.prefix}")
                sys.exit(1)
            global_defaults['container_prefix'] = args.prefix

        # check for -N
        tmp_dir_object = None
        if args.no_clean_up:
            global_defaults['no_clean_up'] = True
            global_defaults['working_directory'] = tmpfile.mkdtemp(prefix=global_defaults['container_prefix']) # does not get auto-deleted
        else:
            tmp_dir_object = tmpfile.TemporaryDirectory(prefix=global_defaults['container_prefix']) # will get auto-deleted
            global_defaults['working_directory'] = tmp_dir_object.name

        # check for -T
        if args.timezone:
            global_defaults['timezone'] = args.timezone

        # check for -P
        if args.ssh_port:
            global_defaults['ssh_port'] = args.ssh_port

        # check for -i
        if args.docker_image:
            global_defaults['docker_image'] = args.docker_image

        #
        # Need to add problems and sshd_config to config BEFORE creating container objects
        # Container object need to inherit these values
        #

        # check for -x
        if args.problem:
            config.set_problems(args.problem)

    # check for -d (need to do this before get_docker_sshd_base_config())
    if args.delete:
        print_global_defaults()
        config.delete_old_ssh_farm_containers()
    else:
        print(f"[W] -d option not used.  You normally want to use -d to delete old containers.  Expect errors when starting containers.")
        print_global_defaults()

    # check for -c (base sshd_config)
    sshd_config = None
    if args.sshdbaseconfig:
        sshd_config_filename = args.configfile
        with open(sshd_config_filename, 'r') as sshd_config_file:
            sshd_config = sshd_config_file.read()
    else:
        # get sshd_config from container
        sshd_config = config.get_docker_sshd_base_config()

    if sshd_config is None or len(sshd_config) == 0:
        print("[E] Could not get sshd_config from container or from -c (zero byte file?)")
        sys.exit(1)

    config.set_sshd_base_config(sshd_config)

    #
    # Create container objects (this doesn't start containers)
    #

    # check for -f config.csv
    # expected columns: ID
    # optional columns: any ssh config option like:
    #   PasswordAuthentication
    #   PermitRootLogin
    #   Port
    if args.farmconfig:
        # read in the farm config
        print()
        print(f"[+] Reading farm config: {args.farmconfig}")
        with open(args.farmconfig, 'r') as farm_config_file:
            # read into a dict
            reader = csv.DictReader(farm_config_file)

            # loop through each row
            row_number = 1
            for row in reader:
                row_number += 1

                # check column names and values only contain letters, numbers, and underscores
                for key in row:
                    if not re.match("^[a-zA-Z0-9_]*$", key):
                        print(f"[E] Invalid column name: {key} at row {row_number}")
                        sys.exit(1)
                    if not re.match("^[a-zA-Z0-9_]*$", row[key]):
                        print(f"[E] Invalid value: {row[key]} at row {row_number}")
                        sys.exit(1)

                # check for required columns
                if "ID" not in row:
                    print(f"[E] Missing ID column at row {row_number}")
                    sys.exit(1)

                container = config.create_container(container_user_id=row["ID"], is_base_container=True)

                # By default, allow password logins (user can override in csv file)
                container.modify_sshd_config(option_name="PasswordAuthentication", option_value="yes")

                # check for optional columns
                for key in row:
                    if key == "ID":
                        continue

                    option_name = key
                    option_value = row[key]

                    if key == "ssh_port" or key == "Port":
                        option_name = "Port"
                        container.ssh_port = option_value
                        # continue < we don't "continue" here because we need to process the option later

                    if key == "docker_image":
                        # Blank means default image will be used
                        if option_value != "":
                            container.docker_image = option_value
                        continue

                    if key == "timezone":
                        container.timezone = option_value
                        continue

                    if key == "sudo_access":
                        # convert string in csv to boolean
                        if option_value.lower() in ["true", "yes", "1"]:
                            option_value = "true"
                        elif option_value.lower() in ["false", "no", "0"]:
                            option_value = "false"
                        else:
                            print(f"[E] Invalid sudo_access value: {option_value} at row {row_number}")
                            sys.exit(1)
                        container.sudo_access = option_value
                        continue

                    # assume all other options are sshd_config options
                    container.modify_sshd_config(option_name=option_name, option_value=option_value)

    print(f"  [+] Created {len(config.containers)} container objects")

    # check for -t trusts.csv
    # expected columns: src_host,src_user,dst_host,dst_user,known_hosts_clue
    if args.trusts:
        # read in the trusts csv file
        print()
        print(f"[+] Reading trusts config: {args.trusts}")
        with open(args.trusts, 'r') as trusts_file:
            # read into a dict
            reader = csv.DictReader(trusts_file)

            # loop through each row
            row_number = 1
            for row in reader:
                row_number += 1

                # check column names and values only contain letters, numbers, and underscores
                for key in row:
                    if not re.match("^[a-zA-Z0-9_]*$", key):
                        print(f"[E] Invalid column name: {key} at row {row_number}")
                        sys.exit(1)
                    if not re.match("^[a-zA-Z0-9_]*$", row[key]):
                        print(f"[E] Invalid value: {row[key]} at row {row_number}")
                        sys.exit(1)

                # check for required columns
                if "src_host" not in row:
                    print(f"[E] Missing src_host column at row {row_number}")
                    sys.exit(1)
                if "src_user" not in row:
                    print(f"[E] Missing src_user column at row {row_number}")
                    sys.exit(1)
                if "dst_host" not in row:
                    print(f"[E] Missing dst_host column at row {row_number}")
                    sys.exit(1)
                if "dst_user" not in row:
                    print(f"[E] Missing dst_user column at row {row_number}")
                    sys.exit(1)
                if "known_hosts_clue" not in row:
                    print(f"[E] Missing known_hosts_clue column at row {row_number}")
                    sys.exit(1)

                config.add_trust(src_container=row["src_host"], src_user=row["src_user"], dst_container=row["dst_host"], dst_user=row["dst_user"], known_hosts_clue=row["known_hosts_clue"])

    # check for -C creds.csv
    # expected columns: ID,username,password,sudo
    if args.creds:
        # read in the creds csv file
        print()
        print(f"[+] Reading creds config: {args.creds}")
        with open(args.creds, 'r') as creds_file:
            # read into a dict
            reader = csv.DictReader(creds_file)

            # loop through each row
            row_number = 1
            for row in reader:
                row_number += 1

                # check column names and values only contain letters, numbers, and underscores
                for key in row:
                    if not re.match("^[a-zA-Z0-9_]*$", key):
                        print(f"[E] Invalid column name: {key} at row {row_number}")
                        sys.exit(1)
                    if not re.match("^[a-zA-Z0-9_]*$", row[key]):
                        print(f"[E] Invalid value: {row[key]} at row {row_number}")
                        sys.exit(1)

                # check for required columns
                if "ID" not in row:
                    print(f"[E] Missing ID column at row {row_number}")
                    sys.exit(1)
                if "username" not in row:
                    print(f"[E] Missing username column at row {row_number}")
                    sys.exit(1)
                if "password" not in row:
                    print(f"[E] Missing password column at row {row_number}")
                    sys.exit(1)

                container = config.get_container(container_user_id=row["ID"])
                if not container:
                    container = config.create_container(container_user_id=row["ID"])
                user = container.add_user(row["username"], password=row["password"])

                if "hash_type" in row:
                    user.credential.set_hash_type(row["hash_type"])

                if "sudo" in row:
                    access = row["sudo"]
                    if access.lower() in ["true", "yes", "1"]:
                        access = True
                    elif access.lower() in ["false", "no", "0"]:
                        access = False
                    elif access.lower() in ["nopasswd"]:
                        access = "NOPASSWD"

                    #print(f"[D] Setting sudo access to {access} for user: {user.username} in container: {container.container_name}")
                    user.set_sudo_access(access)

    # Create problem variations of base containers
    config.create_problem_container_objects()

    # Start containers according to the config in the container objects
    config.start_containers()

    # Print a summary of the hosts created
    config.print_container_hosts_file()
    config.print_container_ips()
    config.print_clear_known_hosts()

    # if no_clean_up save json config
    if global_defaults['no_clean_up']:
        path = os.path.join(global_defaults['working_directory'], "ssh_farm.json")
        print()
        print(f"[*] Saving config to: {path} (disable with -N)")
        with open(path, 'w') as json_file:
            json.dump(config.as_dict(), json_file, indent=4)

    print()
    if global_defaults['no_clean_up']:
        print(f"[*] Skipping clean up of working directory (-N): {global_defaults['working_directory']}")
    else:
        # Clean up
        print(f"[-] Cleaning up working directory (-N to disable): {global_defaults['working_directory']}")
        tmp_dir_object.cleanup()
