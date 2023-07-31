# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
# 
#   http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.  

import sys
import re
import subprocess
import argparse
import csv
import tempfile as tmpfile
import time
from argparse import RawTextHelpFormatter
import json

global_defaults = {}
global_defaults['timezone'] = "Etc/UTC"
global_defaults['ssh_port'] = "22"
global_defaults['sudo_access'] = "true"
global_defaults['password_access'] = "true"
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


class Config(object):
    def __init__(self):
        self.trusts = []
        self.containers = []
        self.credentials = []
        self.problems = ""
        self.problem_list = []
        self.sshd_base_config = None

    def delete_old_ssh_farm_containers(self, quiet=False):
        container_ids = []
        # find all containers named ssh_farm_*
        cmd = f"docker ps -a --filter name={global_defaults['container_prefix']}* --format '{{{{.Names}}}}'" # TODO this is an independent prefix.  Should be coupled to prefix in container class
        result = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
        container_ids = result.split("\n")
        # remove empty strings
        container_ids = list(filter(None, container_ids))

        for container_id in container_ids:
            if not quiet:
                print(f"[-] Deleting container: {container_id}")

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
        print("[+] Getting sshd_config from docker container")
        container = self.create_container(container_user_id="base", is_base_container=True)
        container.start()
        container.wait_for_sshd()
        sshd_config = container.get_docker_sshd_config()
        self.delete_container(container)
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

    def print_container_ips(self):
        for container in self.containers:
            print(f"{container.container_name}: {container.get_ip()}")

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
            src_container = self.get_container(container_user_id=trust.src_container)
            if not src_container:
                src_container = self.create_container(container_user_id=trust.src_container, is_base_container=True)

            dst_container = self.get_container(container_user_id=trust.dst_container)
            if not dst_container:
                dst_container = self.create_container(container_user_id=trust.dst_container, is_base_container=True)

            if not src_container.has_user(trust.src_user):
                src_container.add_user(trust.src_user)

            if not dst_container.has_user(trust.dst_user):
                dst_container.add_user(trust.dst_user)

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
        for container in self.containers:
            container.start()

    def create_problem_containers(self):
        for container in self.containers:
            # check if container has problems
            for problem in container.problem_list:
                if problem == "ciphers":
                    for cipher in problem_ciphers:
                        problem_container = container.clone()
                        problem_container.is_base_container = False
                        problem_container.container_name = f"{container.container_name}_c_{cipher}"
                        problem_container.modify_sshd_config(option_name="Ciphers", option_value=cipher)
                        self.containers.append(problem_container)

                if problem == "kex":
                    for kex in problem_kex_algorithms:
                        problem_container = container.clone()
                        problem_container.is_base_container = False
                        problem_container.container_name = f"{container.container_name}_k_{kex}"
                        problem_container.modify_sshd_config(option_name="KexAlgorithms", option_value=kex)
                        self.containers.append(problem_container)

                if problem == "hostkey":
                    for hostkey in problem_host_key_algorithms:
                        problem_container = container.clone()
                        problem_container.is_base_container = False
                        problem_container.container_name = f"{container.container_name}_h_{hostkey}"
                        problem_container.modify_sshd_config(option_name="HostKeyAlgorithms", option_value=hostkey)
                        if hostkey == "ssh-dss":
                            problem_container.modify_sshd_config(option_name="HostKey", option_value="/etc/ssh/ssh_host_dsa_key")
                        self.containers.append(problem_container)


class Credential(object):
    def __init__(self, password, hash_type=None):
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
    def __init__(self, container_user_id, container_prefix=None, container_suffix=None, ssh_port=None, sshd_config=None, is_base_container=None, docker_image=None, timezone=None, sudo_access=None, password_access=None, problems="", problem_list=[]):

        # set defaults
        self.ip = None
        self.problems = ""
        self.problem_list = []
        self.timezone = global_defaults['timezone']
        self.ssh_port = global_defaults['ssh_port']
        self.sudo_access = global_defaults['sudo_access']
        self.password_access = global_defaults['password_access']
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

        if password_access:
            self.password_access = password_access

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
        self.sshd_config = sshd_config
        self.users = []
        print(f"[D] Creating container object for {self.container_name}")

    def get_ip(self):
        if not self.ip:
            cmd = f"docker inspect -f '{{{{range.NetworkSettings.Networks}}}}{{{{.IPAddress}}}}{{{{end}}}}' {self.container_name}"
            result = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
            self.ip = result
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
        print(f"[D] Creating user/credential objects on container {self.container_name}: {user_str}, {password}, {hash_type}")
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
            print(f"[-] Deleting container: {self.container_id}")

        # check container_id is valid
        if self.container_id is None or len(self.container_id) == 0:
            print(f"[E] Invalid container_id: {self.container_id}")
            sys.exit(1)

        # delete the container
        cmd = f"docker rm -f {self.container_id}"
        result = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()

        # check for errors
        if result != self.container_id:
            print(f"[E] Could not remove container: {self.container_id}")
            print(result)
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

    def delete(self, quiet=False):
        if not quiet:
            print(f"[-] Deleting container: {self.container_name}")

        # delete the container
        cmd = f"docker rm -f {self.container_name}"
        result = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()

        # check for errors
        if result != self.container_name:
            print(f"[E] Could not remove container: {self.container_name}.  Reult: {result}")
            sys.exit(1)

    def start(self, quiet=False):
        if not quiet:
            print(f"[+] Starting container: {self.container_name}")

        # check if container is already running
        cmd = f"docker ps -a --filter name={self.container_name} --format '{{{{.Names}}}}'"
        result = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
        if result == self.container_name:
            print(f"[E] Container with name {self.container_name} already running.  Rerun with -d to delete all containers")
            sys.exit(1)

        # create docker env vars
        docker_env_vars = {}
        docker_env_vars["TZ"] = self.timezone
        docker_env_vars["SUDO_ACCESS"] = self.sudo_access
        docker_env_vars["PASSWORD_ACCESS"] = self.password_access
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
            print(f"[D] Setting port for container: {self.container_name} to {self.ssh_port}")
            self.modify_sshd_config(option_name="Port", option_value=self.ssh_port)

            print(f"  [D] Applying sshd_config to container: {self.container_name}")
            # write sshd_config to tmp file
            sshd_config_tmp_filename = tmpfile.mktemp()
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

            # killall -HUP sshd.pam
            # cmd = f"docker exec {container_name} killall -HUP sshd" # for image linuxserver/openssh-server:amd64-8.1_p1-r0-ls1
            cmd = f"docker exec {self.container_name} killall -HUP sshd.pam" # for image lscr.io/linuxserver/openssh-server:latest (OpenSSH_9.3)
            #print(f"[D] {cmd}")
            result = None
            retry = True
            retries = 0
            while retry:
                retry = False
                #print(f"[D] {cmd}")
                try:
                    result = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
                    #print(" [+] Successfully restarted sshd")
                except subprocess.CalledProcessError as e:
                    #print(f"[E] Could not restart sshd.pam in container {container_name}: {e}")
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
        print(f"[D] Configuring users in container: {self.container_name}: {self.users}")
        for user in self.users:
            print(f"[D] Configuring user: {user.username} in container: {self.container_name}")

            # create user
            if not user.created:
                print(f"[D] Creating user: {user.username} (created={user.created}) in container: {self.container_name}")
                cmd = f"docker exec {self.container_name} useradd -m {user.username}"
                result = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()

                # check for errors
                if len(result) != 0:
                    print(f"[E] Could not create user {user.username} in container: {self.container_name}")
                    sys.exit(1)

                user.created = True

            # check if user needs a password set too
            password_hash = None
            if user.credential:
                password = user.credential.password
                hash_type = user.credential.hash_type
                if not hash_type: # NONE DES MD5 SHA256 SHA512
                    hash_type = "MD5"
                cmd = f"docker exec {self.container_name} bash -c \"echo '{user.username}:{password}' | chpasswd -c {hash_type}\"" # TODO cmd injection here
                print(f"[D] Setting password for user: {user.username} in container: {self.container_name}: {cmd}")
                result = subprocess.check_output(cmd, shell=True).decode('utf-8').strip()
                # check for errors
                if len(result) != 0:
                    print(f"[E] Could not set password for user {user.username} in container: {self.container_name}")
                    sys.exit(1)

            # check if user can sudo
            cmd = None
            #print(f"[D] sudo_access: {user.can_sudo} for user: {str(user)}")
            if user.can_sudo == True:
                cmd = f"docker exec {self.container_name} bash -c \"echo {user.username} ALL=\(ALL\) ALL >> /etc/sudoers\"" # TODO cmd injection here
            if user.can_sudo == "NOPASSWD":
                cmd = f"docker exec {self.container_name} bash -c \"echo {user.username} ALL=\(ALL\) ALL >> /etc/sudoers\""  # TODO cmd injection here
            if cmd:
                print(f"[D] Adding sudo access for user: {user.username} in container: {self.container_name}: {cmd}")
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
            # print(f"[D] {cmd}")
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
        # if key is present in sshd_config exactly once, replace it
        print(f"[D] Modifying sshd_config: {option_name} {option_value}")
        #print(f"[D] sshd_config before: {self.sshd_config}")
        occurences = len(re.findall(f"^#?{option_name} ", self.sshd_config, re.MULTILINE))
        if occurences == 1:
            self.sshd_config = re.sub(f"^#?{option_name} .*", f"{option_name} {option_value}", self.sshd_config,
                                 flags=re.MULTILINE)
        elif occurences == 0 or occurences > 1:
            # append to file
            # print("[D] Appending to sshd_config")
            self.sshd_config += f"\n{option_name} {option_value}"
        else:
            print(f"[E] Unexpected number of occurences ({occurences}) of {option_name} in sshd_config: {self.sshd_config}.  Shouldn't happen.")
            sys.exit(1)

        #print(f"[D] sshd_config after: {self.sshd_config}")
        return self.sshd_config


class SshKey(object):
    def __init__(self, ssh_key_type="rsa"):
        self.key_type = ssh_key_type

        # create tmp directory for keys
        tmp_dir = tmpfile.mkdtemp()
        key_filename = tmpfile.mktemp(dir=tmp_dir)

        # generate ssh_key
        cmd = f"ssh-keygen -t {ssh_key_type} -f {key_filename} -N ''"
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

if __name__ == "__main__":
    config = Config()
    tmp_dir = None

    # parse command line arguments
    usage = "ssh-farm.py ( -f config.csv [ -d ] [ -c sshd_config_base ] [ -w /path/to/a/writable/working/directory ] | -o sshd_config_base.txt )"
    epilog = "Example 1: ssh-farm.py -o sshd_config_base.txt"
    epilog += "\nExample 2: ssh-farm.py -f config.csv -c sshd_config_base.txt"
    epilog += "\n"
    epilog += "\nconfig.csv is expected to have the following columns:"
    epilog += "\n\tID,username,password,ssh_port"
    epilog += "\n"
    epilog += "\nAdditional columns can be added with the names of sshd_config options"
    epilog += "\n"
    epilog += "\nBefore you run ssh_farm for the first time, pull down the openssh-server docker image:"
    epilog += "\n# docker pull linuxserver/openssh-server:version-9.3_p2-r0"
    epilog += "\n"
    parser = argparse.ArgumentParser(description='Create lots of docker containers running sshd', usage=usage,
                                     epilog=epilog, formatter_class=RawTextHelpFormatter)

    # ssh-farm.py -f config.csv [ -c sshd_config_base ] [ -w /path/to/a/writable/working/directory ]
    parser.add_argument('-f', '--farmconfig', help='CSV file containing configuration', required=False)
    parser.add_argument('-c', '--sshdbaseconfig', help='sshd_config file to use as base', required=False)
    parser.add_argument('-w', '--directory', help='Working directory for tmp files (mainly for debugging)',
                        required=False)
    parser.add_argument('-d', '--delete', help='Delete all containers named ssh_farm_*', action='store_true',
                        required=False)
    parser.add_argument('-T', '--timezone', help=f'Timezone for containers.  Default is {global_defaults["timezone"]}',
                        required=False)
    parser.add_argument('-P', '--ssh_port', help=f'SSH port for containers.  Default is {global_defaults["ssh_port"]}',
                        required=False)
    parser.add_argument('-s', '--sudo_access',
                        help=f'Sudo access for containers.  Default is {global_defaults["sudo_access"]}', required=False)
    parser.add_argument('-t', '--trusts',
                        help=f'CSV file containing SSH key trusts.  Columns: src_host,src_user,dst_host,dst_user,known_hosts_clue.  Default is none',
                        required=False)
    parser.add_argument('-C', '--creds',
                        help=f'CSV file containing OS usernames and passwords.  Columns: ID,username,password,sudo. Default is none',
                        required=False)
    parser.add_argument('-p', '--password_access',
                        help=f'Password access for containers.  Default is {global_defaults["password_access"]}',
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
            print(f"[I] Base sshd_config file saved to {args.outputsshdconfig}")
            sys.exit(0)

    #
    # Remaining options are in -f mode
    #

    # check for -w
    if args.directory:
        tmp_dir = args.directory
    else:
        tmp_dir = tmpfile.mkdtemp()

    # check for -T
    if args.timezone:
        global_defaults['timezone'] = args.timezone

    # check for -P
    if args.ssh_port:
        global_defaults['ssh_port'] = args.ssh_port

    # check for -s
    if args.sudo_access:
        global_defaults['sudo_access'] = args.sudo_access

    # check for -p
    if args.password_access:
        global_defaults['password_access'] = args.password_access

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
        print(f"[+] Reading farm config: {args.farmconfig}")
        with open(args.farmconfig, 'r') as farm_config_file:
            # read into a dict
            reader = csv.DictReader(farm_config_file)

            # loop through each row
            row_number = 1
            for row in reader:
                row_number += 1

                # check for required columns
                if "ID" not in row:
                    print(f"[E] Missing ID column at row {row_number}")
                    sys.exit(1)

                container = config.create_container(container_user_id=row["ID"], is_base_container=True)

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

                    if key == "password_access":
                        # convert string in csv to boolean
                        if option_value.lower() in ["true", "yes", "1"]:
                            option_value = "true"
                        elif option_value.lower() in ["false", "no", "0"]:
                            option_value = "false"
                        else:
                            print(f"[E] Invalid password_access value: {option_value} at row {row_number}")
                            sys.exit(1)
                        container.password_access = option_value
                        continue

                    # assume all other options are sshd_config options
                    container.modify_sshd_config(option_name=option_name, option_value=option_value)

    # check for -t trusts.csv
    # expected columns: src_host,src_user,dst_host,dst_user,known_hosts_clue
    if args.trusts:
        # read in the trusts csv file
        print(f"[+] Reading trusts config: {args.trusts}")
        with open(args.trusts, 'r') as trusts_file:
            # read into a dict
            reader = csv.DictReader(trusts_file)

            # loop through each row
            row_number = 1
            for row in reader:
                row_number += 1

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
        print(f"[+] Reading creds config: {args.creds}")
        with open(args.creds, 'r') as creds_file:
            # read into a dict
            reader = csv.DictReader(creds_file)

            # loop through each row
            row_number = 1
            for row in reader:
                row_number += 1

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
                    container = config.create_container(container_user_id=row["ID"], sudo_access=row["sudo"])
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

                    print(f"[D] Setting sudo access to {access} for user: {user.username} in container: {container.container_name}")
                    user.set_sudo_access(access)

    # check for -d
    if args.delete:
        config.delete_old_ssh_farm_containers()

#    print(config.as_json())
    print(f"[I] Using {tmp_dir} as working directory")

    # Create problem variations of base containers
    config.create_problem_containers()

    # Start containers according to the config in the container objects
    config.start_containers()


    config.print_container_ips()
