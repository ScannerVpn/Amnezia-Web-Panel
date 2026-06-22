import hashlib
import io
import logging
import os
import paramiko
import shlex
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Persistent known_hosts file (lives under DATA_DIR so it survives container restarts)
_KNOWN_HOSTS_FILE = Path(os.getenv("DATA_DIR", "./data")) / "known_hosts"


class SSHManager:
    def __init__(self, host: str, port: int, username: str,
                 password: Optional[str] = None, key_data: Optional[str] = None):
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.key_data = key_data
        self._client: Optional[paramiko.SSHClient] = None
        self._is_root = (username == "root")

    def connect(self) -> None:
        self._client = paramiko.SSHClient()

        # Load known_hosts for caching, auto-add unknown hosts
        _KNOWN_HOSTS_FILE.parent.mkdir(parents=True, exist_ok=True)
        if _KNOWN_HOSTS_FILE.exists():
            self._client.load_host_keys(str(_KNOWN_HOSTS_FILE))
        self._client.load_system_host_keys()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        kwargs = {
            "hostname": self.host,
            "port": self.port,
            "username": self.username,
            "timeout": 15,
            "banner_timeout": 30,
            "auth_timeout": 30,
        }

        if self.key_data:
            for key_class in [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey]:
                try:
                    key = key_class.from_private_key(io.StringIO(self.key_data))
                    kwargs["pkey"] = key
                    break
                except Exception:
                    continue
        elif self.password:
            kwargs["password"] = self.password

        try:
            self._client.connect(**kwargs)
            # Save host key for future connections
            if self._client.get_transport():
                try:
                    self._client.save_host_keys(str(_KNOWN_HOSTS_FILE))
                except Exception:
                    pass
        except paramiko.AuthenticationException:
            raise ConnectionError(f"Authentication failed for {self.username}@{self.host}")
        except paramiko.SSHException as e:
            raise ConnectionError(f"SSH error connecting to {self.host}: {e}")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to {self.host}: {e}")

    def disconnect(self) -> None:
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()

    def run_command(self, command: str, timeout: int = 120,
                    stdin_data: Optional[str] = None) -> Tuple[str, str, int]:
        """Execute a command. If `stdin_data` is provided, it is piped to the
        command's stdin through paramiko (no shell interpolation)."""
        if not self._client:
            raise ConnectionError("Not connected")
        try:
            stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            stdout.channel.settimeout(timeout)
            if stdin_data is not None:
                stdin.write(stdin_data)
                stdin.flush()
                stdin.channel.shutdown_write()
            out = stdout.read().decode("utf-8", errors="replace").replace("\r\n", "\n")
            err = stderr.read().decode("utf-8", errors="replace").replace("\r\n", "\n")
            code = stdout.channel.recv_exit_status()
            return out, err, code
        except Exception as e:
            logger.error("Command failed on %s: %s", self.host, e)
            raise

    def run_sudo(self, command: str, timeout: int = 120) -> Tuple[str, str, int]:
        """Run command as root. If user is not root, password is piped to sudo
        via stdin (safe — no shell interpolation)."""
        if self._is_root:
            return self.run_command(command, timeout)

        # Strip leading 'sudo ' if present
        command = command.removeprefix("sudo").strip()
        # Use shlex.quote to safely pass the command to sudo -p ''
        # Pass password via stdin (no shell interpolation)
        return self.run_command(
            "sudo -S -p '' " + command,
            timeout=timeout,
            stdin_data=(self.password or "") + "\n",
        )

    def run_sudo_script(self, script: str, timeout: int = 300) -> Tuple[str, str, int]:
        h = hashlib.sha256(script.encode()).hexdigest()[:12]
        tmp = f"/tmp/.script_{h}.sh"
        self.upload_file(script, tmp)
        try:
            self.run_sudo(f"chmod +x {shlex.quote(tmp)}")
            out, err, code = self.run_sudo(f"bash {shlex.quote(tmp)}", timeout)
        finally:
            self.run_command(f"rm -f {shlex.quote(tmp)}")
        return out, err, code

    def upload_file(self, content: str, remote_path: str) -> None:
        sftp = self._client.open_sftp()
        try:
            content = content.replace("\r\n", "\n")
            with sftp.open(remote_path, "w") as f:
                f.write(content)
        finally:
            sftp.close()

    def upload_sudo_file(self, content: str, remote_path: str) -> None:
        h = hashlib.sha256(remote_path.encode()).hexdigest()[:12]
        tmp = f"/tmp/.upload_{h}"
        self.upload_file(content, tmp)
        self.run_sudo(
            f"mv {shlex.quote(tmp)} {shlex.quote(remote_path)} && "
            f"chmod 600 {shlex.quote(remote_path)}"
        )

    def download_file(self, remote_path: str) -> str:
        sftp = self._client.open_sftp()
        try:
            with sftp.open(remote_path, "r") as f:
                return f.read().decode("utf-8", errors="replace").replace("\r\n", "\n")
        finally:
            sftp.close()

    def file_exists(self, remote_path: str) -> bool:
        sftp = self._client.open_sftp()
        try:
            sftp.stat(remote_path)
            return True
        except FileNotFoundError:
            return False
        finally:
            sftp.close()

    def test_connection(self) -> dict:
        try:
            self.connect()
            out, _, code = self.run_command("uname -sr && cat /etc/os-release | grep PRETTY_NAME")
            self.disconnect()
            return {"success": code == 0, "info": out.strip()}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def open_port(self, port: int, protocol: str = "tcp") -> None:
        """Open a firewall port using ufw or iptables. Inputs are validated
        integers/strings — safe from injection."""
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ValueError("Invalid port")
        proto = protocol.lower()
        if proto not in ("tcp", "udp"):
            raise ValueError("Invalid protocol")
        self.run_sudo(f"ufw allow {port}/{proto} 2>/dev/null || true")
        self.run_sudo(
            f"iptables -C INPUT -p {proto} --dport {port} -j ACCEPT 2>/dev/null || "
            f"iptables -I INPUT -p {proto} --dport {port} -j ACCEPT 2>/dev/null || true"
        )
        # Persist iptables rules
        self.run_sudo(
            "(which iptables-save && iptables-save > /etc/iptables/rules.v4) 2>/dev/null || true"
        )

    def ping(self) -> dict:
        import time
        try:
            start = time.time()
            self.connect()
            self.run_command("echo ok")
            self.disconnect()
            latency = round((time.time() - start) * 1000)
            return {"success": True, "latency_ms": latency}
        except Exception as e:
            return {"success": False, "error": str(e)}
