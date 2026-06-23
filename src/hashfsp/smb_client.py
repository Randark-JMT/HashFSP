from __future__ import annotations

from dataclasses import dataclass
import hashlib
import logging
import threading
from typing import Any

from impacket import nt_errors, smb, smb3structs
from impacket.smbconnection import SMBConnection, SessionError

from .auth import HashCredentials
from .paths import ROOT, normalize_mount_path, parent_and_name, wildcard_for_directory


LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class SmbTarget:
    host: str
    share: str
    port: int = 445
    remote_name: str | None = None
    timeout: int = 30


@dataclass(frozen=True)
class RemoteFileInfo:
    path: str
    file_name: str
    file_attributes: int
    allocation_size: int
    file_size: int
    creation_time: int
    last_access_time: int
    last_write_time: int
    change_time: int
    index_number: int

    @property
    def is_directory(self) -> bool:
        return bool(self.file_attributes & smb3structs.FILE_ATTRIBUTE_DIRECTORY)

    def to_winfsp(self) -> dict[str, int]:
        return {
            "file_attributes": self.file_attributes,
            "allocation_size": self.allocation_size,
            "file_size": self.file_size,
            "creation_time": self.creation_time,
            "last_access_time": self.last_access_time,
            "last_write_time": self.last_write_time,
            "change_time": self.change_time,
            "index_number": self.index_number,
        }


class RemoteSmbClient:
    def __init__(self, target: SmbTarget, credentials: HashCredentials):
        self.target = target
        self.credentials = credentials
        self.connection: SMBConnection | None = None
        self.tree_id: Any | None = None
        self._lock = threading.RLock()

    def connect(self) -> None:
        with self._lock:
            if self.connection is not None:
                return

            remote_name = self.target.remote_name or self.target.host
            LOG.info("Connecting to \\\\%s\\%s", self.target.host, self.target.share)
            connection = SMBConnection(
                remoteName=remote_name,
                remoteHost=self.target.host,
                sess_port=self.target.port,
                timeout=self.target.timeout,
            )
            connection.login(
                self.credentials.username,
                "",
                self.credentials.domain,
                lmhash=self.credentials.lmhash,
                nthash=self.credentials.nthash,
                ntlmFallback=False,
            )
            self.tree_id = connection.connectTree(self.target.share)
            self.connection = connection

    def disconnect(self) -> None:
        with self._lock:
            if self.connection is None:
                return
            try:
                if self.tree_id is not None:
                    self.connection.disconnectTree(self.tree_id)
                self.connection.logoff()
            finally:
                self.tree_id = None
                self.connection = None

    def stat(self, path: str) -> RemoteFileInfo:
        path = normalize_mount_path(path)
        if path == ROOT:
            return self._root_info()

        parent, name = parent_and_name(path)
        for entry in self.list_dir(parent, include_dots=True):
            if entry.file_name.lower() == name.lower():
                return RemoteFileInfo(
                    path=path,
                    file_name=entry.file_name,
                    file_attributes=entry.file_attributes,
                    allocation_size=entry.allocation_size,
                    file_size=entry.file_size,
                    creation_time=entry.creation_time,
                    last_access_time=entry.last_access_time,
                    last_write_time=entry.last_write_time,
                    change_time=entry.change_time,
                    index_number=entry.index_number,
                )
        raise self._not_found()

    def list_dir(self, path: str, include_dots: bool = False) -> list[RemoteFileInfo]:
        path = normalize_mount_path(path)
        self._require_connection()
        assert self.connection is not None

        with self._lock:
            try:
                entries = self.connection.listPath(self.target.share, wildcard_for_directory(path))
            except SessionError as exc:
                raise self._translate_error(exc) from exc

        result: list[RemoteFileInfo] = []
        for entry in entries:
            name = self._entry_name(entry)
            if not include_dots and name in {".", ".."}:
                continue
            entry_path = path if name == "." else parent_and_name(path)[0] if name == ".." else _join_info_path(path, name)
            result.append(self._info_from_shared_file(entry_path, entry))

        result.sort(key=lambda info: info.file_name.lower())
        return result

    def open_file(self, path: str, desired_access: int, is_directory: bool) -> Any | None:
        path = normalize_mount_path(path)
        if is_directory:
            return None

        self._require_connection()
        assert self.connection is not None
        assert self.tree_id is not None
        with self._lock:
            try:
                return self.connection.openFile(
                    self.tree_id,
                    path,
                    desiredAccess=desired_access,
                    shareMode=(
                        smb3structs.FILE_SHARE_READ
                        | smb3structs.FILE_SHARE_WRITE
                        | smb3structs.FILE_SHARE_DELETE
                    ),
                    creationOption=smb3structs.FILE_NON_DIRECTORY_FILE,
                    creationDisposition=smb3structs.FILE_OPEN,
                )
            except SessionError as exc:
                raise self._translate_error(exc) from exc

    def create_file(
        self,
        path: str,
        desired_access: int,
        file_attributes: int,
        is_directory: bool,
    ) -> Any | None:
        path = normalize_mount_path(path)
        self._require_connection()
        assert self.connection is not None
        assert self.tree_id is not None

        with self._lock:
            try:
                if is_directory:
                    self.connection.createDirectory(self.target.share, path)
                    return None
                return self.connection.createFile(
                    self.tree_id,
                    path,
                    desiredAccess=desired_access,
                    shareMode=(
                        smb3structs.FILE_SHARE_READ
                        | smb3structs.FILE_SHARE_WRITE
                        | smb3structs.FILE_SHARE_DELETE
                    ),
                    creationOption=smb3structs.FILE_NON_DIRECTORY_FILE,
                    creationDisposition=smb3structs.FILE_CREATE,
                    fileAttributes=_normalize_file_attributes(file_attributes),
                )
            except SessionError as exc:
                raise self._translate_error(exc) from exc

    def close_file(self, file_id: Any | None) -> None:
        if file_id is None:
            return
        self._require_connection()
        assert self.connection is not None
        assert self.tree_id is not None
        with self._lock:
            try:
                self.connection.closeFile(self.tree_id, file_id)
            except SessionError as exc:
                raise self._translate_error(exc) from exc

    def read_file(self, file_id: Any, offset: int, length: int) -> bytes:
        self._require_connection()
        assert self.connection is not None
        assert self.tree_id is not None
        with self._lock:
            try:
                return self.connection.readFile(
                    self.tree_id,
                    file_id,
                    offset=offset,
                    bytesToRead=length,
                    singleCall=False,
                )
            except SessionError as exc:
                raise self._translate_error(exc) from exc

    def write_file(self, file_id: Any, data: bytes, offset: int) -> int:
        self._require_connection()
        assert self.connection is not None
        assert self.tree_id is not None
        with self._lock:
            try:
                written = self.connection.writeFile(self.tree_id, file_id, data, offset)
            except SessionError as exc:
                raise self._translate_error(exc) from exc
        return int(written) if written is not None else len(data)

    def set_file_size(self, file_id: Any, new_size: int) -> None:
        self._require_connection()
        assert self.connection is not None
        assert self.tree_id is not None
        info = smb.SMBSetFileEndOfFileInfo()
        info["EndOfFile"] = int(new_size)

        with self._lock:
            try:
                file_info_class = (
                    smb.SMB_SET_FILE_END_OF_FILE_INFO
                    if self.connection.getDialect() == smb.SMB_DIALECT
                    else smb3structs.SMB2_FILE_END_OF_FILE_INFO
                )
                self.connection.setInfo(self.tree_id, file_id, file_info_class, info)
            except SessionError as exc:
                raise self._translate_error(exc) from exc

    def set_basic_info(
        self,
        file_id: Any,
        *,
        file_attributes: int,
        creation_time: int,
        last_access_time: int,
        last_write_time: int,
        change_time: int,
    ) -> None:
        self._require_connection()
        assert self.connection is not None
        assert self.tree_id is not None

        if self.connection.getDialect() == smb.SMB_DIALECT:
            info = smb.SMBSetFileBasicInfo()
            info["CreationTime"] = int(creation_time)
            info["LastAccessTime"] = int(last_access_time)
            info["LastWriteTime"] = int(last_write_time)
            info["ChangeTime"] = int(change_time)
            info["ExtFileAttributes"] = _set_info_file_attributes(file_attributes)
            file_info_class = smb.SMB_SET_FILE_BASIC_INFO
        else:
            info = smb3structs.FILE_BASIC_INFORMATION()
            info["CreationTime"] = int(creation_time)
            info["LastAccessTime"] = int(last_access_time)
            info["LastWriteTime"] = int(last_write_time)
            info["ChangeTime"] = int(change_time)
            info["FileAttributes"] = _set_info_file_attributes(file_attributes)
            file_info_class = smb3structs.SMB2_FILE_BASIC_INFO

        with self._lock:
            try:
                self.connection.setInfo(self.tree_id, file_id, file_info_class, info)
            except SessionError as exc:
                raise self._translate_error(exc) from exc

    def delete(self, path: str, is_directory: bool) -> None:
        path = normalize_mount_path(path)
        self._require_connection()
        assert self.connection is not None
        with self._lock:
            try:
                if is_directory:
                    self.connection.deleteDirectory(self.target.share, path)
                else:
                    self.connection.deleteFile(self.target.share, path)
            except SessionError as exc:
                raise self._translate_error(exc) from exc

    def rename(self, old_path: str, new_path: str, replace_if_exists: bool) -> None:
        old_path = normalize_mount_path(old_path)
        new_path = normalize_mount_path(new_path)
        self._require_connection()
        assert self.connection is not None

        if not replace_if_exists:
            try:
                self.stat(new_path)
            except Exception as exc:
                if not _is_winfsp_not_found(exc):
                    raise
            else:
                raise self._collision()

        with self._lock:
            try:
                self.connection.rename(self.target.share, old_path, new_path)
            except SessionError as exc:
                raise self._translate_error(exc) from exc

    def _require_connection(self) -> None:
        if self.connection is None:
            raise RuntimeError("SMB connection is not established")

    def _root_info(self) -> RemoteFileInfo:
        return RemoteFileInfo(
            path=ROOT,
            file_name="",
            file_attributes=smb3structs.FILE_ATTRIBUTE_DIRECTORY,
            allocation_size=0,
            file_size=0,
            creation_time=0,
            last_access_time=0,
            last_write_time=0,
            change_time=0,
            index_number=1,
        )

    def _info_from_shared_file(self, path: str, entry: Any) -> RemoteFileInfo:
        attributes = int(entry.get_attributes())
        if entry.is_directory():
            attributes |= smb3structs.FILE_ATTRIBUTE_DIRECTORY
        elif attributes == 0:
            attributes = smb3structs.FILE_ATTRIBUTE_NORMAL

        file_size = int(entry.get_filesize())
        allocation_size = int(entry.get_allocsize() or _round_allocation(file_size))
        return RemoteFileInfo(
            path=normalize_mount_path(path),
            file_name=self._entry_name(entry),
            file_attributes=attributes,
            allocation_size=allocation_size,
            file_size=file_size,
            creation_time=int(entry.get_ctime() or 0),
            last_access_time=int(entry.get_atime() or 0),
            last_write_time=int(entry.get_wtime() or 0),
            change_time=int(entry.get_mtime() or 0),
            index_number=_stable_index(path),
        )

    @staticmethod
    def _entry_name(entry: Any) -> str:
        name = entry.get_longname()
        if isinstance(name, bytes):
            name = name.decode("utf-8", errors="replace")
        return str(name)

    @staticmethod
    def _not_found() -> Exception:
        from winfspy import NTStatusObjectNameNotFound

        return NTStatusObjectNameNotFound()

    @staticmethod
    def _collision() -> Exception:
        from winfspy import NTStatusObjectNameCollision

        return NTStatusObjectNameCollision()

    @staticmethod
    def _translate_error(exc: SessionError) -> Exception:
        from winfspy import (
            NTStatusAccessDenied,
            NTStatusDirectoryNotEmpty,
            NTStatusEndOfFile,
            NTStatusMediaWriteProtected,
            NTStatusNotADirectory,
            NTStatusObjectNameCollision,
            NTStatusObjectNameNotFound,
        )
        from winfspy.plumbing import NTSTATUS, NTStatusError

        code = exc.getErrorCode()
        if code in {
            nt_errors.STATUS_NO_SUCH_FILE,
            nt_errors.STATUS_OBJECT_NAME_NOT_FOUND,
            nt_errors.STATUS_OBJECT_PATH_NOT_FOUND,
        }:
            return NTStatusObjectNameNotFound()
        if code == nt_errors.STATUS_OBJECT_NAME_COLLISION:
            return NTStatusObjectNameCollision()
        if code in {nt_errors.STATUS_ACCESS_DENIED, nt_errors.STATUS_NETWORK_ACCESS_DENIED}:
            return NTStatusAccessDenied()
        if code == nt_errors.STATUS_NOT_A_DIRECTORY:
            return NTStatusNotADirectory()
        if code == nt_errors.STATUS_DIRECTORY_NOT_EMPTY:
            return NTStatusDirectoryNotEmpty()
        if code == nt_errors.STATUS_END_OF_FILE:
            return NTStatusEndOfFile()
        if code == nt_errors.STATUS_MEDIA_WRITE_PROTECTED:
            return NTStatusMediaWriteProtected()
        return NTStatusError(NTSTATUS.STATUS_UNEXPECTED_NETWORK_ERROR)


def _join_info_path(parent: str, name: str) -> str:
    parent = normalize_mount_path(parent)
    if parent == ROOT:
        return normalize_mount_path("\\" + name)
    return normalize_mount_path(parent + "\\" + name)


def _stable_index(path: str) -> int:
    digest = hashlib.blake2b(path.lower().encode("utf-16le"), digest_size=8).digest()
    return int.from_bytes(digest, "little", signed=False)


def _round_allocation(file_size: int) -> int:
    if file_size <= 0:
        return 0
    block = 4096
    return ((file_size + block - 1) // block) * block


def _normalize_file_attributes(file_attributes: int) -> int:
    if file_attributes in {0, 0xFFFFFFFF}:
        return smb3structs.FILE_ATTRIBUTE_NORMAL
    return int(file_attributes)


def _set_info_file_attributes(file_attributes: int) -> int:
    if file_attributes in {0, 0xFFFFFFFF}:
        return 0
    return int(file_attributes)


def _is_winfsp_not_found(exc: Exception) -> bool:
    return exc.__class__.__name__ == "NTStatusObjectNameNotFound"
