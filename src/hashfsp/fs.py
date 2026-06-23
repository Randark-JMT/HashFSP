from __future__ import annotations

from dataclasses import dataclass
import logging
from pathlib import Path
import threading
from typing import Any

from winfspy import (
    BaseFileContext,
    BaseFileSystemOperations,
    CREATE_FILE_CREATE_OPTIONS,
    FILE_ATTRIBUTE,
    FileSystem,
    NTStatusAccessDenied,
    NTStatusDirectoryNotEmpty,
    NTStatusEndOfFile,
    NTStatusMediaWriteProtected,
    NTStatusNotADirectory,
    NTStatusObjectNameCollision,
    NTStatusObjectNameNotFound,
    enable_debug_log,
)
from winfspy.plumbing import NTSTATUS, NTStatusError
from winfspy.plumbing.security_descriptor import SecurityDescriptor
from winfspy.plumbing.win32_filetime import filetime_now

from impacket import smb3structs

from .paths import ROOT, join_child, normalize_mount_path
from .smb_client import RemoteFileInfo, RemoteSmbClient


LOG = logging.getLogger(__name__)

_FULL_LOCAL_SECURITY = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)"

_FSP_CLEANUP_DELETE = 0x01
_REMOTE_READ = (
    smb3structs.FILE_READ_DATA
    | smb3structs.FILE_READ_ATTRIBUTES
    | smb3structs.FILE_READ_EA
    | smb3structs.READ_CONTROL
    | smb3structs.SYNCHRONIZE
)
_REMOTE_WRITE = (
    smb3structs.FILE_WRITE_DATA
    | smb3structs.FILE_APPEND_DATA
    | smb3structs.FILE_WRITE_ATTRIBUTES
    | smb3structs.FILE_WRITE_EA
)
_REMOTE_DELETE = smb3structs.DELETE | smb3structs.FILE_DELETE_CHILD


@dataclass
class RemoteFileContext(BaseFileContext):
    path: str
    is_directory: bool
    file_id: Any | None = None
    cached_info: RemoteFileInfo | None = None
    delete_on_cleanup: bool = False


class RemoteSmbFileSystemOperations(BaseFileSystemOperations):
    def __init__(self, client: RemoteSmbClient, volume_label: str, read_only: bool = False):
        super().__init__()
        if len(volume_label) > 31:
            raise ValueError("volume label must be at most 31 characters")

        self.client = client
        self.volume_label = volume_label
        self.read_only = read_only
        self.security_descriptor = SecurityDescriptor.from_string(_FULL_LOCAL_SECURITY)
        self._lock = threading.RLock()

    def get_volume_info(self) -> dict[str, int | str]:
        return {
            "total_size": 1024 * 1024 * 1024 * 1024,
            "free_size": 1024 * 1024 * 1024 * 1024,
            "volume_label": self.volume_label,
        }

    def set_volume_label(self, volume_label: str) -> None:
        self.volume_label = volume_label

    def get_security_by_name(self, file_name: str):
        info = self.client.stat(file_name)
        return (
            info.file_attributes,
            self.security_descriptor.handle,
            self.security_descriptor.size,
        )

    def create(
        self,
        file_name: str,
        create_options: int,
        granted_access: int,
        file_attributes: int,
        security_descriptor,
        allocation_size: int,
    ) -> RemoteFileContext:
        self._ensure_writable()
        path = normalize_mount_path(file_name)
        is_directory = bool(create_options & CREATE_FILE_CREATE_OPTIONS.FILE_DIRECTORY_FILE)
        desired_access = self._desired_access(granted_access, for_directory=is_directory)

        with self._lock:
            file_id = self.client.create_file(
                path,
                desired_access=desired_access,
                file_attributes=file_attributes,
                is_directory=is_directory,
            )
            context = RemoteFileContext(path=path, is_directory=is_directory, file_id=file_id)
            if allocation_size and file_id is not None:
                self.client.set_file_size(file_id, allocation_size)
            context.cached_info = self.client.stat(path)
            return context

    def open(self, file_name: str, create_options: int, granted_access: int) -> RemoteFileContext:
        path = normalize_mount_path(file_name)
        info = self.client.stat(path)
        is_directory = info.is_directory

        if is_directory and create_options & CREATE_FILE_CREATE_OPTIONS.FILE_NON_DIRECTORY_FILE:
            raise NTStatusNotADirectory()
        if not is_directory and create_options & CREATE_FILE_CREATE_OPTIONS.FILE_DIRECTORY_FILE:
            raise NTStatusNotADirectory()

        desired_access = self._desired_access(granted_access, for_directory=is_directory)
        with self._lock:
            file_id = self.client.open_file(path, desired_access=desired_access, is_directory=is_directory)
            return RemoteFileContext(
                path=path,
                is_directory=is_directory,
                file_id=file_id,
                cached_info=info,
            )

    def overwrite(
        self,
        file_context: RemoteFileContext,
        file_attributes: int,
        replace_file_attributes: bool,
        allocation_size: int,
    ) -> None:
        self._ensure_writable()
        if file_context.is_directory:
            raise NTStatusAccessDenied()
        if file_context.file_id is not None:
            self.client.set_file_size(file_context.file_id, allocation_size)
            self.set_basic_info(
                file_context,
                file_attributes,
                0,
                0,
                filetime_now(),
                filetime_now(),
                {},
            )

    def cleanup(self, file_context: RemoteFileContext, file_name: str | None, flags: int) -> None:
        should_delete = file_context.delete_on_cleanup or bool(flags & _FSP_CLEANUP_DELETE)
        if not should_delete:
            return

        self._ensure_writable()
        with self._lock:
            self._close_remote_handle(file_context)
            self.client.delete(file_context.path, file_context.is_directory)

    def close(self, file_context: RemoteFileContext) -> None:
        with self._lock:
            self._close_remote_handle(file_context)

    def read(self, file_context: RemoteFileContext, offset: int, length: int) -> bytes:
        if file_context.is_directory or file_context.file_id is None:
            raise NTStatusAccessDenied()

        info = self._stat_context(file_context)
        if offset >= info.file_size:
            raise NTStatusEndOfFile()
        return self.client.read_file(file_context.file_id, offset, min(length, info.file_size - offset))

    def write(
        self,
        file_context: RemoteFileContext,
        buffer,
        offset: int,
        write_to_end_of_file: bool,
        constrained_io: bool,
    ) -> int:
        self._ensure_writable()
        if file_context.is_directory or file_context.file_id is None:
            raise NTStatusAccessDenied()

        data = bytes(buffer)
        info = self._stat_context(file_context)
        if write_to_end_of_file:
            offset = info.file_size
        if constrained_io:
            if offset >= info.file_size:
                return 0
            data = data[: max(0, info.file_size - offset)]
        if not data:
            return 0
        return self.client.write_file(file_context.file_id, data, offset)

    def flush(self, file_context: RemoteFileContext) -> None:
        return None

    def get_file_info(self, file_context: RemoteFileContext) -> dict[str, int]:
        return self._stat_context(file_context).to_winfsp()

    def set_basic_info(
        self,
        file_context: RemoteFileContext,
        file_attributes: int,
        creation_time: int,
        last_access_time: int,
        last_write_time: int,
        change_time: int,
        file_info,
    ) -> dict[str, int]:
        self._ensure_writable()
        if file_context.file_id is None:
            raise NTStatusAccessDenied()

        attrs = 0 if file_attributes == FILE_ATTRIBUTE.INVALID_FILE_ATTRIBUTES else int(file_attributes)
        self.client.set_basic_info(
            file_context.file_id,
            file_attributes=attrs,
            creation_time=creation_time,
            last_access_time=last_access_time,
            last_write_time=last_write_time,
            change_time=change_time,
        )
        return self._stat_context(file_context, refresh=True).to_winfsp()

    def set_file_size(
        self,
        file_context: RemoteFileContext,
        new_size: int,
        set_allocation_size: bool,
    ) -> None:
        self._ensure_writable()
        if file_context.is_directory or file_context.file_id is None:
            raise NTStatusAccessDenied()
        if set_allocation_size:
            return
        self.client.set_file_size(file_context.file_id, new_size)
        file_context.cached_info = None

    def can_delete(self, file_context: RemoteFileContext, file_name: str) -> None:
        info = self._stat_context(file_context)
        if not info.is_directory:
            return
        entries = [entry for entry in self.client.list_dir(file_context.path) if entry.file_name not in {".", ".."}]
        if entries:
            raise NTStatusDirectoryNotEmpty()

    def set_delete(self, file_context: RemoteFileContext, file_name: str, delete_file: bool):
        if delete_file:
            self.can_delete(file_context, file_name)
        file_context.delete_on_cleanup = bool(delete_file)

    def rename(
        self,
        file_context: RemoteFileContext,
        file_name: str,
        new_file_name: str,
        replace_if_exists: bool,
    ):
        self._ensure_writable()
        old_path = normalize_mount_path(file_name)
        new_path = normalize_mount_path(new_file_name)
        if old_path == ROOT or new_path == ROOT:
            raise NTStatusAccessDenied()

        with self._lock:
            self._close_remote_handle(file_context)
            self.client.rename(old_path, new_path, replace_if_exists)
            file_context.path = new_path
            file_context.cached_info = None

    def get_security(self, file_context: RemoteFileContext):
        return self.security_descriptor.handle, self.security_descriptor.size

    def set_security(self, file_context, security_information, modification_descriptor):
        self._ensure_writable()
        raise NTStatusError(NTSTATUS.STATUS_NOT_SUPPORTED)

    def read_directory(self, file_context: RemoteFileContext, marker: str | None) -> list[dict[str, int | str]]:
        if not file_context.is_directory:
            raise NTStatusNotADirectory()

        entries = self.client.list_dir(file_context.path)
        if file_context.path != ROOT:
            current = self._stat_context(file_context)
            parent = self.client.stat(_parent_path(file_context.path))
            entries = [
                _named_info(".", current),
                _named_info("..", parent),
                *entries,
            ]

        info_dicts = [{"file_name": entry.file_name, **entry.to_winfsp()} for entry in entries]
        info_dicts.sort(key=lambda item: str(item["file_name"]).lower())
        if marker is None:
            return info_dicts

        marker_lower = marker.lower()
        return [item for item in info_dicts if str(item["file_name"]).lower() > marker_lower]

    def get_dir_info_by_name(self, file_context: RemoteFileContext, file_name: str) -> dict[str, int | str]:
        if not file_context.is_directory:
            raise NTStatusNotADirectory()
        if file_name == ".":
            return {"file_name": ".", **self._stat_context(file_context).to_winfsp()}
        if file_name == "..":
            return {"file_name": "..", **self.client.stat(_parent_path(file_context.path)).to_winfsp()}
        info = self.client.stat(join_child(file_context.path, file_name))
        return {"file_name": file_name, **info.to_winfsp()}

    def _desired_access(self, granted_access: int, for_directory: bool) -> int:
        if self.read_only:
            return _REMOTE_READ

        if granted_access:
            access = int(granted_access)
            access |= smb3structs.FILE_READ_ATTRIBUTES | smb3structs.SYNCHRONIZE
            if for_directory:
                access |= smb3structs.FILE_LIST_DIRECTORY | smb3structs.FILE_TRAVERSE
            return access
        return _REMOTE_READ | _REMOTE_WRITE | _REMOTE_DELETE

    def _stat_context(self, file_context: RemoteFileContext, refresh: bool = False) -> RemoteFileInfo:
        if refresh or file_context.cached_info is None:
            file_context.cached_info = self.client.stat(file_context.path)
        return file_context.cached_info

    def _close_remote_handle(self, file_context: RemoteFileContext) -> None:
        if file_context.file_id is None:
            return
        file_id = file_context.file_id
        file_context.file_id = None
        self.client.close_file(file_id)

    def _ensure_writable(self) -> None:
        if self.read_only:
            raise NTStatusMediaWriteProtected()


def create_hash_file_system(
    mountpoint: str,
    client: RemoteSmbClient,
    *,
    label: str = "HashFSP",
    read_only: bool = False,
    debug: bool = False,
) -> FileSystem:
    if debug:
        enable_debug_log()

    mount_path = Path(mountpoint)
    is_drive = mount_path.parent == mount_path
    operations = RemoteSmbFileSystemOperations(client, label, read_only=read_only)
    return FileSystem(
        str(mountpoint),
        operations,
        sector_size=512,
        sectors_per_allocation_unit=8,
        volume_creation_time=filetime_now(),
        volume_serial_number=0x48465350,
        file_info_timeout=500,
        case_sensitive_search=0,
        case_preserved_names=1,
        unicode_on_disk=1,
        persistent_acls=1,
        read_only_volume=1 if read_only else 0,
        post_cleanup_when_modified_only=1,
        um_file_context_is_user_context2=1,
        file_system_name="HashFSP",
        reject_irp_prior_to_transact0=0 if is_drive else 1,
        debug=debug,
    )


def _parent_path(path: str) -> str:
    path = normalize_mount_path(path)
    if path == ROOT:
        return ROOT
    parent = path.rsplit("\\", 1)[0]
    return normalize_mount_path(parent or ROOT)


def _named_info(name: str, info: RemoteFileInfo) -> RemoteFileInfo:
    return RemoteFileInfo(
        path=info.path,
        file_name=name,
        file_attributes=info.file_attributes,
        allocation_size=info.allocation_size,
        file_size=info.file_size,
        creation_time=info.creation_time,
        last_access_time=info.last_access_time,
        last_write_time=info.last_write_time,
        change_time=info.change_time,
        index_number=info.index_number,
    )
