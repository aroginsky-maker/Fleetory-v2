"""Owned Windows process image/birth observations and a non-breakaway lifetime Job."""
import ctypes
from pathlib import Path
import time


U32, U64, SIZE = ctypes.c_uint32, ctypes.c_uint64, ctypes.c_size_t
HANDLE, BOOL = ctypes.c_void_p, ctypes.c_int32


class BasicLimits(ctypes.Structure):
    _fields_ = [('process_time', ctypes.c_int64), ('job_time', ctypes.c_int64), ('flags', U32),
        ('minimum_working_set', SIZE), ('maximum_working_set', SIZE), ('active_limit', U32),
        ('affinity', SIZE), ('priority', U32), ('scheduling', U32)]


class ExtendedLimits(ctypes.Structure):
    _fields_ = [('basic', BasicLimits), ('io', U64 * 6), ('process_memory', SIZE),
        ('job_memory', SIZE), ('peak_process_memory', SIZE), ('peak_job_memory', SIZE)]


class Accounting(ctypes.Structure):
    _fields_ = [('times', ctypes.c_int64 * 4), ('page_faults', U32), ('total', U32),
        ('active', U32), ('terminated', U32)]


def require(value):
    if not value:
        raise OSError('Owned Windows process observation refused.')


class JobFence:
    def __init__(self):
        self._kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        create = self._kernel.CreateJobObjectW
        create.argtypes, create.restype = [ctypes.c_void_p, ctypes.c_wchar_p], HANDLE
        self.handle = create(None, None)
        require(self.handle)
        self.assigned = False
        try:
            limits = ExtendedLimits()
            limits.basic.flags = 0x2000  # KILL_ON_JOB_CLOSE; no breakaway flags.
            setter = self._kernel.SetInformationJobObject
            setter.argtypes, setter.restype = [HANDLE, ctypes.c_int, ctypes.c_void_p, U32], BOOL
            require(setter(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)))
            flags = U32()
            get_flags = self._kernel.GetHandleInformation
            get_flags.argtypes, get_flags.restype = [HANDLE, ctypes.POINTER(U32)], BOOL
            require(get_flags(self.handle, ctypes.byref(flags)) and not flags.value & 1)
        except BaseException:
            self.close()
            raise

    def assign(self, process):
        assign = self._kernel.AssignProcessToJobObject
        assign.argtypes, assign.restype = [HANDLE, HANDLE], BOOL
        require(not self.assigned and assign(self.handle, int(process._handle)))
        self.assigned = True
        require(self.active() >= 1)
        limits = ExtendedLimits()
        query = self._kernel.QueryInformationJobObject
        query.argtypes, query.restype = [HANDLE, ctypes.c_int, ctypes.c_void_p, U32, ctypes.c_void_p], BOOL
        require(query(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits), None))
        require(limits.basic.flags == 0x2000)

    def active(self):
        info = Accounting()
        query = self._kernel.QueryInformationJobObject
        query.argtypes, query.restype = [HANDLE, ctypes.c_int, ctypes.c_void_p, U32, ctypes.c_void_p], BOOL
        require(query(self.handle, 1, ctypes.byref(info), ctypes.sizeof(info), None))
        return int(info.active)

    def terminate(self):
        require(self.assigned)
        terminate = self._kernel.TerminateJobObject
        terminate.argtypes, terminate.restype = [HANDLE, U32], BOOL
        require(terminate(self.handle, 1))
        deadline = time.monotonic_ns() + 3_000_000_000
        while self.active() != 0:
            require(time.monotonic_ns() < deadline)
            time.sleep(0.01)
        return dict(kind='windows-job-object', activeMembers=0, noRunningMembersVerified=True,
            breakawayDisabled=True, escapedSessionContainmentVerified=False, supervisorDeathKillOnCloseConfigured=True)

    def close(self):
        if self.handle is not None:
            handle, self.handle = self.handle, None
            close = self._kernel.CloseHandle
            close.argtypes, close.restype = [HANDLE], BOOL
            require(close(handle))

    def identity(self, process, pinned):
        handle = int(process._handle)
        get_pid = self._kernel.GetProcessId
        get_pid.argtypes, get_pid.restype = [HANDLE], U32
        require(get_pid(handle) == process.pid and process.poll() is None)
        values = (U64(), U64(), U64(), U64())
        get_times = self._kernel.GetProcessTimes
        get_times.argtypes, get_times.restype = [HANDLE] + [ctypes.POINTER(U64)] * 4, BOOL
        require(get_times(handle, *(ctypes.byref(value) for value in values)))
        require(values[0].value > 0)
        name = ctypes.create_unicode_buffer(32768)
        length = U32(len(name))
        image = self._kernel.QueryFullProcessImageNameW
        image.argtypes, image.restype = [HANDLE, U32, ctypes.c_wchar_p, ctypes.POINTER(U32)], BOOL
        require(image(handle, 0, name, ctypes.byref(length)))
        require(0 < length.value < len(name) and Path(name.value).resolve(strict=True) == pinned.path)
        pinned.check()
        return dict(pid=process.pid, imageSha256=pinned.digest, birthKind='windows-filetime',
            birthToken=str(values[0].value), ownedProcessHandle=True, actualImageMatched=True)


def pid_is_running(pid):
    """Generated-test observer only; never signal a scalar PID on Windows."""
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    opened = kernel.OpenProcess
    opened.argtypes, opened.restype = [U32, BOOL, U32], HANDLE
    handle = opened(0x1000, False, pid)
    if not handle:
        require(ctypes.get_last_error() == 87)
        return False
    close = kernel.CloseHandle
    close.argtypes, close.restype = [HANDLE], BOOL
    try:
        code = U32()
        query = kernel.GetExitCodeProcess
        query.argtypes, query.restype = [HANDLE, ctypes.POINTER(U32)], BOOL
        require(query(handle, ctypes.byref(code)))
        return code.value == 259
    finally:
        require(close(handle))
