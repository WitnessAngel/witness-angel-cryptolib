# This file is part of Witness Angel Cryptolib
# SPDX-FileCopyrightText: Copyright Prolifik SARL
# SPDX-License-Identifier: GPL-2.0-or-later


import abc, logging
from contextlib import contextmanager
import multitimer
import decorator

logger = logging.getLogger(__name__)


@decorator.decorator
def synchronized(func, self, *args, **kwargs):
    """
    Wraps the function call with a mutex locking on the expected "self._lock" mutex.
    """
    with self._lock:
        return func(self, *args, **kwargs)


@contextmanager
def catch_and_log_exception(context_message):
    """Logs and stops any exception in the managed code block or the decorated function"""
    assert isinstance(context_message, str), context_message
    try:
        yield
    except Exception as exc:
        logger.critical("Abnormal exception caught in %s: %r", context_message, exc, exc_info=True)



class TaskRunnerStateMachineBase(abc.ABC):
    """
    State machine for all sensors/players, checking that the order of start/stop/join
    operations is correct.

    The two-steps shutdown (`stop()`, and later `join()`) allows caller to
    efficiently and safely stop numerous runners.
    """

    def __init__(self, **kwargs):  # Ignored exceeding kwargs here
        self._runner_is_started = False

    @property
    def is_running(self):
        return self._runner_is_started

    def start(self):
        """Start the periodic system which will poll or push the value."""
        if self._runner_is_started:
            raise RuntimeError("Can't start an already started runner")
        self._runner_is_started = True

    def stop(self):
        """Request the periodic system to stop as soon as possible."""
        if not self._runner_is_started:
            raise RuntimeError("Can't stop an already stopped runner")
        self._runner_is_started = False

    def join(self):
        """
        Wait for the periodic system to really finish running.
        Does nothing if periodic system is already stopped.
        """
        if self._runner_is_started:
            raise RuntimeError("Can't join an in-progress runner")


class PeriodicTaskHandler(TaskRunnerStateMachineBase):
    """
    This class runs a task at a specified interval, with start/stop/join controls.

    If `task_func` argument is not provided, then `_offloaded_run_task()` must be overridden by subclass.
    """

    from multitimer import RepeatingTimer as _RepeatingTimer

    # TODO make PR upstream to ensure that multitimer is a DAEMON thread!
    assert hasattr(_RepeatingTimer, "daemon")
    _RepeatingTimer.daemon = True  # Do not prevent process shutdown if we forgot to stop...

    _task_func = None  # Might be overridden as a method too!

    def __init__(self, interval_s, count=-1, runonstart=True, task_func=None, **kwargs):
        super().__init__(**kwargs)
        self._interval_s = interval_s
        if task_func:  # Important
            self._task_func = task_func

        self._multitimer = multitimer.MultiTimer(
            interval=interval_s, function=self._private_launch_offloaded_run_task, count=count, runonstart=runonstart
        )

    def _private_launch_offloaded_run_task(self):
        """Wrapper to ensure that offloaded task will not be run if
        state machine has just been stopped concurrently"""
        if not self.is_running:  # pragma: no cover
            return  # In case of race condition (too hard to test)...
        return self._offloaded_run_task()

    def _offloaded_run_task(self):
        """Method which will be run periodically by background thread,
        and which by default simply calls task_func() and returns the result.

        MEANT TO BE OVERRIDDEN BY SUBCLASS
        """
        return self._task_func()

    def start(self):
        """Launch the secondary thread for periodic task execution."""
        super().start()
        self._multitimer.start()

    def stop(self):
        """Request the secondary thread to stop. If it's currently processing data,
        it will not stop immediately, and another offloaded operation might happen."""
        super().stop()
        self._multitimer.stop()

    def join(self):  # TODO - add a join timeout everywhere?
        """
        Wait for the secondary thread to really exit, after `stop()` was called.
        When this function returns, no more offloaded operation will happen,
        until the next `start()`.
        """
        super().join()
        timer_thread = self._multitimer._timer
        if timer_thread:
            assert timer_thread.stopevent.is_set()
            timer_thread.join()
