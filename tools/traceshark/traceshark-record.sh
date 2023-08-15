#! /usr/bin/bash

trace-cmd record --date \
	-e sched/sched_process_exec \
	-e sched/sched_process_exit \
	-e task/task_newtask \
	-e syscalls/sys_enter_exit_group
