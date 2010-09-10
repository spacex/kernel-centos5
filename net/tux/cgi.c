/*
 * TUX - Integrated Application Protocols Layer and Object Cache
 *
 * Copyright (C) 2000, 2001, Ingo Molnar <mingo@redhat.com>
 *
 * cgi.c: user-space CGI (and other) code execution.
 */

#define __KERNEL_SYSCALLS__
#define __KERNEL_SYSCALLS_NO_ERRNO__

#include <net/tux.h>

/****************************************************************
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2, or (at your option)
 *      any later version.
 *
 *      This program is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 ****************************************************************/

static int exec_usermode(char *program_path, char *argv[], char *envp[])
{
	struct files_struct *files = current->files;
	struct fdtable *fdt;
	int i, err;

	err = tux_chroot(tux_cgiroot);
	if (err) {
		printk(KERN_ERR "TUX: CGI chroot returned %d, /proc/sys/net/tux/cgiroot is probably set up incorrectly! Aborting CGI execution.\n", err);
		return err;
	}

	/* Allow execve args to be in kernel space. */
	set_fs(KERNEL_DS);

	// TODO: is this RCU-safe?
	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	spin_unlock(&files->file_lock);

	for (i = 3; i < fdt->max_fds; i++ )
		if (fdt->fd[i])
			tux_close(i);

	err = __exec_usermodehelper(program_path, argv, envp, NULL);
	if (err < 0)
		return err;
	return 0;
}

static inline long tux_dup(unsigned int fildes)
{
	int ret = -EBADF;
	struct file * file = fget(fildes);

	if (file)
		ret = dupfd(file, 0);
	return ret;
}

static int exec_helper (void * data)
{
	exec_param_t *param = data;
	char **tmp;
	int ret;

	sprintf(current->comm,"doexec - %d", current->pid);
#ifdef CONFIG_SMP
	if (!tux_cgi_inherit_cpu) {
		cpumask_t map;

		cpus_and(map, cpu_online_map, tux_cgi_cpu_mask);

		if (!(cpus_empty(map)))
			set_cpus_allowed(current, map);
		else
			set_cpus_allowed(current, cpu_online_map);
	}
#endif

	if (!param)
		TUX_BUG();
	Dprintk("doing exec(%s).\n", param->command);

	Dprintk("argv: ");
	tmp = param->argv;
	while (*tmp) {
		Dprintk("{%s} ", *tmp);
		tmp++;
	}
	Dprintk("\n");
	Dprintk("envp: ");
	tmp = param->envp;
	while (*tmp) {
		Dprintk("{%s} ", *tmp);
		tmp++;
	}
	Dprintk("\n");
	/*
	 * Set up stdin, stdout and stderr of the external
	 * CGI application.
	 */
	if (param->pipe_fds) {
		struct files_struct *files = current->files;
		struct fdtable *fdt;

		tux_close(1);
		tux_close(2);
		tux_close(4);
		if (tux_dup(3) != 1)
			TUX_BUG();
		if (tux_dup(5) != 2)
			TUX_BUG();
		tux_close(3);
		tux_close(5);
		// do not close on exec.
		spin_lock(&files->file_lock);
		fdt = files_fdtable(files);
		FD_CLR(0, fdt->close_on_exec);
		FD_CLR(1, fdt->close_on_exec);
		FD_CLR(2, fdt->close_on_exec);
		spin_unlock(&files->file_lock);
	}
	ret = exec_usermode(param->command, param->argv, param->envp);
	if (ret < 0)
		Dprintk("bug: exec() returned %d.\n", ret);
	else
		Dprintk("exec()-ed successfully!\n");
	return 0;
}

pid_t tux_exec_process (char *command, char **argv,
			char **envp, int pipe_fds,
				exec_param_t *param, int wait)
{
	exec_param_t param_local;
	pid_t pid;
	struct k_sigaction *ka;

	ka = current->sighand->action + SIGCHLD-1;
	ka->sa.sa_handler = SIG_IGN;

	if (!param && wait)
		param = &param_local;

	param->command = command;
	param->argv = argv;
	param->envp = envp;
	param->pipe_fds = pipe_fds;

repeat_fork:
	pid = kernel_thread(exec_helper, (void*) param, CLONE_SIGHAND|SIGCHLD);
	Dprintk("kernel thread created PID %d.\n", pid);
	if (pid < 0) {
		printk(KERN_ERR "TUX: could not create new CGI kernel thread due to %d... retrying.\n", pid);
		current->state = TASK_UNINTERRUPTIBLE;
		schedule_timeout(HZ);
		goto repeat_fork;
	}
	return pid;
}
