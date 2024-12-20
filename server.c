// SPDX-License-Identifier: BSD-3-Clause

#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "ipc.h"

#include "ipc.h"
#include "server.h"

#ifndef OUTPUT_TEMPLATE
#define OUTPUT_TEMPLATE "../checker/output/out-XXXXXX"
#endif

static int lib_prehooks(struct lib *lib)
{
	/* TODO: Implement lib_prehooks(). */
	return 0;
}

static int lib_load(struct lib *lib)
{
	lib->handle = dlopen(lib->libname, RTLD_LAZY);
	if (!lib->handle)
	{
		fprintf(stderr, "Error loading library: %s\n", dlerror());
		return -1;
	}
	
	return 0;

}

static int lib_execute(struct lib *lib)
{
	/* TODO: Implement lib_execute(). */

	if (lib->filename == NULL)
	{
		lib->run = (lambda_func_t)dlsym(lib->handle, lib->funcname);

		if (lib->run != NULL)
			lib->run();
	}
	else
	{
		lib->p_run = (lambda_param_func_t)dlsym(lib->handle, lib->funcname);
		if (lib->p_run != NULL)
		{
			lib->p_run(lib->filename);
		}
		else
		{
			char errorMessage[523];
			snprintf(errorMessage, sizeof(errorMessage), "Error: %s %s%s%s could not be executed.\n",
			         lib->libname,
			         lib->funcname,
			         strcmp(lib->filename, "") ? " " : "",
			         strcmp(lib->filename, "") ? lib->filename : "");
			         
			printf("%s", errorMessage);
			fflush(stdout);
			sleep(0.2);
		}
	}
	
	return 0;
}

static int lib_close(struct lib *lib)
{
	close(lib->handle);
	return 0;

}

static int lib_posthooks(struct lib *lib)
{
	return 0;
}

static int lib_run(struct lib *lib)
{
	int err;

	err = lib_prehooks(lib);
	if (err)
		return err;

	err = lib_load(lib);
	if (err)
		return err;

	err = lib_execute(lib);
	if (err)
		return err;

	err = lib_close(lib);
	if (err)
		return err;

	return lib_posthooks(lib);
}

static int parse_command(const char *buf, char *name, char *func, char *params)
{
	int ret;

	ret = sscanf(buf, "%s %s %s", name, func, params);
	if (ret < 0)
		return -1;

	return ret;
}

int main(void)
{
	int ret;
	struct lib lib;

	setvbuf(stdout, NULL, _IONBF, 0);

	lib.filename = malloc(sizeof(char) * BUFSIZE);
	lib.funcname = malloc(sizeof(char) * 100);
	lib.outputfile = malloc(sizeof(char) * 100);
	lib.libname = malloc(sizeof(char) * 100);

	int server_socket;
	int client_socket;

	struct sockaddr_un server_addr;
	struct sockaddr_un client_addr;

	server_socket = socket(AF_UNIX, SOCK_STREAM, 0);

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sun_family = AF_UNIX;
	strcpy(server_addr.sun_path, SOCKET_NAME);

	int slen = sizeof(server_addr);

	unlink(SOCKET_NAME);
	ret = bind(server_socket, (struct sockaddr *)&server_addr, slen);
	if (ret < 0)
		perror("bind");
	listen(server_socket, 1010);

	pid_t workers[MAX_PROCESSES] = {0};

	while (1)
	{
		memset(&client_addr, 0, sizeof(client_addr));
		socklen_t clen = 0;
		int status = 0;

		memset(&clen, 0, sizeof(clen));
		client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &clen);
		if (client_socket < 0)
		{
			perror("accept");
			exit(2);
		}

		int slot = -1;
		for (int i = 0; i < 2024; ++i)
		{
			if (workers[i] == 0)
			{
				slot = i;
				break;
			}
		}

		if (slot != -1)
		{
			workers[slot] = fork();
			if (workers[slot] == 0)
			{
				char *buffer = calloc(1, 1024);
				int var = recv(client_socket, buffer, 1024, 0);
				if (var < 0)
				{
					fprintf(stderr, "Error receiving data\n");
					perror("recv");
					exit(1);
				}

				int args = parse_command(buffer, lib.libname, lib.funcname, lib.filename);

				if (args == 1)
				{
					strcpy(lib.funcname, "run");
					lib.filename = NULL;
				}
				else if (args == 2)
				{
					lib.filename = NULL;
				}

				strcpy(lib.outputfile, OUTPUT_TEMPLATE);

				int fd = mkstemp(lib.outputfile);
				dup2(fd, STDOUT_FILENO);

				int ret = lib_run(&lib);

				if (ret < 0)
				{
					char errorMessage[523];
					snprintf(errorMessage, sizeof(errorMessage), "Error: %s %s%s%s could not be executed.\n",
					         lib->libname,
					         lib->funcname,
					         strcmp(lib->filename, "") ? " " : "",
					         strcmp(lib->filename, "") ? lib->filename : "");
					         
					printf("%s", errorMessage);
					fflush(stdout);
					sleep(0.2);

				}
				int vari = write(client_socket, lib.outputfile, strlen(lib.outputfile));
				if (vari < 0)
					perror("write");
				exit(0);
			}
			else if (workers[slot] < 0)
			{
				perror("fork");
			}
			else
			{
				close(client_socket);
			}
		}
		else
		{

			pid_t finished_worker = wait(NULL);
			for (int i = 0; i < MAX_PROCESSES; ++i)
			{
				if (workers[i] == finished_worker)
				{
					workers[i] = 0;
					break;
				}
			}
		}
	}

	return 0;
}
