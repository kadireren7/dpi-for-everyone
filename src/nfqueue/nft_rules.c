#include "nft_rules.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

size_t	nft_rules_generate_create(char *out, size_t out_size, int queue_num)
{
	int	written;

	written = snprintf(out, out_size,
			"table inet %s {\n"
			"\tchain %s {\n"
			"\t\ttype filter hook output priority filter; "
			"policy accept;\n"
			"\t\ttcp dport { 80, 443 } meta mark != 0x%x "
			"counter queue num %d bypass\n"
			"\t}\n"
			"}\n",
			NFT_TABLE_NAME, NFT_CHAIN_NAME, NFT_ANTILOOP_MARK,
			queue_num);

	if (written < 0 || (size_t)written >= out_size)
		return (0);

	return ((size_t)written);
}

static int	run_nft_with_stdin(const char *data, size_t len)
{
	int		pipefd[2];
	pid_t	pid;
	int		status;
	ssize_t	written;
	size_t	total;

	if (pipe(pipefd) < 0)
		return (-1);

	pid = fork();
	if (pid < 0)
	{
		close(pipefd[0]);
		close(pipefd[1]);
		return (-1);
	}

	if (pid == 0)
	{
		dup2(pipefd[0], STDIN_FILENO);
		close(pipefd[0]);
		close(pipefd[1]);
		/* Fixed argv, no shell involved: the ruleset text is built
		 * entirely from compile-time constants (table/chain names,
		 * an int queue number), never from external/user input, so
		 * there is nothing here for a shell to reinterpret even if
		 * one were used — but we avoid system()/popen() anyway. */
		execlp("nft", "nft", "-f", "-", (char *)NULL);
		_exit(127);
	}

	close(pipefd[0]);
	total = 0;
	while (total < len)
	{
		written = write(pipefd[1], data + total, len - total);
		if (written < 0)
		{
			if (errno == EINTR)
				continue ;
			break ;
		}
		total += (size_t)written;
	}
	close(pipefd[1]);

	if (waitpid(pid, &status, 0) < 0)
		return (-1);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return (-1);

	return (0);
}

int	nft_rules_remove(void)
{
	char	ruleset[128];
	int		len;

	len = snprintf(ruleset, sizeof(ruleset), "delete table inet %s\n",
			NFT_TABLE_NAME);
	if (len > 0)
		run_nft_with_stdin(ruleset, (size_t)len);

	/* Best-effort by contract: a missing table is not a failure, and
	 * cleanup must never be the reason shutdown gets stuck. */
	return (0);
}

int	nft_rules_apply(int queue_num)
{
	char	ruleset[512];
	size_t	len;

	nft_rules_remove();

	len = nft_rules_generate_create(ruleset, sizeof(ruleset), queue_num);
	if (len == 0)
		return (-1);

	return (run_nft_with_stdin(ruleset, len));
}
