#include "discovery.h"

#include <string.h>

const t_strategy_chain	g_discovery_ladder[DISCOVERY_LADDER_LEN] = {
	{{STRATEGY_PASS, STRATEGY_PASS}, 1},
	{{STRATEGY_SPLIT, STRATEGY_PASS}, 1},
	{{STRATEGY_FAKE, STRATEGY_PASS}, 1},
	{{STRATEGY_DISORDER, STRATEGY_PASS}, 1},
	{{STRATEGY_FRAGMENT, STRATEGY_PASS}, 1},
	{{STRATEGY_FAKE, STRATEGY_SPLIT}, 2},
	{{STRATEGY_SPLIT, STRATEGY_FAKE}, 2},
};

const char	*probe_result_name(t_probe_result r)
{
	if (r == PROBE_SUCCESS)
		return ("success");
	if (r == PROBE_REMOTE_REJECTED)
		return ("remote_rejected");
	if (r == PROBE_LOCAL_ERROR)
		return ("local_error");
	if (r == PROBE_TIMEOUT)
		return ("timeout");
	return ("unknown");
}

int	discovery_run(const char *domain, t_prober_fn prober, void *userdata,
	int timeout_ms, t_strategy_chain *out_chain,
	t_probe_result *out_last_result)
{
	size_t			ladder_idx;
	int				attempt;
	t_probe_result	result;

	result = PROBE_LOCAL_ERROR;
	ladder_idx = 0;
	while (ladder_idx < DISCOVERY_LADDER_LEN)
	{
		attempt = 0;
		while (attempt < DISCOVERY_MAX_ATTEMPTS_PER_CANDIDATE)
		{
			result = prober(domain, &g_discovery_ladder[ladder_idx],
					timeout_ms, userdata);
			if (result == PROBE_SUCCESS)
			{
				*out_chain = g_discovery_ladder[ladder_idx];
				if (out_last_result != NULL)
					*out_last_result = result;
				return (1);
			}
			/* A local error means the attempt itself never ran (no
			 * network evidence either way) — retrying the exact same
			 * candidate immediately is unlikely to help and just adds
			 * load, so move on to the next candidate rather than
			 * spending the bounded retry budget on it. */
			if (result == PROBE_LOCAL_ERROR)
				break ;
			attempt++;
		}
		ladder_idx++;
	}
	if (out_last_result != NULL)
		*out_last_result = result;
	return (0);
}

t_probe_result	probe_classify_openssl_output(const char *out)
{
	if (strstr(out, "CONNECTED(") == NULL)
		return (PROBE_LOCAL_ERROR);
	if (strstr(out, "Verify return code:") == NULL)
		return (PROBE_REMOTE_REJECTED);
	if (strstr(out, "Verify return code: 0 (ok)") == NULL)
		return (PROBE_REMOTE_REJECTED);
	return (PROBE_SUCCESS);
}
