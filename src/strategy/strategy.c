#include "strategy.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void	strategy_config_init(t_strategy_config *cfg)
{
	cfg->default_strategy = STRATEGY_PASS;
	cfg->rule_count = 0;
	cfg->fake_ttl = STRATEGY_DEFAULT_FAKE_TTL;
}

const char	*strategy_name(t_strategy s)
{
	if (s == STRATEGY_PASS)
		return ("pass");
	if (s == STRATEGY_SPLIT)
		return ("split");
	if (s == STRATEGY_DISORDER)
		return ("disorder");
	if (s == STRATEGY_FAKE)
		return ("fake");
	if (s == STRATEGY_FRAGMENT)
		return ("fragment");
	if (s == STRATEGY_TLSREC)
		return ("tlsrec");
	if (s == STRATEGY_TLSREC_SPLIT)
		return ("tlsrec-split");
	return ("pass");
}

static int	ieq(const char *a, const char *b)
{
	while (*a != '\0' && *b != '\0')
	{
		if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
			return (0);
		a++;
		b++;
	}
	return (*a == '\0' && *b == '\0');
}

/* True if `domain` ends with `suffix` (case-insensitive), matching
 * only on a label boundary — ".example.com" matches "sub.example.com"
 * and "example.com" itself, but never "notexample.com". */
static int	suffix_match(const char *domain, const char *suffix)
{
	size_t	dlen;
	size_t	slen;
	size_t	tail_start;

	dlen = strlen(domain);
	slen = strlen(suffix);
	if (slen == 0 || suffix[0] != '.' || slen > dlen + 1)
		return (0);
	if (slen == dlen + 1)
		return (ieq(domain, suffix + 1));
	tail_start = dlen - slen;
	return (ieq(domain + tail_start, suffix));
}

int	strategy_from_name(const char *name, t_strategy *out)
{
	if (ieq(name, "pass"))
		*out = STRATEGY_PASS;
	else if (ieq(name, "split"))
		*out = STRATEGY_SPLIT;
	else if (ieq(name, "disorder"))
		*out = STRATEGY_DISORDER;
	else if (ieq(name, "fake"))
		*out = STRATEGY_FAKE;
	else if (ieq(name, "fragment"))
		*out = STRATEGY_FRAGMENT;
	else if (ieq(name, "tlsrec"))
		*out = STRATEGY_TLSREC;
	else if (ieq(name, "tlsrec-split"))
		*out = STRATEGY_TLSREC_SPLIT;
	else
		return (-1);
	return (0);
}

/* The complete safe-combination whitelist. Every entry is checked as
 * an exact ordered sequence — order matters (fake+split and
 * split+fake are both listed and behave differently at execution
 * time; see nfqueue_engine.c). Kept as one explicit table rather than
 * general rules so adding a new combination is always a deliberate,
 * reviewable one-line change, never an accident of some general rule
 * matching more than intended. */
static int	chain_matches(const t_strategy_chain *chain,
	const t_strategy *pattern, size_t pattern_len)
{
	size_t	i;

	if (chain->action_count != pattern_len)
		return (0);
	i = 0;
	while (i < pattern_len)
	{
		if (chain->actions[i] != pattern[i])
			return (0);
		i++;
	}
	return (1);
}

int	strategy_chain_is_safe(const t_strategy_chain *chain)
{
	static const t_strategy	fake_split[2] = {STRATEGY_FAKE, STRATEGY_SPLIT};
	static const t_strategy	split_fake[2] = {STRATEGY_SPLIT, STRATEGY_FAKE};

	if (chain->action_count == 1)
		return (1);
	if (chain->action_count == 2)
	{
		if (chain_matches(chain, fake_split, 2))
			return (1);
		if (chain_matches(chain, split_fake, 2))
			return (1);
		return (0);
	}
	return (0);
}

int	strategy_chain_from_string(const char *s, t_strategy_chain *out)
{
	t_strategy_chain	chain;
	char				token[64];
	size_t				token_len;
	size_t				i;
	t_strategy			parsed;

	chain.action_count = 0;
	i = 0;
	while (1)
	{
		token_len = 0;
		while (s[i] != '\0' && s[i] != '+' && token_len < sizeof(token) - 1)
		{
			token[token_len] = s[i];
			token_len++;
			i++;
		}
		if (s[i] != '\0' && s[i] != '+')
			return (-1);
		token[token_len] = '\0';
		if (token_len == 0)
			return (-1);
		if (strategy_from_name(token, &parsed) != 0)
			return (-1);
		if (chain.action_count >= STRATEGY_CHAIN_MAX)
			return (-1);
		chain.actions[chain.action_count] = parsed;
		chain.action_count++;
		if (s[i] == '\0')
			break ;
		i++;
	}

	/* Normalize split+disorder to plain disorder: DISORDER's only
	 * correct construction already is "split, then reorder", so this specific
	 * two-action shape has no distinct safe meaning beyond the
	 * single-action DISORDER chain — collapsing it here means
	 * execution code never has to special-case it. */
	if (chain.action_count == 2 && chain.actions[0] == STRATEGY_SPLIT
		&& chain.actions[1] == STRATEGY_DISORDER)
	{
		chain.actions[0] = STRATEGY_DISORDER;
		chain.action_count = 1;
	}

	if (!strategy_chain_is_safe(&chain))
		return (-1);

	*out = chain;
	return (0);
}

void	strategy_chain_describe(const t_strategy_chain *chain,
	char *buf, size_t buf_size)
{
	size_t	i;
	size_t	pos;
	size_t	written;

	if (buf_size == 0)
		return ;
	pos = 0;
	i = 0;
	while (i < chain->action_count)
	{
		if (i > 0 && pos + 1 < buf_size)
			buf[pos++] = '+';
		written = 0;
		while (strategy_name(chain->actions[i])[written] != '\0'
			&& pos + 1 < buf_size)
		{
			buf[pos] = strategy_name(chain->actions[i])[written];
			pos++;
			written++;
		}
		i++;
	}
	buf[pos] = '\0';
}

/* Exact rules are checked first (in config order — since duplicates
 * are collapsed to last-write-wins at parse time, there's at most one
 * exact match per domain), then suffix rules (".example.com").
 * Deterministic: same config always yields the same decision for a
 * given hostname. Returns 0 (out untouched) if no rule matches — see
 * strategy_chain_for_domain() for the "fall through to default"
 * caller most callers want instead. */
int	strategy_has_explicit_rule(const t_strategy_config *cfg,
	const char *domain, t_strategy_chain *out)
{
	size_t	i;

	i = 0;
	while (i < cfg->rule_count)
	{
		if (cfg->rules[i].domain[0] != '.'
			&& ieq(cfg->rules[i].domain, domain))
		{
			*out = cfg->rules[i].chain;
			return (1);
		}
		i++;
	}
	i = 0;
	while (i < cfg->rule_count)
	{
		if (cfg->rules[i].domain[0] == '.'
			&& suffix_match(domain, cfg->rules[i].domain))
		{
			*out = cfg->rules[i].chain;
			return (1);
		}
		i++;
	}
	return (0);
}

void	strategy_chain_for_domain(const t_strategy_config *cfg,
	const char *domain, t_strategy_chain *out)
{
	if (strategy_has_explicit_rule(cfg, domain, out))
		return ;
	out->action_count = 1;
	out->actions[0] = cfg->default_strategy;
}

t_strategy	strategy_for_domain(const t_strategy_config *cfg,
	const char *domain)
{
	t_strategy_chain	chain;

	strategy_chain_for_domain(cfg, domain, &chain);
	return (chain.actions[0]);
}

static void	trim(char *s)
{
	size_t	len;
	size_t	start;

	start = 0;
	while (s[start] == ' ' || s[start] == '\t')
		start++;
	if (start > 0)
		memmove(s, s + start, strlen(s + start) + 1);
	len = strlen(s);
	while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t'
			|| s[len - 1] == '\r'))
	{
		s[len - 1] = '\0';
		len--;
	}
}

static int	parse_kv(char *line, char **key, char **value)
{
	char	*eq;

	eq = strchr(line, '=');
	if (eq == NULL)
		return (-1);
	*eq = '\0';
	*key = line;
	*value = eq + 1;
	trim(*key);
	trim(*value);
	if ((*key)[0] == '\0' || (*value)[0] == '\0')
		return (-1);
	return (0);
}

/* Adds/updates a domain rule. Duplicate exact-same-key entries are
 * deterministic: the last one in the file wins, overwriting the
 * earlier rule in place rather than appending a second, potentially
 * conflicting entry. */
static int	set_domain_rule(t_strategy_config *cfg, const char *domain,
	const t_strategy_chain *chain)
{
	size_t	i;

	i = 0;
	while (i < cfg->rule_count)
	{
		if (ieq(cfg->rules[i].domain, domain))
		{
			cfg->rules[i].chain = *chain;
			return (0);
		}
		i++;
	}
	if (cfg->rule_count >= STRATEGY_MAX_DOMAINS
		|| strlen(domain) >= STRATEGY_DOMAIN_MAX)
		return (-1);
	strcpy(cfg->rules[cfg->rule_count].domain, domain);
	cfg->rules[cfg->rule_count].chain = *chain;
	cfg->rule_count++;
	return (0);
}

static void	warn_skip(size_t line_no, const char *reason)
{
	fprintf(stderr, "[strategy] line %zu: %s, skipped\n", line_no, reason);
}

/* "fake_ttl = N": a top-level (outside [domains]) key, 1-255. Any
 * other value (0, non-numeric, out of range) is rejected and the
 * existing/default fake_ttl is kept — never silently set to 0, which
 * would make every FAKE decoy invalid at the very first hop and
 * defeat its purpose in a way that's hard to notice. */
static int	try_parse_fake_ttl(t_strategy_config *cfg, const char *key,
	const char *value)
{
	long	ttl;
	char	*end;

	if (!ieq(key, "fake_ttl"))
		return (0);
	ttl = strtol(value, &end, 10);
	if (*end != '\0' || ttl < 1 || ttl > 255)
		return (-1);
	cfg->fake_ttl = (uint8_t)ttl;
	return (1);
}

size_t	strategy_config_parse(t_strategy_config *cfg,
	const char *text, size_t text_len)
{
	char				line[512];
	size_t				pos;
	size_t				line_len;
	size_t				line_no;
	int					in_domains_section;
	size_t				skipped;
	char				*key;
	char				*value;
	t_strategy			parsed;
	t_strategy_chain	chain;
	int					ttl_result;

	in_domains_section = 0;
	skipped = 0;
	pos = 0;
	line_no = 0;

	while (pos < text_len)
	{
		line_no++;
		line_len = 0;
		while (pos < text_len && text[pos] != '\n'
			&& line_len < sizeof(line) - 1)
		{
			line[line_len] = text[pos];
			line_len++;
			pos++;
		}
		while (pos < text_len && text[pos] != '\n')
			pos++;
		if (pos < text_len)
			pos++;
		line[line_len] = '\0';

		trim(line);

		if (line[0] == '\0' || line[0] == '#' || line[0] == ';')
			continue ;

		if (line[0] == '[')
		{
			in_domains_section = (ieq(line, "[domains]"));
			if (!in_domains_section)
			{
				warn_skip(line_no, "unknown section (only [domains] exists)");
				skipped++;
			}
			continue ;
		}

		if (parse_kv(line, &key, &value) < 0)
		{
			warn_skip(line_no, "not a valid \"key = value\" line");
			skipped++;
			continue ;
		}

		if (!in_domains_section)
		{
			ttl_result = try_parse_fake_ttl(cfg, key, value);
			if (ttl_result == 1)
				continue ;
			if (ttl_result < 0)
			{
				warn_skip(line_no, "invalid fake_ttl (expected 1-255)");
				skipped++;
				continue ;
			}
		}

		if (!in_domains_section && ieq(key, "default"))
		{
			if (strategy_from_name(value, &parsed) == 0)
				cfg->default_strategy = parsed;
			else
			{
				warn_skip(line_no, "unknown strategy name");
				skipped++;
			}
			continue ;
		}

		if (in_domains_section)
		{
			if (strategy_chain_from_string(value, &chain) != 0)
			{
				warn_skip(line_no,
					"unknown strategy name or unsafe/unsupported "
					"combination");
				skipped++;
				continue ;
			}
			if (set_domain_rule(cfg, key, &chain) < 0)
			{
				warn_skip(line_no, "too many rules or domain too long");
				skipped++;
			}
			continue ;
		}

		warn_skip(line_no, "key=value outside [domains], not \"default\"");
		skipped++;
	}

	return (skipped);
}
