#include "discovery.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void	discovery_cache_init(t_discovery_cache *cache)
{
	cache->count = 0;
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

int	discovery_cache_set(t_discovery_cache *cache, const char *domain,
	const t_strategy_chain *chain, uint64_t fingerprint, int64_t now)
{
	size_t	i;

	i = 0;
	while (i < cache->count)
	{
		if (ieq(cache->entries[i].domain, domain))
		{
			cache->entries[i].chain = *chain;
			cache->entries[i].fingerprint = fingerprint;
			cache->entries[i].validated_at = now;
			return (0);
		}
		i++;
	}
	if (cache->count >= DISCOVERY_CACHE_MAX
		|| strlen(domain) >= STRATEGY_DOMAIN_MAX)
		return (-1);
	strcpy(cache->entries[cache->count].domain, domain);
	cache->entries[cache->count].chain = *chain;
	cache->entries[cache->count].fingerprint = fingerprint;
	cache->entries[cache->count].validated_at = now;
	cache->count++;
	return (0);
}

const t_discovery_cache_entry	*discovery_cache_lookup(
	const t_discovery_cache *cache, const char *domain,
	uint64_t current_fingerprint, int64_t ttl_seconds, int64_t now)
{
	size_t	i;

	if (current_fingerprint == NETFP_UNKNOWN)
		return (NULL);
	i = 0;
	while (i < cache->count)
	{
		if (ieq(cache->entries[i].domain, domain))
		{
			if (cache->entries[i].fingerprint != current_fingerprint)
				return (NULL);
			if (now - cache->entries[i].validated_at > ttl_seconds)
				return (NULL);
			if (now < cache->entries[i].validated_at)
				return (NULL); /* clock went backwards: don't trust it */
			return (&cache->entries[i]);
		}
		i++;
	}
	return (NULL);
}

size_t	discovery_cache_serialize(const t_discovery_cache *cache, char *out,
	size_t out_size)
{
	size_t	i;
	size_t	pos;
	char	chain_desc[64];
	int		written;

	pos = 0;
	i = 0;
	while (i < cache->count)
	{
		strategy_chain_describe(&cache->entries[i].chain, chain_desc,
			sizeof(chain_desc));
		written = snprintf(out + pos, pos < out_size ? out_size - pos : 0,
				"%s %016llx %lld %s\n", cache->entries[i].domain,
				(unsigned long long)cache->entries[i].fingerprint,
				(long long)cache->entries[i].validated_at, chain_desc);
		if (written < 0)
			break ;
		pos += (size_t)written;
		i++;
	}
	if (pos >= out_size)
		return (0);
	return (pos);
}

static void	trim(char *s)
{
	size_t	len;

	len = strlen(s);
	while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t'
			|| s[len - 1] == '\r' || s[len - 1] == '\n'))
	{
		s[len - 1] = '\0';
		len--;
	}
}

size_t	discovery_cache_parse(t_discovery_cache *cache, const char *text,
	size_t text_len)
{
	char				line[512];
	size_t				pos;
	size_t				line_len;
	size_t				skipped;
	char				domain[STRATEGY_DOMAIN_MAX];
	char				fp_hex[32];
	char				ts_dec[32];
	char				chain_str[64];
	unsigned long long	fp;
	long long			ts;
	t_strategy_chain	chain;

	skipped = 0;
	pos = 0;
	while (pos < text_len)
	{
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

		if (sscanf(line, "%255s %31s %31s %63s", domain, fp_hex, ts_dec,
				chain_str) != 4)
		{
			skipped++;
			continue ;
		}
		if (sscanf(fp_hex, "%llx", &fp) != 1
			|| sscanf(ts_dec, "%lld", &ts) != 1
			|| strategy_chain_from_string(chain_str, &chain) != 0)
		{
			skipped++;
			continue ;
		}
		if (discovery_cache_set(cache, domain, &chain,
				(uint64_t)fp, (int64_t)ts) < 0)
			skipped++;
	}
	return (skipped);
}

int	discovery_cache_load_file(t_discovery_cache *cache, const char *path)
{
	FILE	*f;
	char	buf[16384];
	size_t	n;

	discovery_cache_init(cache);
	f = fopen(path, "r");
	if (f == NULL)
		return (0);
	n = fread(buf, 1, sizeof(buf) - 1, f);
	if (ferror(f))
	{
		fclose(f);
		return (-1);
	}
	fclose(f);
	buf[n] = '\0';
	discovery_cache_parse(cache, buf, n);
	return (0);
}

int	discovery_cache_save_file(const t_discovery_cache *cache,
	const char *path)
{
	char	buf[16384];
	size_t	written;
	FILE	*f;

	written = discovery_cache_serialize(cache, buf, sizeof(buf));
	if (written == 0 && cache->count > 0)
		return (-1);
	f = fopen(path, "w");
	if (f == NULL)
		return (-1);
	if (fwrite(buf, 1, written, f) != written)
	{
		fclose(f);
		return (-1);
	}
	return (fclose(f) == 0 ? 0 : -1);
}

const char	*strategy_source_name(t_strategy_source s)
{
	if (s == STRATEGY_SOURCE_MANUAL)
		return ("manual");
	if (s == STRATEGY_SOURCE_AUTO)
		return ("auto-discovery");
	return ("default");
}

t_strategy_source	strategy_resolve_chain(const t_strategy_config *cfg,
	const t_discovery_cache *cache, uint64_t fingerprint, int64_t now,
	const char *domain, t_strategy_chain *out,
	const t_discovery_cache_entry **entry_out)
{
	const t_discovery_cache_entry	*entry;

	if (entry_out != NULL)
		*entry_out = NULL;
	if (strategy_has_explicit_rule(cfg, domain, out))
		return (STRATEGY_SOURCE_MANUAL);
	if (cache != NULL)
	{
		entry = discovery_cache_lookup(cache, domain, fingerprint,
				DISCOVERY_CACHE_DEFAULT_TTL_SECONDS, now);
		if (entry != NULL)
		{
			*out = entry->chain;
			if (entry_out != NULL)
				*entry_out = entry;
			return (STRATEGY_SOURCE_AUTO);
		}
	}
	out->action_count = 1;
	out->actions[0] = cfg->default_strategy;
	return (STRATEGY_SOURCE_DEFAULT);
}
