# tw-escapist
A proof-of-concept WordPress plugin for detecting unescaped values in wpdb queries.

A quick overview of how it works:

TW_Escapist replaces the $wpdb global with a custom class, TW_DB.
TW_DB overrides _real_escape() to keep track of values that have been safely escaped.
TW_DB::get_unescaped_query_string() will take a raw SQL query, and convert those safely escaped literal values into %s and %d placeholders.

When a query is run, TW_Escapist::filter_query() calls get_unescaped_query_string(), then examines the "de-escaped" SQL for any remaining literal strings or numbers. Any remaining literals didn't pass through a proper escaping function.

Any queries that contain unescaped literals are logged. Currently it just uses error_log().

There are plenty of core functions that use direct calls to functions like absint() to sanitize query literals, rather than wpdb's escape functions. Escapist detects those values as unescaped, which is correct but not very helpful, as it creates a lot of noise. I've started whitelisting known safe queries (or portions of them) in remove_whitelisted_sql(), after first confirming that those core functions do in fact correctly escape inputs. That's  time consuming, but draws attention to code that fails to use explicit DB escaping.
