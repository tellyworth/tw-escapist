<?php
/*
Plugin Name: Escapist
Description: Monitors wpdb queries for safe escaping.
Author: tellyworth
Version: 0.0
Author URI: http://flightpathblog.com/
License: GPLv2 or later
*/

// Ideas and snippets borrowed liberally from John Blackbourn's Query Monitor plugin.
// https://wordpress.org/plugins/query-monitor/
 

class TW_Escapist {
	protected function __construct() {
		add_action( 'plugins_loaded', array($this, 'action_plugins_loaded'), -1 );
		add_filter( 'query', array($this, 'filter_query') );
	}

	public static function init() {
		static $instance = null;
		
		if ( is_null( $instance ) ) {
			$instance = new TW_Escapist();
		}
		
		return $instance;
	}
	
	protected function log( $message ) {
		error_log( __CLASS__ . ': ' . $message );
		error_log( join("\n", $this->get_call_stack('TW_DB::query') ) );
	}
	
	protected function get_call_stack( $before_function = 'TW_Escapist::get_call_stack' ) {
		$backtrace = debug_backtrace();
		$stack = array();
		foreach ( $backtrace as $item ) {
			if ( empty( $item['class'] ) ) {
				$stack[] = $item['function'];
			} else {
				$stack[] = $item['class'] . '::' . $item['function'];
			}
		}
		
		if ( $before_function ) {
			$offset = array_search( $before_function, $stack );
			if ( $offset !== false )
				return array_slice( $stack, $offset + 1 );
		}
		
		return $stack;
	}
	
	public function action_plugins_loaded() {
		// Some hackery within.
		
		// Replace the $wpdb global with our own child class.
		// The proper way to do this is with a dropin, but to get started now we'll try this on-the-fly.
		require_once( dirname(__FILE__) . '/tw-db.php' );
		$GLOBALS['wpdb'] = new TW_DB( DB_USER, DB_PASSWORD, DB_NAME, DB_HOST );
		wp_set_wpdb_vars();
		
	}
	
	// Many core WP functions use methods other than wpdb->prepare() and friends to escape db values.
	// This whitelists certain SQL queries (or portions thereof) if the call stack shows the queries came via those trusted functions.
	public function remove_whitelisted_sql( $sql ) {
		global $wpdb;
		$stack = $this->get_call_stack( 'TW_DB::query' );
		
		// Called from get_option()?
		if ( $stack[0] === 'wpdb::get_row' && $stack[1] === 'get_option' ) {
			$sql = str_replace( 'SELECT option_value FROM wp_options WHERE option_name = %s LIMIT 1', '', $sql );
		}
		
		// Called from get_post()?
		if ( $stack[0] === 'wpdb::get_row' && $stack[1] === 'WP_Post::get_instance' && $stack[2] === 'get_post' ) {
			$sql = str_replace( 'SELECT * FROM wp_posts WHERE ID = %d LIMIT 1', '', $sql );
		}
		
		// Called from wp_unique_post_slug
		if ( $stack[0] === 'wpdb::get_var' && $stack[1] === 'wp_unique_post_slug' ) {
			$sql = str_replace( 'SELECT post_name FROM wp_posts WHERE post_name = %s AND post_type = %s AND ID != %d LIMIT 1', '', $sql );
		}
		
		// Called from WP_Query::get_posts
		if ( ($stack[0] === 'wpdb::get_results' || $stack[0] === 'wpdb::get_col') && $stack[1] === 'WP_Query::get_posts' ) {
			// 'true=true' won't be considered unescaped values
			$sql = str_replace( ' WHERE 1=1 ', ' WHERE true=true ', $sql );
			
			// post_status uses direct regex sanitizing, see https://build.trac.wordpress.org/changeset/17689
			$sql = preg_replace( '/[.]post_status (<>|=) \'[-a-z0-9_]+\'/', '.post_status $1 %s', $sql );
			
			// absint() used for pagination sanitizing
			$sql = preg_replace( '/ LIMIT \d+, \d+$/', ' LIMIT %d, %d', $sql );
			
			// absint() used for post ID sanitizing
			$sql = preg_replace( '/'.preg_quote( "{$wpdb->posts}.ID = ", '/').'\d+/', "{$wpdb->posts}.ID = %d", $sql );
		}

		// Called from WP_User_Query
		if ( ($stack[0] === 'wpdb::get_results' || $stack[0] === 'wpdb::get_col') && $stack[1] === 'WP_User_Query::query' ) {
			$sql = str_replace( ' WHERE 1=1 ', ' WHERE true=true ', $sql );
		}
		
		// Called from WP_Comment_Query
		if ( $stack[0] === 'wpdb::get_results' && $stack[1] === 'WP_Comment_Query::get_comments' ) {
			// hard-coded literals
			$sql = str_replace( 'comment_approved = \'0\'', 'comment_approved = %d', $sql );
			$sql = str_replace( 'comment_approved = \'1\'', 'comment_approved = %d', $sql );
		}
		
		if ( $stack[0] === 'wpdb::get_var' && $stack[1] === 'wp_enqueue_media' ) {
			// has hard-coded literal strings
			$sql = str_replace( 'WHERE post_type = \'attachment\'', 'WHERE post_type = %s', $sql );
			$sql = str_replace( 'AND post_mime_type LIKE \'video%\'', 'AND post_mime_type LIKE %s', $sql );
			$sql = str_replace( 'AND post_mime_type LIKE \'audio%\'', 'AND post_mime_type LIKE %s', $sql );
			$sql = str_replace( 'LIMIT 1', 'LIMIT %d', $sql );
		}
		
		// Taxonomy functions generally use taxonomy_exists() to sanitize taxonomy literal values
		if ( ($stack[0] === 'wpdb::get_results' || $stack[0] === 'wpdb::get_col') && ($stack[1] === 'get_terms' || $stack[1] === 'wp_get_object_terms') ) {
			foreach ( get_taxonomies() as $tax_name ) {
				$sql = str_replace( "'$tax_name'", '%s', $sql );
			}
			
			$sql = preg_replace( '/ LIMIT \d+, \d+$/', ' LIMIT %d, %d', $sql );
			$sql = preg_replace( '/ LIMIT \d+$/', ' LIMIT %d', $sql );
			
			$sql = str_replace( ' AND tt.count > 0', ' AND tt.count > %d', $sql );
			
			// wp_get_object_terms uses intval to sanitize object_ids
			$sql = preg_replace( '/tr[.]object_id IN [(][\d, ]+[)]/', 'tr.object_id IN (%d)', $sql );

		}
		
		if ( $stack[0] === 'wpdb::get_var' && $stack[1] === '_update_post_term_count' ) {
			// has hard-coded literal strings
			$sql = str_replace( 'post_status = \'publish\'', 'post_status = %s', $sql );
		}
		
		// Called from get_pending_comments_num
		if ( $stack[0] === 'wpdb::get_results' && $stack[1] === 'get_pending_comments_num' ) {
			// intval escaping used, just assume that the query is ok.
			$sql = '';
		}
		
		return $sql;
	}
	
	public function filter_query( $sql ) {
		global $wpdb;
		
		// Don't attempt this during plugin activation
		if ( is_a( $wpdb, 'TW_DB' ) ) {
			// Get a copy of the query with all the escaped literal values removed. Note that we leave $sql unmodified.
			$_sql = $wpdb->get_unescaped_query_string( $sql );
			
			// Some core functions use unescaped literals in queries, such as " .. LIMIT 1".
			// Eliminate these so as not to cause false positives.
			$_sql = $this->remove_whitelisted_sql( $_sql );
			
			// Empty strings are ok.
			$_sql = str_replace( "''", '%s', $_sql );
			$_sql = str_replace( '""', '%s', $_sql );
			
			// Does the query still contain anything that looks like a literal value? If so, it was unescaped.
			
			if ( preg_match( '/\s[_nN]\w*\'/', $_sql ) ) {
				$this->log( 'Query contains unescaped value with _charset_name: ' . $_sql );
			}
			
			if ( preg_match( '/[\'"]/', $_sql ) ) {
				$this->log( 'Query contains unescaped string: ' . $_sql );
			}
			
			if ( preg_match( '/[-+\s]\d/', $_sql ) ) {
				$this->log( 'Query contains unescaped numeric literal: ' . $_sql );
			}
			
			if ( preg_match( '/\s[xX]\'/', $_sql ) ) {
				$this->log( 'Query contains unescaped hex value: ' . $_sql );
			}

			if ( preg_match( '/\s[bB]\'/', $_sql ) ) {
				$this->log( 'Query contains unescaped bitfield value: ' . $_sql );
			}
			
		}
		
		
		return $sql; // unmodified.
	}
}

TW_Escapist::init();