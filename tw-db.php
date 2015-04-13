<?php

class TW_DB extends wpdb {
	public $escaped = array();
	
	public function __construct( $dbuser, $dbpassword, $dbname, $dbhost ) {
		
		// WP_Query uses sanitize_key() to escape some values like post types.
		// We need to filter that function in order to count those values as escaped.
		add_filter( 'sanitize_key', array($this, 'filter_sanitize_key') );
		
		return parent::__construct( $dbuser, $dbpassword, $dbname, $dbhost );
	}
	
	// Override _real_escape with a version that tracks escaped strings, so we can later figure out which parts of a query were escaped.
	function _real_escape( $string ) {
		$escaped =  parent::_real_escape( $string );
		
		if ( strlen( $escaped ) )
			$this->escaped[] = $escaped;
		
		return $escaped;
	}
	
	// Override query() to reset escaped values after the query is run
	public function query( $query ) {
		$result = parent::query( $query );
		$this->escaped = array();
		
		return $result;
	}
	
	// Take a raw query string, remove the parts that we know have been safely escaped, and return the rest.
	public function get_unescaped_query_string( $query ) {
		foreach ( $this->escaped as $key => $escaped ) {
			$c = 0;
			// Is it a string, surrounded by quotes?
			$offset = strpos( $query, "'" . $escaped . "'" );
			if ( $offset !== false ) {
				// Using strpos+substr_replace instead of str_replace in order to only replace the first occurrence.
				$query = substr_replace( $query, '%s', $offset, 2 + strlen( $escaped ) );
				$c = 1;
			} else {
				// Otherwise it's a number.
				// Note that there are cases where this could incorrectly replace a number that occurs within an unescaped string.
				// The result of that though should be to fail safely: it'll still correctly determine that there is unescaped data,
				// just be confused about where it occurs.
				$query = preg_replace( '/(^|[\s,])'.preg_quote($escaped, '/').'([\s,]|$)/', '$1%d$2', $query, 1, $c );
			}
			
			// Once an escaped string has been found, remove it.
			// This ensures we won't get a false positive if there's a subsequent query with the same string unescaped.
			if ( $c ) {
				unset( $this->escaped[ $key ] );
			} else {
				if ( $escaped == '1' || $escaped == '15' ) {
					error_log( "Didn't find '$escaped' in '$query'" );
				}
			}
		}
		
		return $query;
	}
	
	public function filter_sanitize_key( $value ) {
		$this->escaped[] = $value;
		return $value;
	}

}