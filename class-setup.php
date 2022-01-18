<?php

/**
 * Setup JWT Auth.
 *
 * @package jwt-auth
 */

namespace JWTOauthSystem;

/**
 * Setup JWT Auth.
 */
class OauthSystemSetup {
	/**
	 * Setup action & filter hooks.
	 */
	public function __construct() {
	
		$auth = new OauthSystem();

		add_action( 'rest_api_init', array( $auth, 'register_rest_routes' ) );
	}


}
