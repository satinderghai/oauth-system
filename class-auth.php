<?php
/**
 * Setup JWT-Auth.
 *
 * @package jwt-auth
 */

namespace JWTOauthSystem;

use Exception;

use WP_Error;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;

use Firebase\JWT\JWT;

/**
 * The public-facing functionality of the plugin.
 */
class OauthSystem {
	/**
	 * The namespace to add to the api calls.
	 *
	 * @var string The namespace to add to the api call
	 */
	private $namespace;

	/**
	 * Store errors to display if the JWT is wrong
	 *
	 * @var WP_REST_Response
	 */
	private $jwt_error = null;

	/**
	 * Collection of translate-able messages.
	 *
	 * @var array
	 */
	private $messages = array();

	/**
	 * The REST API slug.
	 *
	 * @var string
	 */
	private $rest_api_slug = 'wp-json';

	/**
	 * Setup action & filter hooks.
	 */
	public function __construct() {
		$this->namespace = 'oauth';
		$this->messages = array(
			'oauth_no_auth_header'  => __( 'Authorization header not found.', 'jwt-auth' ),
			'oauth_bad_auth_header' => __( 'Authorization header malformed.', 'jwt-auth' ),
		);
	}

	/**
	 * Add the endpoints to the API
	 */
	public function register_rest_routes() {
		register_rest_route(
			$this->namespace,
			'token',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'get_token' ),
				'permission_callback' => '__return_true',
			)
		);



		register_rest_route(
			'wc/v3',
			'infos-user',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'validate_token_service' ),
				'permission_callback' => '__return_true',
			)
		);

	}

		/**
	 * Get token by sending POST request to jwt-auth/v1/token.
	 *
	 * @param WP_REST_Request $request The request.
	 * @return WP_REST_Response The response.
	 */
		public function get_token( WP_REST_Request $request ) {

			$oauth_client_id = get_option('OAUTH_CLIENT_KEY');
			$oauth_secret_id = get_option('OAUTH_SECRET_KEY');
			$client_id = $request->get_param( 'client_id' );
			$client_secret = $request->get_param( 'client_secret' );
			$grant_type    = $request->get_param( 'grant_type' );
			$code    = $request->get_param( 'code' );
			$additional_info    = $request->get_param( 'additional_info' );

			if($grant_type == 'CUSTOM_ACCESS_TOKEN'){

				if(empty($code)){
					return new WP_REST_Response(
						array(
							'success'    => false,
							'statusCode' => 403,
							'code'       => 'oauth_bad_config',
							'message'    => __( 'Code is required', 'oauth' ),
							'data'       => array(),
						),
						403
					);
				}

				if ( $oauth_client_id !=  $client_id) {
					return new WP_REST_Response(
						array(
							'success'    => false,
							'statusCode' => 403,
							'code'       => 'oauth_bad_config',
							'message'    => __( 'Client id is not valid', 'oauth' ),
							'data'       => array(),
						),
						403
					);
				}

				if ( $oauth_secret_id !=  $client_secret) {
					return new WP_REST_Response(
						array(
							'success'    => false,
							'statusCode' => 403,
							'code'       => 'oauth_bad_config',
							'message'    => __( 'Secret id is not valid', 'oauth' ),
							'data'       => array(),
						),
						403
					);
				}


				$apiusers = get_users( array(
					'meta_key' => 'jwtOauthCode', 
					'meta_value' => $code
				) );

				if(isset($apiusers[0]->ID)){

		// First thing, check the secret key if not exist return a error.


					// $user = $this->authenticate_user( $username, $password, $custom_auth );

					$user = $apiusers[0];

		// If the authentication is failed return error response.
					if ( is_wp_error( $user ) ) {
						$error_code = $user->get_error_code();

						return new WP_REST_Response(
							array(
								'success'    => false,
								'statusCode' => 403,
								'code'       => $error_code,
								'message'    => strip_tags( $user->get_error_message( $error_code ) ),
								'data'       => array(),
							),
							403
						);
					}

						// Save additional info for user
					
					if(isset($additional_info) && !empty($user)){
						$array_additional_info = json_decode($additional_info, true);
						foreach ($array_additional_info as $info_key => $info_value) {								
							update_user_meta( $user->ID, $info_key, $info_value );
						}
					}


		// Valid credentials, the user exists, let's generate the token.
					return $this->generate_token( $user, false );
				}else{
					return new WP_REST_Response(
						array(
							'success'    => false,
							'statusCode' => 403,
							'code'       => 'oauth_bad_config',
							'message'    => __( 'Code not valid', 'oauth' ),
							'data'       => array(),
						),
						403
					);
				}
				

			}

			if($grant_type == 'REGULAR_ACCESS_TOKEN'){

				if ( $oauth_client_id !=  $client_id) {
					return new WP_REST_Response(
						array(
							'success'    => false,
							'statusCode' => 403,
							'code'       => 'oauth_bad_config',
							'message'    => __( 'Client id is not valid', 'oauth' ),
							'data'       => array(),
						),
						403
					);
				}

				if ( $oauth_secret_id !=  $client_secret) {
					return new WP_REST_Response(
						array(
							'success'    => false,
							'statusCode' => 403,
							'code'       => 'oauth_bad_config',
							'message'    => __( 'Secret id is not valid', 'oauth' ),
							'data'       => array(),
						),
						403
					);
				}

		// Save additional info for user

				if(isset($additional_info) && !empty($user)){
					$array_additional_info = json_decode($additional_info, true);
					foreach ($array_additional_info as $info_key => $info_value) {								
						update_user_meta( $user->ID, $info_key, $info_value );
					}
				}


		// Valid credentials, the user exists, let's generate the token.
				return $this->generate_token_service();

			}
		}

		/**
	 * Generate token
	 *
	 * @param WP_User $user The WP_User object.
	 * @param bool    $return_raw Whether or not to return as raw token string.
	 *
	 * @return WP_REST_Response|string Return as raw token string or as a formatted WP_REST_Response.
	 */
		public function generate_token( $user, $return_raw = true ) {
			$oauth_client_id = get_option('OAUTH_CLIENT_KEY');
			$issued_at  = time();
			$not_before = $issued_at;
			$not_before = apply_filters( 'oauth_not_before', $not_before, $issued_at );
			$expire     = $issued_at + ( DAY_IN_SECONDS * 7 );
			$expire     = apply_filters( 'oauth_expire', $expire, $issued_at );

			$payload = array(
				'iss'  => $this->get_iss(),
				'iat'  => $issued_at,
				'nbf'  => $not_before,
				'exp'  => $expire,
				'data' => array(
					'user' => array(
						'id' => $user->ID,
					),
				),
			);

			$alg = $this->get_alg();

		// Let the user modify the token data before the sign.
			$token = JWT::encode( apply_filters( 'oauth_payload', $payload, $user ), $oauth_client_id, $alg );

		// If return as raw token string.
			if ( $return_raw ) {
				return $token;
			}

		// The token is signed, now create object with basic info of the user.
			$response = array(
				'success'    => true,
				'statusCode' => 200,
				'expires_in' => $expire,
				// 'token_type' => "Bearer",
				'jwt_token' => $token,
			);

		// Let the user modify the data before send it back.
			return apply_filters( 'oauth_valid_credential_response', $response, $user );
		}


		/**
	 * Generate token Service
	 *
	 * @param WP_User $user The WP_User object.
	 * @param bool    $return_raw Whether or not to return as raw token string.
	 *
	 * @return WP_REST_Response|string Return as raw token string or as a formatted WP_REST_Response.
	 */
		public function generate_token_service() {
			$oauth_client_id = get_option('OAUTH_CLIENT_KEY');
			$issued_at  = time();
			$not_before = $issued_at;
			$not_before = apply_filters( 'oauth_not_before', $not_before, $issued_at );
			$expire     = $issued_at + ( DAY_IN_SECONDS * 7 );
			$expire     = apply_filters( 'oauth_expire', $expire, $issued_at );

			$payload = array(
				'iss'  => $this->get_iss(),
				'iat'  => $issued_at,
				'nbf'  => $not_before,
				'exp'  => $expire,
			);

			$alg = $this->get_alg();

		// Let the user modify the token data before the sign.
			$token = JWT::encode(apply_filters( 'oauth_payload', $payload, "REGULAR_ACCESS_TOKEN" ), $oauth_client_id, $alg );


		// The token is signed, now create object with basic info of the user.
			$response = array(
				'success'    => true,
				'statusCode' => 200,
				'expires_in' => $expire,
				'token_type' => "Bearer",
				'jwt_token' => $token,
			);

			update_option( 'REST_CRON_REGULAR_ACCESS_TOKEN', $response );

		// Let the user modify the data before send it back.
			return apply_filters( 'oauth_valid_credential_response', $response, "REGULAR_ACCESS_TOKEN" );


		}

		public function get_iss() {
			return apply_filters( 'oauth_iss', get_bloginfo( 'url' ) );
		}


		/**
	 * Get the supported jwt auth signing algorithm.
	 *
	 * @see https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40
	 *
	 * @return string $alg
	 */
		public function get_alg() {
			return apply_filters( 'oauth_alg', 'HS256' );
		}


			/**
	 * Main validation function, this function try to get the Autentication
	 * headers and decoded.
	 *
	 * @param bool $return_response Either to return full WP_REST_Response or to return the payload only.
	 *
	 * @return WP_REST_Response | Array Returns WP_REST_Response or token's $payload.
	 */
			public function validate_token( $return_response = true ) {
		/**
		 * Looking for the HTTP_AUTHORIZATION header, if not present just
		 * return the user.
		 */

		
		$headerkey = apply_filters( 'oauth_authorization_header', 'HTTP_AUTHORIZATION' );
		$auth      = isset( $_SERVER[ $headerkey ] ) ? $_SERVER[ $headerkey ] : false;

		// Double check for different auth header string (server dependent).
		if ( ! $auth ) {
			$auth = isset( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) ? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] : false;
		}

		if ( ! $auth ) {
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 403,
					'code'       => 'oauth_no_auth_header',
					'message'    => $this->messages['oauth_no_auth_header'],
					'data'       => array(),
				)
			);
		}

		/**
		 * The HTTP_AUTHORIZATION is present, verify the format.
		 * If the format is wrong return the user.
		 */
		list($token) = sscanf( $auth, 'Bearer %s' );

		if ( ! $token ) {
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 403,
					'code'       => 'oauth_bad_auth_header',
					'message'    => $this->messages['oauth_bad_auth_header'],
					'data'       => array(),
				)
			);
		}

		// Get the Secret Key.
		// $oauth_client_id = defined( 'OAUTH_CLIENT_KEY' ) ? OAUTH_CLIENT_KEY : false;
		$oauth_client_id = get_option('OAUTH_CLIENT_KEY');

		if ( ! $oauth_client_id ) {
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 403,
					'code'       => 'oauth_bad_config',
					'message'    => __( 'JWT is not configured properly.', 'jwt-auth' ),
					'data'       => array(),
				),
				403
			);
		}

		// Try to decode the token.
		try {
			$alg     = $this->get_alg();
			$payload = JWT::decode( $token, $oauth_client_id, array( $alg ) );

			// The Token is decoded now validate the iss.
			if ( $payload->iss !== $this->get_iss() ) {
				// The iss do not match, return error.
				return new WP_REST_Response(
					array(
						'success'    => false,
						'statusCode' => 403,
						'code'       => 'oauth_bad_iss',
						'message'    => __( 'The iss do not match with this server.', 'jwt-auth' ),
						'data'       => array(),
					),
					403
				);
			}

			// Check the user id existence in the token.
			if ( ! isset( $payload->data->user->id ) ) {
				// No user id in the token, abort!!
				return new WP_REST_Response(
					array(
						'success'    => false,
						'statusCode' => 403,
						'code'       => 'oauth_bad_request',
						'message'    => __( 'User ID not found in the token.', 'jwt-auth' ),
						'data'       => array(),
					),
					403
				);
			}

			// So far so good, check if the given user id exists in db.
			$user = get_user_by( 'id', $payload->data->user->id );

			if ( ! $user ) {
				// No user id in the token, abort!!
				return new WP_REST_Response(
					array(
						'success'    => false,
						'statusCode' => 403,
						'code'       => 'oauth_user_not_found',
						'message'    => __( "User doesn't exist", 'jwt-auth' ),
						'data'       => array(),
					),
					403
				);
			}

			// Check extra condition if exists.
			$failed_msg = apply_filters( 'oauth_extra_token_check', '', $user, $token, $payload );

			if ( ! empty( $failed_msg ) ) {
				// No user id in the token, abort!!
				return new WP_REST_Response(
					array(
						'success'    => false,
						'statusCode' => 403,
						'code'       => 'oauth_obsolete_token',
						'message'    => __( 'Token is obsolete', 'jwt-auth' ),
						'data'       => array(),
					),
					403
				);
			}

			// Everything looks good, return the payload if $return_response is set to false.
			if ( ! $return_response ) {
				return $payload;
			}

			$response = array(
				'success'    => true,
				'statusCode' => 200,
				'code'       => 'oauth_valid_token',
				'message'    => __( 'Token is valid', 'jwt-auth' ),
				'data'       => array(
					'id'          => $user->ID,
					'email'       => $user->user_email,
					'nicename'    => $user->user_nicename,
					'firstName'   => $user->first_name,
					'lastName'    => $user->last_name,
					'displayName' => $user->display_name,
				),
			);

			$response = apply_filters( 'oauth_valid_token_response', $response, $user, $token, $payload );

			// Otherwise, return success response.
			return new WP_REST_Response( $response );
		} catch ( Exception $e ) {
			// Something is wrong when trying to decode the token, return error response.
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 403,
					'code'       => 'oauth_invalid_token',
					'message'    => $e->getMessage(),
					'data'       => array(),
				),
				403
			);
		}
	}


			/**
	 * Main validation function, this function try to get the Autentication
	 * headers and decoded.
	 *
	 * @param bool $return_response Either to return full WP_REST_Response or to return the payload only.
	 *
	 * @return WP_REST_Response | Array Returns WP_REST_Response or token's $payload.
	 */
			public function validate_token_service( $return_response = true ) {

				$headerkey = apply_filters( 'oauth_authorization_header', 'HTTP_AUTHORIZATION' );
				$auth      = isset( $_SERVER[ $headerkey ] ) ? $_SERVER[ $headerkey ] : false;

		// Double check for different auth header string (server dependent).
				if ( ! $auth ) {
					$auth = isset( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) ? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] : false;
				}

				if ( ! $auth ) {
					return new WP_REST_Response(
						array(
							'success'    => false,
							'statusCode' => 403,
							'code'       => 'oauth_no_auth_header',
							'message'    => $this->messages['oauth_no_auth_header'],
							'data'       => array(),
						)
					);
				}

		/**
		 * The HTTP_AUTHORIZATION is present, verify the format.
		 * If the format is wrong return the user.
		 */
		list($token) = sscanf( $auth, 'Bearer %s' );

		if ( ! $token ) {
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 403,
					'code'       => 'oauth_bad_auth_header',
					'message'    => $this->messages['oauth_bad_auth_header'],
					'data'       => array(),
				)
			);
		}

		// Get the Secret Key.
		// $oauth_client_id = defined( 'OAUTH_CLIENT_KEY' ) ? OAUTH_CLIENT_KEY : false;
		$oauth_client_id = get_option('OAUTH_CLIENT_KEY');
		if ( ! $oauth_client_id ) {
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 403,
					'code'       => 'oauth_bad_config',
					'message'    => __( 'JWT is not configured properly.', 'jwt-auth' ),
					'data'       => array(),
				),
				403
			);
		}

		// Try to decode the token.
		try {
			$alg     = $this->get_alg();
			$payload = JWT::decode( $token, $oauth_client_id, array( $alg ) );

			// The Token is decoded now validate the iss.
			if ( $payload->iss !== $this->get_iss() ) {
				// The iss do not match, return error.
				return new WP_REST_Response(
					array(
						'success'    => false,
						'statusCode' => 403,
						'code'       => 'oauth_bad_iss',
						'message'    => __( 'The iss do not match with this server.', 'jwt-auth' ),
						'data'       => array(),
					),
					403
				);
			}

			// Everything looks good, return the payload if $return_response is set to false.
			if ( ! $return_response ) {
				return $payload;
			}

			$data = array();
			if(isset($_REQUEST)){
				$get_customer_information = $this->get_customer_information($_REQUEST);
				if($get_customer_information){
					$user = $get_customer_information->data;
					$data = array(
						'id'          => $user->ID,
						'email'       => $user->user_email,
						'nicename'    => $user->user_nicename,
						'displayName' => $user->display_name,
					);
				}
			}

			$response = array(
				'success'    => true,
				'statusCode' => 200,
				'code'       => 'oauth_valid_token',
				'message'    => __( 'Token is valid', 'jwt-auth' ),
				'data'       => $data,
			);

			$response = apply_filters( 'oauth_valid_token_response', $response, "REGULAR_ACCESS_TOKEN", $token, $payload );

			// Otherwise, return success response.
			return new WP_REST_Response( $response );
		} catch ( Exception $e ) {
			// Something is wrong when trying to decode the token, return error response.
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 403,
					'code'       => 'oauth_invalid_token',
					'message'    => "Invalid token",
					'data'       => array(),
				),
				403
			);
		}
	}

	// GET user details on user id based

	public function get_customer_information($request = null){
		$external_id = $request["external_id"]; 
		// $customer = get_user_meta ( $external_id);
		$customer = get_user_by('id', $external_id);

		return $customer;
	}

}
