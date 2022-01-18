<?php

use Firebase\JWT\JWT;
use Firebase\JWT\ExpiredException;

class ValidateToken {

	public function validate_token($token = null){

		$oauth_client_id = get_option('OAUTH_CLIENT_KEY');
		$alg     = $this->get_alg();

		try {
			$payload = JWT::decode($token, $oauth_client_id,  array( $alg ) ); 
		} catch (Exception $e) {
	// echo 'Exception catched: ', $e->getMessage(), "\n"; 


			$oauth_invalid_token = array(
				'success'    => false,
				'statusCode' => 403,
				'code'       => 'oauth_invalid_token',
				'message'    => __( "Invalid token", 'jwt-auth' ),
			);

			echo  json_encode($oauth_invalid_token);

			exit();
		}


			// Check the user id existence in the token.
		if ( ! isset( $payload->data->user->id ) ) {
				// No user id in the token, abort!!
			
			$oauth_bad_request = array(
				'success'    => false,
				'statusCode' => 403,
				'code'       => 'oauth_bad_request',
				'message'    => __( 'User ID not found in the token.', 'jwt-auth' ),
				'data'       => array(),
			);
			echo json_encode($oauth_bad_request);
			exit();

		}

			// So far so good, check if the given user id exists in db.
		$user = get_user_by( 'id', $payload->data->user->id );

		if ( ! $user ) {
				// No user id in the token, abort!!

			$oauth_user_not_found = array(
				'success'    => false,
				'statusCode' => 403,
				'code'       => 'oauth_user_not_found',
				'message'    => __( "User doesn't exist", 'jwt-auth' ),
				'data'       => array(),
			);

			echo  json_encode($oauth_user_not_found);
			exit();

		}

			// Check extra condition if exists.
		$failed_msg = apply_filters( 'oauth_extra_token_check', '', $user, $token, $payload );

		if ( ! empty( $failed_msg ) ) {
				// No user id in the token, abort!!

			$oauth_obsolete_token = array(
				'success'    => false,
				'statusCode' => 403,
				'code'       => 'oauth_obsolete_token',
				'message'    => __( 'Token is obsolete', 'jwt-auth' ),
				'data'       => array(),
			);

			return json_encode($oauth_obsolete_token);
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


		return $response;
		
	} 


	public function get_alg() {
		return apply_filters( 'oauth_alg', 'HS256' );
	}


}
