<?php
/**
 * Plugin Name: Oauth system
 * Description: Auto login system
 * Version:     2.0.0
 * Author:      Jeremine
 */

defined( 'ABSPATH' ) || die( "Can't access directly" );

// Helper constants.
define( 'OAUTH_PLUGIN_DIR', rtrim( plugin_dir_path( __FILE__ ), '/' ) );
define( 'OAUTH_PLUGIN_URL', rtrim( plugin_dir_url( __FILE__ ), '/' ) );
define( 'OAUTH_PLUGIN_VERSION', '2.0.0' );

// Require composer.
require __DIR__ . '/vendor/autoload.php';

// Require classes.
require __DIR__ . '/class-auth.php';
require __DIR__ . '/validateToken.php';
require __DIR__ . '/class-setup.php';

new JWTOauthSystem\OauthSystemSetup();


/* Oauth Admin Page Code */
add_action('admin_menu', 'oauth_plugin_setup_menu');

function oauth_plugin_setup_menu(){
	add_menu_page( 'Oauth Server', 'Oauth Server', 'manage_options', 'oauth-settings', 'global_custom_options','dashicons-groups',3);

	add_action( 'admin_init', 'register_oauth_system_settings' );
}


function global_custom_options()
{
	?>
	<div class="wrap">
		<h2>Oauth Server Client Id And Secret Id</h2>
		<form method="post" action="options.php">
			<?php settings_fields( 'oauth-system-plugin-settings' ); ?>
			<?php do_settings_sections( 'oauth-system-plugin-settings' ); ?>
			<table class="form-table">
				<tr valign="top">
					<th scope="row">OAUTH CLIENT KEY:</th>
					<td><input type="text" name="OAUTH_CLIENT_KEY"  size="50" value="<?php echo esc_attr( get_option('OAUTH_CLIENT_KEY') ); ?>" /></td>
				</tr>
				
				<tr valign="top">
					<th scope="row">OAUTH SECRET KEY:</th>
					<td><input type="text" name="OAUTH_SECRET_KEY" size="50" value="<?php echo esc_attr( get_option('OAUTH_SECRET_KEY') ); ?>" /></td>
				</tr>
				
			</table>
			
			<?php submit_button(); ?>

		</form>
	</div>
	<?php
}
function register_oauth_system_settings() {
	//register our settings
	register_setting( 'oauth-system-plugin-settings', 'OAUTH_CLIENT_KEY' );
	register_setting( 'oauth-system-plugin-settings', 'OAUTH_SECRET_KEY' );
}
/* End of admin page */



function check_if_user_is_loggedin_function()
{

	if (isset($_REQUEST['response_type']) && isset($_REQUEST['client_id'])) {


		if ( is_user_logged_in() )
		{

			$client_id =  $_REQUEST['client_id'];

			if (  get_option( 'OAUTH_CLIENT_KEY' ) !=  $client_id) {
				echo  json_encode(
					array(
						'success'    => false,
						'statusCode' => 403,
						'code'       => 'oauth_bad_config',
						'message'    => __( 'Client id is not valid', 'oauth' ),
						'data'       => array(),
					)
				);
				exit();
			}else{

				include( plugin_dir_path( __FILE__ ) . 'template/prompt_template.php' );
				exit();
			}
		}else{
			auth_redirect();
		}

	}


	if (isset($_REQUEST['_wp_http_referer'])) {

		if(isset($_REQUEST['user-response'])){


			if($_REQUEST['user-response'] == 'allow'){

				$code = bin2hex(openssl_random_pseudo_bytes(16));
				
				update_user_meta( get_current_user_id(), 'jwtOauthCode', $code );

				wp_redirect( get_permalink( get_option('woocommerce_myaccount_page_id')).'?code='.$code );
				exit();
			}

			if($_REQUEST['user-response'] == 'deny'){
				wp_redirect( get_permalink( get_option('woocommerce_myaccount_page_id')).'?error=access_denied&error_description=The-user-denied-access-to-your-application' );
				exit();
			}
		}
	}

	if (isset($_REQUEST['jwt_token'])) {

		$OauthSystem = new ValidateToken();

		$data =  $OauthSystem->validate_token($_REQUEST['jwt_token']);
		if(isset($data['success'])){
			if($data['statusCode'] == 200){

				if($data['data']['email'] !== ""){
					$user = get_user_by('email', $data['data']['email']);
					clean_user_cache($user->ID);
					wp_clear_auth_cookie();
					wp_set_current_user ( $user->ID );
					wp_set_auth_cookie  ( $user->ID );

					wp_redirect( get_permalink( get_option('woocommerce_myaccount_page_id')));
					exit();
				} 
			}

		}

	}

}

add_action('init', 'check_if_user_is_loggedin_function'); 