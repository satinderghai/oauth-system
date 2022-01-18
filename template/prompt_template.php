<?php
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

?>

<style>
  body {
    background: #ecf0f1;
  }

  .main-wrapper {
    width: 100%;
    max-width: 320px;
    background: #FFFFFF;
    margin: 0 auto;
    padding: 1em;
    box-sizing: content-box;
    position: relative;

    height: 300px;
    position: relative;
    /*top: 50%;*/
    transform: translateY(-50%);
    margin-top: 205px;
  }

  input[type="submit"] {
    border: none;
    outline: none;
    width: 100%;
    display: block;
    text-align: center;
    text-transform: uppercase;
    padding: 1em;
    font-size: 14px;
    cursor: pointer;
  }

  .allow-btn {
    background: #2980b9;
    color: #FFFFFF;
  }

  .request-description {
    margin-bottom: 1.5em;
    display: block;
  }

  .request-notice {
    color: #cccccc;
    position: absolute;
    bottom: 0px;
  }
</style>

<div class="main-wrapper">
  <h2>Allow Access?</h2>
  <p class="request-description"><strong>southpigalles</strong> would like to access and/or
  update your account.</p>
  <form action="" method="post">
    <input type="hidden" id="nonce" name="nonce" value="b7b85f0502" /><input type="hidden" name="_wp_http_referer" value="/oauth/authorize/?response_type=code&amp;client_id=gU7hVrYpJ5YLjbJaZdv1ugHAEbYCcrKfE8WGhgTb&amp;prompt=consent" />       

    <input type="hidden" name="request-grant" value="1"/>
    <input type="hidden" name="user-response" value="allow"/>
    <input class="allow-btn" type="submit" value="Allow"/>
  </form>

  <form action="" method="post">
    <input type="hidden" id="nonce" name="nonce" value="b7b85f0502" />
    <input type="hidden" name="_wp_http_referer" value="/oauth/authorize/?response_type=code&amp;client_id=gU7hVrYpJ5YLjbJaZdv1ugHAEbYCcrKfE8WGhgTb&amp;prompt=consent" />  

    <input type="hidden" name="request-grant" value="1"/>
    <input type="hidden" name="user-response" value="deny"/>
    <input class="deny-btn" type="submit" value="Deny"/>
  </form>

  <p class="request-notice">You should only grant access to applications you trust with your account information.</p>
</div>



