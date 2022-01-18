<?php return array(
    'root' => array(
        'pretty_version' => '1.0.0+no-version-set',
        'version' => '1.0.0.0',
        'type' => 'wordpress-plugin',
        'install_path' => __DIR__ . '/../../',
        'aliases' => array(),
        'reference' => NULL,
        'name' => 'usefulteam/jwt-auth',
        'dev' => true,
    ),
    'versions' => array(
        'firebase/php-jwt' => array(
            'pretty_version' => 'v5.5.0',
            'version' => '5.5.0.0',
            'type' => 'library',
            'install_path' => __DIR__ . '/../firebase/php-jwt',
            'aliases' => array(),
            'reference' => 'cf814442ce0e9eebe5317d61b63ccda4b85de67a',
            'dev_requirement' => false,
        ),
        'usefulteam/jwt-auth' => array(
            'pretty_version' => '1.0.0+no-version-set',
            'version' => '1.0.0.0',
            'type' => 'wordpress-plugin',
            'install_path' => __DIR__ . '/../../',
            'aliases' => array(),
            'reference' => NULL,
            'dev_requirement' => false,
        ),
    ),
);
