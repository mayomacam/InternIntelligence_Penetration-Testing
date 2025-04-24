<?php return array (
  'api' => 
  array (
    'default_item_count' => 100,
    'max_item_count' => 500,
    'requests_per_minute' => 180,
  ),
  'app' => 
  array (
    'env' => 'production',
    'debug' => false,
    'revision_limit' => 100,
    'recycle_bin_lifetime' => 30,
    'upload_limit' => 50,
    'allow_content_scripts' => false,
    'allow_untrusted_server_fetching' => false,
    'allow_robots' => NULL,
    'url' => 'http://checker.htb',
    'iframe_hosts' => NULL,
    'iframe_sources' => 'https://*.draw.io https://*.youtube.com https://*.youtube-nocookie.com https://*.vimeo.com',
    'ssr_hosts' => '*',
    'ip_address_precision' => 4,
    'timezone' => 'UTC',
    'locale' => 'en',
    'default_locale' => 'en',
    'fallback_locale' => 'en',
    'faker_locale' => 'en_GB',
    'auto_detect_locale' => true,
    'key' => 'base64:A+Io9TrHdEwh5pyUfh9KJmLEw6ujrMd5uXPaWB4TnLw=',
    'cipher' => 'AES-256-CBC',
    'maintenance' => 
    array (
      'driver' => 'file',
    ),
    'providers' => 
    array (
      0 => 'Illuminate\\Auth\\AuthServiceProvider',
      1 => 'Illuminate\\Broadcasting\\BroadcastServiceProvider',
      2 => 'Illuminate\\Bus\\BusServiceProvider',
      3 => 'Illuminate\\Cache\\CacheServiceProvider',
      4 => 'Illuminate\\Foundation\\Providers\\ConsoleSupportServiceProvider',
      5 => 'Illuminate\\Cookie\\CookieServiceProvider',
      6 => 'Illuminate\\Database\\DatabaseServiceProvider',
      7 => 'Illuminate\\Encryption\\EncryptionServiceProvider',
      8 => 'Illuminate\\Filesystem\\FilesystemServiceProvider',
      9 => 'Illuminate\\Foundation\\Providers\\FoundationServiceProvider',
      10 => 'Illuminate\\Hashing\\HashServiceProvider',
      11 => 'Illuminate\\Mail\\MailServiceProvider',
      12 => 'Illuminate\\Notifications\\NotificationServiceProvider',
      13 => 'Illuminate\\Pagination\\PaginationServiceProvider',
      14 => 'Illuminate\\Pipeline\\PipelineServiceProvider',
      15 => 'Illuminate\\Queue\\QueueServiceProvider',
      16 => 'Illuminate\\Redis\\RedisServiceProvider',
      17 => 'Illuminate\\Auth\\Passwords\\PasswordResetServiceProvider',
      18 => 'Illuminate\\Session\\SessionServiceProvider',
      19 => 'Illuminate\\Validation\\ValidationServiceProvider',
      20 => 'Illuminate\\View\\ViewServiceProvider',
      21 => 'Barryvdh\\DomPDF\\ServiceProvider',
      22 => 'Barryvdh\\Snappy\\ServiceProvider',
      23 => 'Intervention\\Image\\ImageServiceProvider',
      24 => 'SocialiteProviders\\Manager\\ServiceProvider',
      25 => 'BookStack\\App\\Providers\\ThemeServiceProvider',
      26 => 'BookStack\\App\\Providers\\AppServiceProvider',
      27 => 'BookStack\\App\\Providers\\AuthServiceProvider',
      28 => 'BookStack\\App\\Providers\\EventServiceProvider',
      29 => 'BookStack\\App\\Providers\\RouteServiceProvider',
      30 => 'BookStack\\App\\Providers\\TranslationServiceProvider',
      31 => 'BookStack\\App\\Providers\\ValidationRuleServiceProvider',
      32 => 'BookStack\\App\\Providers\\ViewTweaksServiceProvider',
    ),
    'aliases' => 
    array (
      'App' => 'Illuminate\\Support\\Facades\\App',
      'Arr' => 'Illuminate\\Support\\Arr',
      'Artisan' => 'Illuminate\\Support\\Facades\\Artisan',
      'Auth' => 'Illuminate\\Support\\Facades\\Auth',
      'Blade' => 'Illuminate\\Support\\Facades\\Blade',
      'Broadcast' => 'Illuminate\\Support\\Facades\\Broadcast',
      'Bus' => 'Illuminate\\Support\\Facades\\Bus',
      'Cache' => 'Illuminate\\Support\\Facades\\Cache',
      'Config' => 'Illuminate\\Support\\Facades\\Config',
      'Cookie' => 'Illuminate\\Support\\Facades\\Cookie',
      'Crypt' => 'Illuminate\\Support\\Facades\\Crypt',
      'Date' => 'Illuminate\\Support\\Facades\\Date',
      'DB' => 'Illuminate\\Support\\Facades\\DB',
      'Eloquent' => 'Illuminate\\Database\\Eloquent\\Model',
      'Event' => 'Illuminate\\Support\\Facades\\Event',
      'File' => 'Illuminate\\Support\\Facades\\File',
      'Gate' => 'Illuminate\\Support\\Facades\\Gate',
      'Hash' => 'Illuminate\\Support\\Facades\\Hash',
      'Http' => 'Illuminate\\Support\\Facades\\Http',
      'Js' => 'Illuminate\\Support\\Js',
      'Lang' => 'Illuminate\\Support\\Facades\\Lang',
      'Log' => 'Illuminate\\Support\\Facades\\Log',
      'Mail' => 'Illuminate\\Support\\Facades\\Mail',
      'Notification' => 'Illuminate\\Support\\Facades\\Notification',
      'Password' => 'Illuminate\\Support\\Facades\\Password',
      'Queue' => 'Illuminate\\Support\\Facades\\Queue',
      'RateLimiter' => 'Illuminate\\Support\\Facades\\RateLimiter',
      'Redirect' => 'Illuminate\\Support\\Facades\\Redirect',
      'Request' => 'Illuminate\\Support\\Facades\\Request',
      'Response' => 'Illuminate\\Support\\Facades\\Response',
      'Route' => 'Illuminate\\Support\\Facades\\Route',
      'Schema' => 'Illuminate\\Support\\Facades\\Schema',
      'Session' => 'Illuminate\\Support\\Facades\\Session',
      'Storage' => 'Illuminate\\Support\\Facades\\Storage',
      'Str' => 'Illuminate\\Support\\Str',
      'URL' => 'Illuminate\\Support\\Facades\\URL',
      'Validator' => 'Illuminate\\Support\\Facades\\Validator',
      'View' => 'Illuminate\\Support\\Facades\\View',
      'Vite' => 'Illuminate\\Support\\Facades\\Vite',
      'Socialite' => 'Laravel\\Socialite\\Facades\\Socialite',
      'ImageTool' => 'Intervention\\Image\\Facades\\Image',
      'Activity' => 'BookStack\\Facades\\Activity',
      'Theme' => 'BookStack\\Facades\\Theme',
    ),
    'proxies' => '',
  ),
  'auth' => 
  array (
    'method' => 'standard',
    'auto_initiate' => false,
    'defaults' => 
    array (
      'guard' => 'standard',
      'passwords' => 'users',
    ),
    'guards' => 
    array (
      'standard' => 
      array (
        'driver' => 'session',
        'provider' => 'users',
      ),
      'ldap' => 
      array (
        'driver' => 'ldap-session',
        'provider' => 'external',
      ),
      'saml2' => 
      array (
        'driver' => 'async-external-session',
        'provider' => 'external',
      ),
      'oidc' => 
      array (
        'driver' => 'async-external-session',
        'provider' => 'external',
      ),
      'api' => 
      array (
        'driver' => 'api-token',
      ),
    ),
    'providers' => 
    array (
      'users' => 
      array (
        'driver' => 'eloquent',
        'model' => 'BookStack\\Users\\Models\\User',
      ),
      'external' => 
      array (
        'driver' => 'external-users',
        'model' => 'BookStack\\Users\\Models\\User',
      ),
    ),
    'passwords' => 
    array (
      'users' => 
      array (
        'provider' => 'users',
        'email' => 'emails.password',
        'table' => 'password_resets',
        'expire' => 60,
        'throttle' => 60,
      ),
    ),
    'password_timeout' => 10800,
  ),
  'broadcasting' => 
  array (
    'default' => 'null',
    'connections' => 
    array (
      'log' => 
      array (
        'driver' => 'log',
      ),
      'null' => 
      array (
        'driver' => 'null',
      ),
    ),
  ),
  'cache' => 
  array (
    'default' => 'file',
    'stores' => 
    array (
      'apc' => 
      array (
        'driver' => 'apc',
      ),
      'array' => 
      array (
        'driver' => 'array',
        'serialize' => false,
      ),
      'database' => 
      array (
        'driver' => 'database',
        'table' => 'cache',
        'connection' => NULL,
        'lock_connection' => NULL,
      ),
      'file' => 
      array (
        'driver' => 'file',
        'path' => '/opt/BookStack/storage/framework/cache',
      ),
      'memcached' => 
      array (
        'driver' => 'memcached',
        'options' => 
        array (
        ),
        'servers' => 
        array (
        ),
      ),
      'redis' => 
      array (
        'driver' => 'redis',
        'connection' => 'default',
        'lock_connection' => 'default',
      ),
      'octane' => 
      array (
        'driver' => 'octane',
      ),
    ),
    'prefix' => 'laravel_cache_',
  ),
  'clockwork' => 
  array (
    'enable' => false,
    'features' => 
    array (
      'cache' => 
      array (
        'enabled' => true,
        'collect_queries' => true,
        'collect_values' => false,
      ),
      'database' => 
      array (
        'enabled' => true,
        'collect_queries' => true,
        'collect_models_actions' => true,
        'collect_models_retrieved' => false,
        'slow_threshold' => NULL,
        'slow_only' => false,
        'detect_duplicate_queries' => false,
      ),
      'events' => 
      array (
        'enabled' => true,
        'ignored_events' => 
        array (
        ),
      ),
      'log' => 
      array (
        'enabled' => true,
      ),
      'notifications' => 
      array (
        'enabled' => true,
      ),
      'performance' => 
      array (
        'client_metrics' => true,
      ),
      'queue' => 
      array (
        'enabled' => true,
      ),
      'redis' => 
      array (
        'enabled' => true,
      ),
      'routes' => 
      array (
        'enabled' => false,
        'only_namespaces' => 
        array (
          0 => 'App',
        ),
      ),
      'views' => 
      array (
        'enabled' => true,
        'collect_data' => false,
        'use_twig_profiler' => false,
      ),
    ),
    'web' => true,
    'toolbar' => true,
    'requests' => 
    array (
      'on_demand' => false,
      'errors_only' => false,
      'slow_threshold' => NULL,
      'slow_only' => false,
      'sample' => false,
      'except' => 
      array (
        0 => '/horizon/.*',
        1 => '/telescope/.*',
        2 => '/_debugbar/.*',
      ),
      'only' => 
      array (
      ),
      'except_preflight' => true,
    ),
    'artisan' => 
    array (
      'collect' => false,
      'except' => 
      array (
      ),
      'only' => 
      array (
      ),
      'collect_output' => false,
      'except_laravel_commands' => true,
    ),
    'queue' => 
    array (
      'collect' => false,
      'except' => 
      array (
      ),
      'only' => 
      array (
      ),
    ),
    'tests' => 
    array (
      'collect' => false,
      'except' => 
      array (
      ),
    ),
    'collect_data_always' => false,
    'storage' => 'files',
    'storage_files_path' => '/opt/BookStack/storage/clockwork',
    'storage_files_compress' => false,
    'storage_sql_database' => '/opt/BookStack/storage/clockwork.sqlite',
    'storage_sql_table' => 'clockwork',
    'storage_expiration' => 10080,
    'authentication' => false,
    'authentication_password' => 'VerySecretPassword',
    'stack_traces' => 
    array (
      'enabled' => true,
      'limit' => 10,
      'skip_vendors' => 
      array (
      ),
      'skip_namespaces' => 
      array (
      ),
      'skip_classes' => 
      array (
      ),
    ),
    'serialization_depth' => 10,
    'serialization_blackbox' => 
    array (
      0 => 'Illuminate\\Container\\Container',
      1 => 'Illuminate\\Foundation\\Application',
    ),
    'register_helpers' => true,
    'headers' => 
    array (
    ),
    'server_timing' => 10,
  ),
  'database' => 
  array (
    'default' => 'mysql',
    'connections' => 
    array (
      'mysql' => 
      array (
        'driver' => 'mysql',
        'url' => NULL,
        'host' => 'localhost',
        'database' => 'bookstack_db',
        'username' => 'bookstack',
        'password' => 'pK8HK7IHCKLCNHUJ7',
        'unix_socket' => '',
        'port' => 3306,
        'charset' => 'utf8mb4',
        'collation' => 'utf8mb4_unicode_ci',
        'prefix' => '',
        'prefix_indexes' => true,
        'strict' => false,
        'engine' => NULL,
        'options' => 
        array (
        ),
      ),
      'mysql_testing' => 
      array (
        'driver' => 'mysql',
        'url' => NULL,
        'host' => '127.0.0.1',
        'database' => 'bookstack-test',
        'username' => 'bookstack-test',
        'password' => 'bookstack-test',
        'port' => 3306,
        'charset' => 'utf8mb4',
        'collation' => 'utf8mb4_unicode_ci',
        'prefix' => '',
        'prefix_indexes' => true,
        'strict' => false,
      ),
    ),
    'migrations' => 'migrations',
    'redis' => 
    array (
    ),
  ),
  'debugbar' => 
  array (
    'enabled' => false,
    'except' => 
    array (
      0 => 'telescope*',
    ),
    'storage' => 
    array (
      'enabled' => true,
      'driver' => 'file',
      'path' => '/opt/BookStack/storage/debugbar',
      'connection' => NULL,
      'provider' => '',
    ),
    'include_vendors' => true,
    'capture_ajax' => true,
    'add_ajax_timing' => false,
    'error_handler' => false,
    'clockwork' => false,
    'collectors' => 
    array (
      'phpinfo' => true,
      'messages' => true,
      'time' => true,
      'memory' => true,
      'exceptions' => true,
      'log' => true,
      'db' => true,
      'views' => true,
      'route' => true,
      'auth' => true,
      'gate' => true,
      'session' => true,
      'symfony_request' => true,
      'mail' => true,
      'laravel' => false,
      'events' => false,
      'default_request' => false,
      'logs' => false,
      'files' => false,
      'config' => false,
      'cache' => false,
      'models' => true,
    ),
    'options' => 
    array (
      'auth' => 
      array (
        'show_name' => true,
      ),
      'db' => 
      array (
        'with_params' => true,
        'backtrace' => true,
        'timeline' => false,
        'explain' => 
        array (
          'enabled' => false,
          'types' => 
          array (
            0 => 'SELECT',
          ),
        ),
        'hints' => true,
      ),
      'mail' => 
      array (
        'full_log' => false,
      ),
      'views' => 
      array (
        'data' => false,
      ),
      'route' => 
      array (
        'label' => true,
      ),
      'logs' => 
      array (
        'file' => NULL,
      ),
      'cache' => 
      array (
        'values' => true,
      ),
    ),
    'inject' => true,
    'route_prefix' => '_debugbar',
    'route_domain' => 'http://checker.htb',
  ),
  'dompdf' => 
  array (
    'show_warnings' => false,
    'public_path' => NULL,
    'convert_entities' => true,
    'options' => 
    array (
      'font_dir' => '/opt/BookStack/storage/fonts/',
      'font_cache' => '/opt/BookStack/storage/fonts/',
      'temp_dir' => '/tmp',
      'chroot' => '/opt/BookStack/public',
      'allowed_protocols' => 
      array (
        'file://' => 
        array (
          'rules' => 
          array (
          ),
        ),
        'http://' => 
        array (
          'rules' => 
          array (
          ),
        ),
        'https://' => 
        array (
          'rules' => 
          array (
          ),
        ),
      ),
      'log_output_file' => NULL,
      'enable_fontsubsetting' => false,
      'pdf_backend' => 'CPDF',
      'default_media_type' => 'print',
      'default_paper_size' => 'a4',
      'default_paper_orientation' => 'portrait',
      'default_font' => 'dejavu sans',
      'dpi' => 96,
      'enable_php' => false,
      'enable_javascript' => false,
      'enable_remote' => false,
      'font_height_ratio' => 1.1,
      'enable_css_float' => true,
      'enable_html5_parser' => true,
    ),
  ),
  'filesystems' => 
  array (
    'default' => 'local',
    'images' => 'local',
    'attachments' => 'local',
    'url' => false,
    'disks' => 
    array (
      'local' => 
      array (
        'driver' => 'local',
        'root' => '/opt/BookStack/public',
        'visibility' => 'public',
        'throw' => true,
      ),
      'local_secure_attachments' => 
      array (
        'driver' => 'local',
        'root' => '/opt/BookStack/storage/uploads/files/',
        'throw' => true,
      ),
      'local_secure_images' => 
      array (
        'driver' => 'local',
        'root' => '/opt/BookStack/storage/uploads/images/',
        'visibility' => 'public',
        'throw' => true,
      ),
      's3' => 
      array (
        'driver' => 's3',
        'key' => 'your-key',
        'secret' => 'your-secret',
        'region' => 'your-region',
        'bucket' => 'your-bucket',
        'endpoint' => NULL,
        'use_path_style_endpoint' => false,
        'throw' => true,
      ),
    ),
    'links' => 
    array (
      '/opt/BookStack/public/storage' => '/opt/BookStack/storage/app/public',
    ),
  ),
  'hashing' => 
  array (
    'driver' => 'bcrypt',
    'bcrypt' => 
    array (
      'rounds' => 10,
    ),
    'argon' => 
    array (
      'memory' => 1024,
      'threads' => 2,
      'time' => 2,
    ),
  ),
  'logging' => 
  array (
    'default' => 'single',
    'deprecations' => 
    array (
      'channel' => 'null',
      'trace' => false,
    ),
    'channels' => 
    array (
      'stack' => 
      array (
        'driver' => 'stack',
        'channels' => 
        array (
          0 => 'daily',
        ),
        'ignore_exceptions' => false,
      ),
      'single' => 
      array (
        'driver' => 'single',
        'path' => '/opt/BookStack/storage/logs/laravel.log',
        'level' => 'debug',
        'days' => 14,
      ),
      'daily' => 
      array (
        'driver' => 'daily',
        'path' => '/opt/BookStack/storage/logs/laravel.log',
        'level' => 'debug',
        'days' => 7,
      ),
      'stderr' => 
      array (
        'driver' => 'monolog',
        'level' => 'debug',
        'handler' => 'Monolog\\Handler\\StreamHandler',
        'with' => 
        array (
          'stream' => 'php://stderr',
        ),
      ),
      'syslog' => 
      array (
        'driver' => 'syslog',
        'level' => 'debug',
      ),
      'errorlog' => 
      array (
        'driver' => 'errorlog',
        'level' => 'debug',
      ),
      'errorlog_plain_webserver' => 
      array (
        'driver' => 'monolog',
        'level' => 'debug',
        'handler' => 'Monolog\\Handler\\ErrorLogHandler',
        'handler_with' => 
        array (
          0 => 4,
        ),
        'formatter' => 'Monolog\\Formatter\\LineFormatter',
        'formatter_with' => 
        array (
          'format' => '%message%',
        ),
      ),
      'null' => 
      array (
        'driver' => 'monolog',
        'handler' => 'Monolog\\Handler\\NullHandler',
      ),
      'testing' => 
      array (
        'driver' => 'testing',
      ),
      'emergency' => 
      array (
        'path' => '/opt/BookStack/storage/logs/laravel.log',
      ),
    ),
    'failed_login' => 
    array (
      'message' => NULL,
      'channel' => 'errorlog_plain_webserver',
    ),
  ),
  'mail' => 
  array (
    'default' => 'smtp',
    'from' => 
    array (
      'address' => 'bookstack@checker.htb',
      'name' => 'BookStack',
    ),
    'mailers' => 
    array (
      'smtp' => 
      array (
        'transport' => 'smtp',
        'scheme' => NULL,
        'host' => 'localhost',
        'port' => '587',
        'username' => NULL,
        'password' => NULL,
        'verify_peer' => true,
        'timeout' => NULL,
        'local_domain' => NULL,
        'tls_required' => false,
      ),
      'sendmail' => 
      array (
        'transport' => 'sendmail',
        'path' => '/usr/sbin/sendmail -bs',
      ),
      'log' => 
      array (
        'transport' => 'log',
        'channel' => NULL,
      ),
      'array' => 
      array (
        'transport' => 'array',
      ),
      'failover' => 
      array (
        'transport' => 'failover',
        'mailers' => 
        array (
          0 => 'smtp',
          1 => 'log',
        ),
      ),
    ),
    'markdown' => 
    array (
      'theme' => 'default',
      'paths' => 
      array (
        0 => '/opt/BookStack/resources/views/vendor/mail',
      ),
    ),
  ),
  'oidc' => 
  array (
    'name' => 'SSO',
    'dump_user_details' => false,
    'display_name_claims' => 'name',
    'external_id_claim' => 'sub',
    'client_id' => NULL,
    'client_secret' => NULL,
    'issuer' => NULL,
    'discover' => false,
    'jwt_public_key' => NULL,
    'authorization_endpoint' => NULL,
    'token_endpoint' => NULL,
    'additional_scopes' => NULL,
    'user_to_groups' => false,
    'groups_claim' => 'groups',
    'remove_from_groups' => false,
  ),
  'queue' => 
  array (
    'default' => 'sync',
    'connections' => 
    array (
      'sync' => 
      array (
        'driver' => 'sync',
      ),
      'database' => 
      array (
        'driver' => 'database',
        'table' => 'jobs',
        'queue' => 'default',
        'retry_after' => 90,
        'after_commit' => false,
      ),
      'redis' => 
      array (
        'driver' => 'redis',
        'connection' => 'default',
        'queue' => 'default',
        'retry_after' => 90,
        'block_for' => NULL,
        'after_commit' => false,
      ),
    ),
    'failed' => 
    array (
      'driver' => 'database-uuids',
      'database' => 'mysql',
      'table' => 'failed_jobs',
    ),
  ),
  'saml2' => 
  array (
    'name' => 'SSO',
    'dump_user_details' => false,
    'email_attribute' => 'email',
    'display_name_attributes' => 
    array (
      0 => 'username',
    ),
    'external_id_attribute' => NULL,
    'user_to_groups' => false,
    'group_attribute' => 'group',
    'remove_from_groups' => false,
    'autoload_from_metadata' => false,
    'onelogin_overrides' => NULL,
    'onelogin' => 
    array (
      'strict' => true,
      'debug' => false,
      'baseurl' => NULL,
      'sp' => 
      array (
        'entityId' => '',
        'assertionConsumerService' => 
        array (
          'url' => '',
          'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        ),
        'singleLogoutService' => 
        array (
          'url' => '',
          'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        ),
        'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        'x509cert' => '',
        'privateKey' => '',
      ),
      'idp' => 
      array (
        'entityId' => NULL,
        'singleSignOnService' => 
        array (
          'url' => NULL,
          'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        ),
        'singleLogoutService' => 
        array (
          'url' => NULL,
          'responseUrl' => NULL,
          'binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        ),
        'x509cert' => NULL,
      ),
      'security' => 
      array (
        'requestedAuthnContext' => true,
        'logoutRequestSigned' => false,
        'logoutResponseSigned' => false,
        'authnRequestsSigned' => false,
        'lowercaseUrlencoding' => false,
      ),
    ),
  ),
  'services' => 
  array (
    'disable_services' => false,
    'drawio' => true,
    'avatar_url' => '',
    'callback_url' => 'http://checker.htb',
    'github' => 
    array (
      'client_id' => false,
      'client_secret' => false,
      'redirect' => 'http://checker.htb/login/service/github/callback',
      'name' => 'GitHub',
      'auto_register' => false,
      'auto_confirm' => false,
    ),
    'google' => 
    array (
      'client_id' => false,
      'client_secret' => false,
      'redirect' => 'http://checker.htb/login/service/google/callback',
      'name' => 'Google',
      'auto_register' => false,
      'auto_confirm' => false,
      'select_account' => false,
    ),
    'slack' => 
    array (
      'client_id' => false,
      'client_secret' => false,
      'redirect' => 'http://checker.htb/login/service/slack/callback',
      'name' => 'Slack',
      'auto_register' => false,
      'auto_confirm' => false,
    ),
    'facebook' => 
    array (
      'client_id' => false,
      'client_secret' => false,
      'redirect' => 'http://checker.htb/login/service/facebook/callback',
      'name' => 'Facebook',
      'auto_register' => false,
      'auto_confirm' => false,
    ),
    'twitter' => 
    array (
      'client_id' => false,
      'client_secret' => false,
      'redirect' => 'http://checker.htb/login/service/twitter/callback',
      'name' => 'Twitter',
      'auto_register' => false,
      'auto_confirm' => false,
    ),
    'azure' => 
    array (
      'client_id' => false,
      'client_secret' => false,
      'tenant' => false,
      'redirect' => 'http://checker.htb/login/service/azure/callback',
      'name' => 'Microsoft Azure',
      'auto_register' => false,
      'auto_confirm' => false,
    ),
    'okta' => 
    array (
      'client_id' => NULL,
      'client_secret' => NULL,
      'redirect' => 'http://checker.htb/login/service/okta/callback',
      'base_url' => NULL,
      'name' => 'Okta',
      'auto_register' => false,
      'auto_confirm' => false,
    ),
    'gitlab' => 
    array (
      'client_id' => NULL,
      'client_secret' => NULL,
      'redirect' => 'http://checker.htb/login/service/gitlab/callback',
      'instance_uri' => NULL,
      'name' => 'GitLab',
      'auto_register' => false,
      'auto_confirm' => false,
    ),
    'twitch' => 
    array (
      'client_id' => NULL,
      'client_secret' => NULL,
      'redirect' => 'http://checker.htb/login/service/twitch/callback',
      'name' => 'Twitch',
      'auto_register' => false,
      'auto_confirm' => false,
    ),
    'discord' => 
    array (
      'client_id' => NULL,
      'client_secret' => NULL,
      'redirect' => 'http://checker.htb/login/service/discord/callback',
      'name' => 'Discord',
      'auto_register' => false,
      'auto_confirm' => false,
    ),
    'ldap' => 
    array (
      'server' => false,
      'dump_user_details' => false,
      'dump_user_groups' => false,
      'dn' => false,
      'pass' => false,
      'base_dn' => false,
      'user_filter' => '(&(uid=${user}))',
      'version' => false,
      'id_attribute' => 'uid',
      'email_attribute' => 'mail',
      'display_name_attribute' => 'cn',
      'follow_referrals' => false,
      'user_to_groups' => false,
      'group_attribute' => 'memberOf',
      'remove_from_groups' => false,
      'tls_insecure' => false,
      'start_tls' => false,
      'thumbnail_attribute' => NULL,
    ),
  ),
  'session' => 
  array (
    'driver' => 'file',
    'lifetime' => 120,
    'expire_on_close' => false,
    'encrypt' => false,
    'files' => '/opt/BookStack/storage/framework/sessions',
    'connection' => NULL,
    'table' => 'sessions',
    'store' => NULL,
    'lottery' => 
    array (
      0 => 2,
      1 => 100,
    ),
    'cookie' => 'bookstack_session',
    'path' => '/',
    'domain' => NULL,
    'secure' => false,
    'http_only' => true,
    'same_site' => 'lax',
  ),
  'setting-defaults' => 
  array (
    'app-name' => 'BookStack',
    'app-logo' => '',
    'app-name-header' => true,
    'app-editor' => 'wysiwyg',
    'app-color' => '#206ea7',
    'app-color-light' => 'rgba(32,110,167,0.15)',
    'link-color' => '#206ea7',
    'bookshelf-color' => '#a94747',
    'book-color' => '#077b70',
    'chapter-color' => '#af4d0d',
    'page-color' => '#206ea7',
    'page-draft-color' => '#7e50b1',
    'app-color-dark' => '#195785',
    'app-color-light-dark' => 'rgba(32,110,167,0.15)',
    'link-color-dark' => '#429fe3',
    'bookshelf-color-dark' => '#ff5454',
    'book-color-dark' => '#389f60',
    'chapter-color-dark' => '#ee7a2d',
    'page-color-dark' => '#429fe3',
    'page-draft-color-dark' => '#a66ce8',
    'app-custom-head' => false,
    'registration-enabled' => false,
    'user' => 
    array (
      'ui-shortcuts' => '{}',
      'ui-shortcuts-enabled' => false,
      'dark-mode-enabled' => false,
      'bookshelves_view_type' => 'grid',
      'bookshelf_view_type' => 'grid',
      'books_view_type' => 'grid',
    ),
  ),
  'snappy' => 
  array (
    'pdf' => 
    array (
      'enabled' => true,
      'binary' => false,
      'timeout' => false,
      'options' => 
      array (
        'outline' => true,
        'page-size' => 'A4',
      ),
      'env' => 
      array (
      ),
    ),
    'image' => 
    array (
      'enabled' => false,
      'binary' => '/usr/local/bin/wkhtmltoimage',
      'timeout' => false,
      'options' => 
      array (
      ),
      'env' => 
      array (
      ),
    ),
  ),
  'view' => 
  array (
    'theme' => false,
    'paths' => 
    array (
      0 => '/opt/BookStack/resources/views',
    ),
    'compiled' => '/opt/BookStack/storage/framework/views',
  ),
  'image' => 
  array (
    'driver' => 'gd',
  ),
  'tinker' => 
  array (
    'commands' => 
    array (
    ),
    'alias' => 
    array (
    ),
    'dont_alias' => 
    array (
      0 => 'App\\Nova',
    ),
  ),
);
