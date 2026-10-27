<?php

declare(strict_types=1);

// Without a config Phan parses no files and exits 0, so `composer test:phan` checked nothing.
return [
    'target_php_version' => '8.2',
    'minimum_target_php_version' => '8.2',
    'directory_list' => ['src', 'tests', 'vendor'],
    'exclude_analysis_directory_list' => ['vendor'],
    // Rector ships its own PHPUnit TestCase stub, which Phan would report as a second TestCase definition.
    'exclude_file_regex' => '@^vendor/rector/rector/stubs-rector/@',
    'suppress_issue_types' => [
        // Symfony documents its HTTP client exceptions as interfaces, so @throws has to name interfaces.
        'PhanTypeInvalidThrowsIsInterface',
        // Phan 5 cannot parse multi-line array shapes or Closure() types; PHPStan and Psalm check those docblocks.
        'PhanUnextractableAnnotationElementName',
        'PhanUnextractableAnnotationSuffix',
        // PHP applies #[SensitiveParameter] on a promoted property to the parameter only; Phan checks the property.
        'PhanAttributeWrongTarget',
        // The polyfill parser reports these whatever the minimum version; PHP 8.0+ allows them and PER requires them.
        'PhanCompatibleTrailingCommaParameterList',
    ],
];
