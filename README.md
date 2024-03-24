# EcoFlow

EcoFlow is a PHP library that provides functionality for interacting with the EcoFlow developer platform. It allows
users to integrate their applications with EcoFlow devices and access various features and data provided by the
platform.

## Features

- Authenticate and authorize with the EcoFlow developer platform
- Retrieve device information and status
- Control and monitor EcoFlow devices remotely
- Access energy flow data and metrics
- Perform device-specific actions and configurations

## Installation

To install EcoFlow, you can use Composer, the dependency manager for PHP. Run the following command in your project
directory:

```bash
composer require marjovanlier/ecoflow
```

Make sure you have Composer installed and your project's composer.json file is properly configured.

## Usage

To use the EcoFlow library, you need to sign up for the EcoFlow developer program
at https://developer-eu.ecoflow.com/us/. Once you have obtained your API credentials, you can start using the library in
your PHP application.

Here's a basic example of how to use the EcoFlow library:

```php
use Marjovanlier\EcoFlow\EcoFlow;

// Create a new instance of the EcoFlow class
$ecoFlow = new EcoFlow('your-api-key', 'your-api-secret');

// Retrieve a list of devices associated with your account
$devices = $ecoFlow->getDevices();

// Sets the permanent wattage of a device (100 for 10W)
$ecoFlow->setParams($deviceSn, 'WN511_SET_PERMANENT_WATTS_PACK', ['permanentWatts' => 100]);
```

## Contributing

Contributions to the EcoFlow library are welcome! If you find any issues or have suggestions for improvements, please
open an issue or submit a pull request on the GitHub repository.

## Licence

The EcoFlow library is open-source software licensed under the MIT licence.